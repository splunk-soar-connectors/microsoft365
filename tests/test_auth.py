# Copyright (c) 2017-2026 Splunk Inc.

import importlib
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from soar_sdk.asset_state import AssetState
from soar_sdk.auth import AuthorizationCodeFlow, OAuthClientError, OAuthToken
from soar_sdk.webhooks.models import WebhookRequest

from src.helper import MsGraphHelper


app_module = importlib.import_module("src.app")
REDIRECT_URI = "https://soar.example.com:3500/webhook/microsoft365/42/result"
TOKEN_ENDPOINT = "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"


@pytest.fixture
def asset():
    saved = {"auth": {"unrelated": "preserved"}}
    backend = Mock()
    backend.load_state.side_effect = lambda: dict(saved)

    def save_state(state):
        saved.clear()
        saved.update(state)

    backend.save_state.side_effect = save_state
    asset = app_module.Asset(
        tenant="tenant",
        client_id="client-id",
        client_secret="client-secret",  # pragma: allowlist secret
        auth_type="OAuth",
        admin_access=False,
    )
    asset._auth_state = AssetState(backend, "auth", "42", encrypted=False)
    return asset


def _authorization_flow(asset):
    return AuthorizationCodeFlow(
        asset.auth_state,
        "42",
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        authorization_endpoint=app_module.MS_GRAPH_AUTH_URL.format(tenant=asset.tenant),
        token_endpoint=TOKEN_ENDPOINT,
        redirect_uri=REDIRECT_URI,
        scope=asset.scope.split(),
    )


def _request(asset, query):
    return WebhookRequest[app_module.Asset](
        method="GET",
        headers={},
        path_parts=["result"],
        query=query,
        body=None,
        asset=asset,
        soar_base_url="https://soar.example.com",
        soar_auth_token="session-token",
        asset_id=42,
    )


@pytest.fixture
def connectivity(mocker, asset):
    soar = Mock()
    soar.get_asset_id.return_value = 42
    config = mocker.patch.object(
        app_module.app.actions_manager,
        "get_config",
        return_value={"directory": "microsoft365"},
    )
    responses = {
        "rest/system_info": httpx.Response(
            200, json={"base_url": "https://soar.example.com"}
        ),
        "rest/feature_flag/webhooks": httpx.Response(
            200, json={"config": {"webhooks_port": 3500}}
        ),
    }
    mocker.patch.object(
        app_module.app.soar_client,
        "get",
        side_effect=lambda endpoint: responses[endpoint],
    )
    mocker.patch.object(app_module.app.soar_client, "get_asset_id", return_value="42")
    webhook_url = mocker.spy(app_module.app, "get_webhook_url")
    authorization_url = mocker.spy(AuthorizationCodeFlow, "get_authorization_url")
    wait = mocker.spy(AuthorizationCodeFlow, "wait_for_authorization")
    mocker.patch(
        "httpx.Client.request", side_effect=AssertionError("Unexpected HTTP call")
    )
    mocker.patch(
        "requests.sessions.Session.request",
        side_effect=AssertionError("Unexpected HTTP call"),
    )
    exchange = mocker.patch(
        "httpx.Client.post",
        return_value=httpx.Response(
            200,
            json={
                "access_token": "delegated-token",
                "refresh_token": "refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer",
            },
            request=httpx.Request("POST", TOKEN_ENDPOINT),
        ),
    )
    helper_token_request = mocker.patch(
        "src.helper.requests.post",
        side_effect=AssertionError("The authorized token must be reused"),
    )
    graph_response = Mock(
        status_code=200,
        headers={"Content-Type": "application/json"},
        text='{"id":"user-id"}',
    )
    graph_response.json.return_value = {"id": "user-id"}
    graph_request = mocker.patch("src.helper.requests.get", return_value=graph_response)

    def complete_authorization(interval):
        state = asset.auth_state["oauth"]["session"]["state"]
        config.return_value = None
        try:
            result = app_module.handle_oauth_result(
                _request(asset, {"code": ["auth-code"], "state": [state]})
            )
        finally:
            config.return_value = {"directory": "microsoft365"}
        assert result.status_code == 200

    mocker.patch("soar_sdk.auth.flows.time.sleep", side_effect=complete_authorization)
    return SimpleNamespace(
        soar=soar,
        webhook_url=webhook_url,
        authorization_url=authorization_url,
        wait=wait,
        exchange=exchange,
        helper_token_request=helper_token_request,
        graph_request=graph_request,
    )


def test_authorization_callback_without_action_config(mocker, asset):
    flow = _authorization_flow(asset)
    auth_url = flow.get_authorization_url()
    query = parse_qs(urlparse(auth_url).query)
    assert query["redirect_uri"] == [REDIRECT_URI]
    state = query["state"]
    mocker.patch.object(app_module.app.actions_manager, "get_config", return_value=None)
    redirect_uri = mocker.spy(app_module.app, "get_webhook_url")
    response = Mock(status_code=200)
    response.json.return_value = {"base_url": "https://soar.example.com"}
    mocker.patch.object(app_module.app.soar_client, "get", return_value=response)

    result = app_module.handle_oauth_result(
        _request(asset, {"code": ["auth-code"], "state": state})
    )

    assert result.status_code == 200
    assert result.content == "Authorization successful! You can close this window."
    assert flow.client.get_authorization_code() == "auth-code"
    assert asset.auth_state["oauth"]["session"]["auth_pending"] is False
    assert asset.auth_state["unrelated"] == "preserved"
    redirect_uri.assert_not_called()

    mocker.patch("soar_sdk.auth.flows.time.sleep")
    exchange = mocker.patch(
        "httpx.Client.post",
        return_value=httpx.Response(
            200,
            json={"access_token": "access-token", "expires_in": 3600},
            request=httpx.Request("POST", TOKEN_ENDPOINT),
        ),
    )

    token = flow.wait_for_authorization()

    assert token.access_token == "access-token"
    exchange.assert_called_once()
    assert exchange.call_args.args == (TOKEN_ENDPOINT,)
    assert exchange.call_args.kwargs["data"]["grant_type"] == "authorization_code"
    assert exchange.call_args.kwargs["data"]["code"] == "auth-code"
    assert exchange.call_args.kwargs["data"]["redirect_uri"] == REDIRECT_URI


@pytest.mark.parametrize(
    "scope",
    [
        "https://graph.microsoft.com/Calendars.Read https://graph.microsoft.com/User.Read",
        "https://graph.microsoft.com/Calendars.Read https://graph.microsoft.com/User.Read offline_access",
    ],
)
def test_delegated_connectivity_reuses_and_refreshes_authorized_token(
    mocker, asset, connectivity, scope
):
    asset.scope = scope

    app_module.test_connectivity.__wrapped__(connectivity.soar, asset)

    connectivity.webhook_url.assert_called_once_with("result")
    query = parse_qs(urlparse(connectivity.authorization_url.spy_return).query)
    assert query["redirect_uri"] == [REDIRECT_URI]
    scopes = query["scope"][0].split()
    assert scopes.count("offline_access") == 1
    assert set(scopes) == set(scope.split()) | {"offline_access"}
    connectivity.exchange.assert_called_once()
    assert connectivity.exchange.call_args.args == (TOKEN_ENDPOINT,)
    assert connectivity.exchange.call_args.kwargs["data"] == {
        "grant_type": "authorization_code",
        "client_id": asset.client_id,
        "client_secret": asset.client_secret,
        "code": "auth-code",
        "redirect_uri": REDIRECT_URI,
    }
    token = connectivity.wait.spy_return
    assert isinstance(token, OAuthToken)
    saved = asset.auth_state["non_admin_auth"]
    assert saved == token.model_dump(mode="json", exclude_none=True)
    assert saved["refresh_token"] == "refresh-token"
    assert saved["expires_at"] > 0
    assert asset.auth_state["unrelated"] == "preserved"
    connectivity.helper_token_request.assert_not_called()
    connectivity.graph_request.assert_called_once()
    assert connectivity.graph_request.call_args.args[0] == (
        "https://graph.microsoft.com/v1.0/me"
    )
    assert connectivity.graph_request.call_args.kwargs["headers"]["Authorization"] == (
        "Bearer delegated-token"
    )
    assert connectivity.graph_request.call_args.kwargs["params"] == {"$top": "1"}
    connectivity.soar.set_message.assert_called_once_with("Test Connectivity Passed")

    reloaded_asset = app_module.Asset(**asset.model_dump(exclude_none=True))
    reloaded_asset._auth_state = AssetState(
        asset.auth_state.backend, "auth", "42", encrypted=False
    )
    assert reloaded_asset.auth_state["non_admin_auth"] == saved
    helper = MsGraphHelper(connectivity.soar, reloaded_asset)
    helper.get_token()

    assert helper._access_token == "delegated-token"
    assert helper._refresh_token == "refresh-token"
    connectivity.helper_token_request.assert_not_called()

    renewal_response = Mock()
    renewal_response.json.return_value = {
        "access_token": "renewed-token",
        "expires_in": 3600,
    }
    connectivity.helper_token_request.side_effect = None
    connectivity.helper_token_request.return_value = renewal_response
    mocker.patch("src.helper.time.time", return_value=saved["expires_at"] + 1)

    helper.get_token()

    connectivity.helper_token_request.assert_called_once()
    assert connectivity.helper_token_request.call_args.args == (TOKEN_ENDPOINT,)
    renewal_data = connectivity.helper_token_request.call_args.kwargs["data"]
    assert renewal_data["grant_type"] == "refresh_token"
    assert renewal_data["refresh_token"] == "refresh-token"
    assert renewal_data["client_id"] == asset.client_id
    assert renewal_data["client_secret"] == asset.client_secret
    assert "code" not in renewal_data
    assert helper._access_token == "renewed-token"
    assert (
        reloaded_asset.auth_state["non_admin_auth"]["refresh_token"] == "refresh-token"
    )
    assert (
        reloaded_asset.auth_state["non_admin_auth"]["expires_at"] > saved["expires_at"]
    )


def test_invalid_client_secret_stops_before_helper_token_or_graph_request(
    asset, connectivity
):
    connectivity.exchange.return_value = httpx.Response(
        400,
        json={
            "error": "invalid_client",
            "error_description": "AADSTS7000215: Invalid client secret provided.",
        },
        request=httpx.Request("POST", TOKEN_ENDPOINT),
    )

    with pytest.raises(OAuthClientError, match="AADSTS7000215"):
        app_module.test_connectivity.__wrapped__(connectivity.soar, asset)

    connectivity.exchange.assert_called_once()
    assert (
        connectivity.exchange.call_args.kwargs["data"]["client_id"] == asset.client_id
    )
    assert connectivity.exchange.call_args.kwargs["data"]["client_secret"] == (
        asset.client_secret
    )
    connectivity.helper_token_request.assert_not_called()
    connectivity.graph_request.assert_not_called()
    connectivity.soar.set_message.assert_not_called()
    assert "non_admin_auth" not in asset.auth_state
