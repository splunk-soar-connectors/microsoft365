# Copyright (c) 2017-2026 Splunk Inc.

import importlib
from unittest.mock import Mock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from soar_sdk.asset_state import AssetState
from soar_sdk.auth import AuthorizationCodeFlow
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
        scope="https://graph.microsoft.com/User.Read",
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


def test_authorization_callback_without_action_config(mocker, asset):
    flow = _authorization_flow(asset)
    flow.get_authorization_url()
    mocker.patch.object(app_module.app.actions_manager, "get_config", return_value=None)
    response = Mock(status_code=200)
    response.json.return_value = {"base_url": "https://soar.example.com"}
    mocker.patch.object(app_module.app.soar_client, "get", return_value=response)

    result = app_module.handle_oauth_result(_request(asset, {"code": ["auth-code"]}))

    assert result.status_code == 200
    assert result.content == "Authorization successful! You can close this window."
    assert flow.client.get_authorization_code() == "auth-code"
    assert asset.auth_state["oauth"]["session"]["auth_pending"] is False
    assert asset.auth_state["unrelated"] == "preserved"


def test_authorization_callback_does_not_look_up_redirect_uri(mocker, asset):
    flow = _authorization_flow(asset)
    flow.get_authorization_url()
    redirect_uri = mocker.patch.object(
        app_module.app,
        "get_webhook_url",
        side_effect=AssertionError("Callback must not look up the redirect URI"),
    )

    result = app_module.handle_oauth_result(_request(asset, {"code": ["auth-code"]}))

    assert result.status_code == 200
    assert flow.client.get_authorization_code() == "auth-code"
    redirect_uri.assert_not_called()


@pytest.mark.parametrize(
    ("query", "content"),
    [
        (
            {"error": ["access_denied"], "error_description": ["Consent denied"]},
            "Authorization failed: Consent denied",
        ),
        ({"error": ["access_denied"]}, "Authorization failed: Unknown error"),
        ({}, "Missing authorization code"),
        ({"code": []}, "Missing authorization code"),
    ],
)
def test_authorization_callback_rejects_error_or_missing_code(asset, query, content):
    state = asset.auth_state.get_all()

    result = app_module.handle_oauth_result(_request(asset, query))

    assert result.status_code == 400
    assert result.content == content
    assert asset.auth_state.get_all() == state


def test_admin_consent_callback_preserves_auth_state(asset):
    result = app_module.handle_oauth_result(
        _request(asset, {"admin_consent": ["True"]})
    )

    assert result.status_code == 200
    assert result.content == "Admin consent received. You can close this window."
    assert asset.auth_state[app_module.ADMIN_CONSENT_STATE_KEY] is True
    assert asset.auth_state["unrelated"] == "preserved"


@pytest.mark.parametrize(
    "scope",
    [
        "https://graph.microsoft.com/User.Read",
        "https://graph.microsoft.com/User.Read offline_access",
    ],
)
def test_first_time_delegated_connectivity_reuses_authorized_token(
    mocker, asset, scope
):
    asset.scope = scope
    soar = Mock()
    soar.get_asset_id.return_value = 42
    redirect_uri = mocker.patch.object(
        app_module.app, "get_webhook_url", return_value=REDIRECT_URI
    )
    authorization_url = mocker.spy(
        app_module.AuthorizationCodeFlow, "get_authorization_url"
    )
    token_response = {
        "access_token": "delegated-token",
        "refresh_token": "refresh-token",
        "expires_in": 3600,
        "token_type": "Bearer",
    }
    exchange = mocker.patch(
        "httpx.Client.post",
        return_value=httpx.Response(
            200,
            json=token_response,
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
        result = app_module.handle_oauth_result(
            _request(asset, {"code": ["auth-code"]})
        )
        assert result.status_code == 200

    mocker.patch("soar_sdk.auth.flows.time.sleep", side_effect=complete_authorization)

    app_module.test_connectivity.__wrapped__(soar, asset)

    exchange.assert_called_once()
    assert exchange.call_args.args == (TOKEN_ENDPOINT,)
    assert exchange.call_args.kwargs["data"] == {
        "grant_type": "authorization_code",
        "client_id": "client-id",
        "client_secret": "client-secret",  # pragma: allowlist secret
        "code": "auth-code",
        "redirect_uri": REDIRECT_URI,
    }
    helper_token_request.assert_not_called()
    redirect_uri.assert_called_once_with("result")
    scopes = parse_qs(urlparse(authorization_url.spy_return).query)["scope"][0].split()
    assert scopes.count("offline_access") == 1
    assert "https://graph.microsoft.com/User.Read" in scopes
    graph_request.assert_called_once()
    assert graph_request.call_args.args[0] == "https://graph.microsoft.com/v1.0/me"
    assert graph_request.call_args.kwargs["headers"]["Authorization"] == (
        "Bearer delegated-token"
    )
    assert graph_request.call_args.kwargs["params"] == {"$top": "1"}
    soar.set_message.assert_called_once_with("Test Connectivity Passed")
    saved = asset.auth_state["non_admin_auth"]
    assert saved["access_token"] == "delegated-token"
    assert saved["refresh_token"] == "refresh-token"
    assert saved["expires_at"] > 0
    assert asset.auth_state["unrelated"] == "preserved"
    helper = MsGraphHelper(soar, asset)
    helper.get_token()
    assert helper._access_token == "delegated-token"
    assert helper._refresh_token == "refresh-token"
    helper_token_request.assert_not_called()

    renewal_response = Mock()
    renewal_response.json.return_value = {
        "access_token": "renewed-token",
        "refresh_token": "renewed-refresh-token",
        "expires_in": 3600,
    }
    helper_token_request.side_effect = None
    helper_token_request.return_value = renewal_response
    mocker.patch("src.helper.time.time", return_value=saved["expires_at"] + 1)

    helper.get_token()

    helper_token_request.assert_called_once()
    renewal_data = helper_token_request.call_args.kwargs["data"]
    assert renewal_data["grant_type"] == "refresh_token"
    assert renewal_data["refresh_token"] == "refresh-token"
    assert "code" not in renewal_data
    assert helper._access_token == "renewed-token"
    assert asset.auth_state["non_admin_auth"]["refresh_token"] == (
        "renewed-refresh-token"
    )
    assert asset.auth_state["non_admin_auth"]["expires_at"] > saved["expires_at"]
