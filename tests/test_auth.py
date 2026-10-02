# Copyright (c) 2017-2026 Splunk Inc.

import importlib
from unittest.mock import Mock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from soar_sdk.asset_state import AssetState
from soar_sdk.auth import AuthorizationCodeFlow
from soar_sdk.webhooks.models import WebhookRequest


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
