# Copyright (c) 2026 Splunk Inc.
"""Check source progress using the SDK's real ES polling decorator."""

import importlib
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from types import SimpleNamespace

import httpx
import pytest
from soar_sdk.asset_state import AssetState
from soar_sdk.params import OnESPollParams


module = importlib.import_module("src.app")


def raw_email(identifier):
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.com"
    message["Subject"] = identifier
    message.set_content("Synthetic checkpoint test")
    return message.as_bytes()


@pytest.fixture
def runtime(monkeypatch, mocker):
    app = module.app
    if not hasattr(app.soar_client, "_get_es_finding_context"):
        pytest.skip("Requires the AR-2061 SDK wheel; see TESTING_ES_POLL.md")
    asset = make_asset()
    saved = {}
    mocker.patch.object(
        app.actions_manager, "load_state", side_effect=lambda: dict(saved)
    )
    mocker.patch.object(app.actions_manager, "save_state", side_effect=saved.update)
    asset._ingest_state = AssetState(
        app.actions_manager, "ingest", "1", encrypted=False
    )
    monkeypatch.setattr(app, "_asset", asset, raising=False)
    monkeypatch.setattr(app, "_es_ingest_config", {"es_security_domain": "threat"})
    monkeypatch.setattr(app.soar_client, "MAX_BULK_FINDINGS", 2)
    monkeypatch.setitem(
        sys.modules,
        "es_poll_api",
        SimpleNamespace(get_es_context=lambda: ("https://es.example", "test-token")),
    )
    mocker.patch.object(app.actions_manager, "add_result")
    mocker.patch.object(
        app.soar_client, "get", side_effect=AssertionError("SOAR REST called")
    )
    mocker.patch.object(
        app.soar_client, "post", side_effect=AssertionError("SOAR REST called")
    )
    mocker.patch(
        "soar_sdk.decorators._es_poll._upload_poll_attachments",
        side_effect=lambda client, findings, *args: [[] for _ in findings],
    )
    context = SimpleNamespace(
        asset=asset, sent=[], failed=None, rows={}, pages={}, mime="valid"
    )
    for number in range(1, 7):
        identifier = f"mail-{number}"
        context.rows[identifier] = {
            "id": identifier,
            "subject": identifier,
            "receivedDateTime": (
                datetime(2026, 11, 13, tzinfo=UTC) + timedelta(minutes=number)
            ).isoformat(),
        }

    def create(client, url, *, content, headers):
        payload = json.loads(content)
        identifier = re.search(r"mail-\d+$", payload["rule_title"]).group()
        context.sent.append(identifier)
        if identifier == context.failed:
            return httpx.Response(429)
        return httpx.Response(201, json={"_time": "now", "finding_id": identifier})

    mocker.patch.object(httpx.Client, "post", autospec=True, side_effect=create)
    mock_mailbox(context, mocker)
    return context


@pytest.mark.parametrize("manner", ["oldest first", "latest first"])
def test_failed_batch_replays_without_repeating_successful_batches(runtime, manner):
    context = runtime
    context.asset.ingest_manner = manner
    expected = expected_order(context)
    context.failed = expected[2]
    assert module.on_es_poll(OnESPollParams())
    assert context.sent == expected[:4]
    result = module.app.actions_manager.add_result.call_args.args[0]
    assert result.get_summary()["failed"] == 1
    assert not context.asset.ingest_state.in_transaction
    context.failed = None
    context.sent.clear()
    assert module.on_es_poll(OnESPollParams())
    assert context.sent == expected[2:]
    assert not context.asset.ingest_state.in_transaction


def test_equal_timestamps_retain_previously_checkpointed_ids(runtime):
    context = runtime
    context.asset.ingest_manner = "oldest first"
    timestamp = context.rows["mail-1"]["receivedDateTime"]
    context.rows = {
        key: {**value, "receivedDateTime": timestamp}
        for key, value in context.rows.items()
    }
    expected = expected_order(context)
    context.failed = expected[2]
    assert module.on_es_poll(OnESPollParams())
    context.failed = None
    context.sent.clear()
    assert module.on_es_poll(OnESPollParams())
    assert context.sent == expected[2:]
    context.sent.clear()
    assert module.on_es_poll(OnESPollParams())
    assert context.sent == []


def make_asset():
    return module.Asset(
        tenant="test",
        client_id="test",
        email_address="test@example.com",
        get_folder_id=False,
        max_containers=50,
    )


def expected_order(context):
    return sorted(
        context.rows,
        key=lambda key: context.rows[key]["receivedDateTime"],
        reverse=context.asset.ingest_manner == "latest first",
    )


def mock_mailbox(context, mocker):
    helper = mocker.Mock()

    def request(endpoint, **kwargs):
        if endpoint.endswith("/$value"):
            return raw_email(endpoint.split("/")[-2])
        identifier = endpoint.split("/")[-1]
        if identifier in context.rows:
            return context.rows[identifier]
        if kwargs.get("nextLink"):
            if getattr(context, "fail_page", False):
                raise RuntimeError("Synthetic page unavailable")
            ids = context.pages[kwargs["nextLink"]]
        else:
            query = kwargs["params"]
            ids = sorted(
                context.rows,
                key=lambda key: context.rows[key]["receivedDateTime"],
                reverse=query["$orderby"].endswith("desc"),
            )
            if "$filter" in query:
                lower = query["$filter"].removeprefix("receivedDateTime ge ")
                ids = [
                    key for key in ids if context.rows[key]["receivedDateTime"] >= lower
                ]
        result = {"value": [context.rows[key] for key in ids[:3]]}
        if len(ids) > 3:
            link = f"https://graph.microsoft.com/v1.0/page-{len(context.pages)}"
            context.pages[link] = ids[3:]
            result["@odata.nextLink"] = link
        return result

    helper.make_rest_call_helper.side_effect = request
    mocker.patch.object(module, "MsGraphHelper", return_value=helper)


def test_latest_first_pending_window_survives_new_mail_arrival(runtime):
    context = runtime
    context.asset.ingest_manner = "latest first"
    expected = expected_order(context)
    context.failed = expected[2]
    assert module.on_es_poll(OnESPollParams())
    context.rows["mail-7"] = {
        "id": "mail-7",
        "subject": "mail-7",
        "receivedDateTime": (
            datetime(2026, 11, 13, tzinfo=UTC) + timedelta(minutes=7)
        ).isoformat(),
    }
    context.failed = None
    context.sent.clear()
    assert module.on_es_poll(OnESPollParams())
    assert context.sent == expected[2:]
    context.sent.clear()
    assert module.on_es_poll(OnESPollParams())
    assert context.sent == ["mail-7"]


def test_page_request_failure_preserves_previous_batch(runtime):
    context = runtime
    context.asset.ingest_manner = "latest first"
    context.fail_page = True
    expected = expected_order(context)
    assert not module.on_es_poll(OnESPollParams())
    assert context.sent == expected[:2]
    context.fail_page = False
    context.sent.clear()
    assert module.on_es_poll(OnESPollParams())
    assert context.sent == expected[2:]
