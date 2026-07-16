# Copyright (c) 2017-2026 Splunk Inc.

import importlib
from types import SimpleNamespace
from unittest.mock import Mock


app_module = importlib.import_module("src.app")


def _email(message_id, received):
    return {
        "id": message_id,
        "subject": message_id,
        "receivedDateTime": received,
        "lastModifiedDateTime": received,
        "from": {"emailAddress": {"address": "sender@example.com"}},
        "body": {"content": ""},
        "hasAttachments": False,
    }


def test_scheduled_poll_consumes_next_link_and_uses_checkpoint_safe_order(mocker):
    helper = Mock()
    helper.make_rest_call_helper.side_effect = [
        {
            "value": [_email("one", "2026-07-16T01:00:00Z")],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/next",
        },
        {"value": [_email("two", "2026-07-16T02:00:00Z")]},
    ]
    mocker.patch.object(app_module, "MsGraphHelper", return_value=helper)
    params = Mock(container_count=4294967295)
    params.is_manual_poll.return_value = False
    state = {"first_run": False, "last_time": "2026-07-16T00:00:00Z"}
    asset = SimpleNamespace(
        ingest_state=state,
        email_address="mailbox@example.com",
        folder="Inbox",
        get_folder_id=False,
        first_run_max_emails=100,
        max_containers=2,
        ingest_manner="latest first",
        extract_urls=False,
        extract_domains=False,
        extract_ips=False,
        extract_hashes=False,
        extract_eml=False,
        extract_attachments=False,
        ingest_eml=False,
    )

    output = list(app_module.on_poll.__wrapped__(params, Mock(), asset))

    assert len(output) == 4
    assert (
        helper.make_rest_call_helper.call_args_list[0].kwargs["params"]["$orderby"]
        == "receivedDateTime asc"
    )
    assert helper.make_rest_call_helper.call_args_list[1].kwargs == {
        "params": None,
        "nextLink": "https://graph.microsoft.com/v1.0/next",
    }
    assert state["last_time"] == "2026-07-16T02:00:00Z"
    assert state["first_run"] is False
