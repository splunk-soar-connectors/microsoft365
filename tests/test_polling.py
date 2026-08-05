# Copyright (c) 2017-2026 Splunk Inc.

import base64
import importlib
from types import SimpleNamespace
from unittest.mock import Mock

from soar_sdk.models.container import Container


app_module = importlib.import_module("src.app")


def _email(message_id, received, has_attachments=False):
    return {
        "id": message_id,
        "subject": message_id,
        "receivedDateTime": received,
        "lastModifiedDateTime": received,
        "from": {"emailAddress": {"address": "sender@example.com"}},
        "body": {"content": ""},
        "hasAttachments": has_attachments,
    }


def _asset(**overrides):
    defaults = dict(
        ingest_state={"first_run": False, "last_time": "2026-07-16T00:00:00Z"},
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
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


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
    first_page_kwargs = helper.make_rest_call_helper.call_args_list[0].kwargs
    next_page_kwargs = helper.make_rest_call_helper.call_args_list[1].kwargs
    assert next_page_kwargs["params"] is None
    assert next_page_kwargs["nextLink"] == "https://graph.microsoft.com/v1.0/next"
    assert next_page_kwargs["pagination_state"] is first_page_kwargs["pagination_state"]
    assert state["last_time"] == "2026-07-16T02:00:00Z"
    assert state["first_run"] is False


def test_on_poll_extract_attachments_adds_to_vault_using_container_id(mocker):
    content_bytes = base64.b64encode(b"attachment payload").decode("utf-8")
    helper = Mock()
    helper.make_rest_call_helper.side_effect = [
        {"value": [_email("one", "2026-07-16T01:00:00Z", has_attachments=True)]},
        {
            "value": [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "report.pdf",
                    "size": 1234,
                    "contentBytes": content_bytes,
                }
            ]
        },
    ]
    mocker.patch.object(app_module, "MsGraphHelper", return_value=helper)

    soar = Mock()
    soar.vault.create_attachment.return_value = "vault-id-xyz"

    params = Mock(container_count=4294967295)
    params.is_manual_poll.return_value = False
    asset = _asset(extract_attachments=True)

    output = []
    for item in app_module.on_poll.__wrapped__(params, soar, asset):
        if isinstance(item, Container):
            item.container_id = 55
        output.append(item)

    soar.vault.create_attachment.assert_called_once_with(
        55, b"attachment payload", "report.pdf"
    )
    vault_artifacts = [
        item for item in output if getattr(item, "name", None) == "Vault Artifact"
    ]
    assert len(vault_artifacts) == 1
    assert vault_artifacts[0].cef["vaultId"] == "vault-id-xyz"


def test_on_poll_extract_eml_adds_root_email_to_vault_using_container_id(mocker):
    helper = Mock()
    helper.make_rest_call_helper.side_effect = [
        {"value": [_email("one", "2026-07-16T01:00:00Z")]},
        b"raw eml bytes",
    ]
    mocker.patch.object(app_module, "MsGraphHelper", return_value=helper)

    soar = Mock()
    soar.vault.create_attachment.return_value = "vault-id-eml"

    params = Mock(container_count=4294967295)
    params.is_manual_poll.return_value = False
    asset = _asset(extract_eml=True)

    output = []
    for item in app_module.on_poll.__wrapped__(params, soar, asset):
        if isinstance(item, Container):
            item.container_id = 99
        output.append(item)

    soar.vault.create_attachment.assert_called_once_with(
        99, b"raw eml bytes", "one.eml"
    )
    vault_artifacts = [
        item for item in output if getattr(item, "name", None) == "Vault Artifact"
    ]
    assert len(vault_artifacts) == 1
    assert vault_artifacts[0].cef["vaultId"] == "vault-id-eml"
