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


def test_on_poll_encodes_message_id_when_fetching_eml(mocker):
    helper = Mock()
    helper.make_rest_call_helper.side_effect = [
        {"value": [_email("one/two+three=", "2026-07-16T01:00:00Z")]},
        b"raw eml bytes",
    ]
    mocker.patch.object(app_module, "MsGraphHelper", return_value=helper)

    params = Mock(container_count=4294967295)
    params.is_manual_poll.return_value = False
    asset = _asset(extract_eml=True)

    list(app_module.on_poll.__wrapped__(params, Mock(), asset))

    eml_endpoint = helper.make_rest_call_helper.call_args_list[1].args[0]
    assert eml_endpoint == (
        "/users/mailbox@example.com/messages/one%2Ftwo%2Bthree%3D/$value"
    )


def test_on_poll_email_artifact_includes_full_field_set(mocker):
    email_data = {
        "id": "msg-1",
        "subject": "Test",
        "receivedDateTime": "2026-07-16T01:00:00Z",
        "sentDateTime": "2026-07-16T00:59:00Z",
        "lastModifiedDateTime": "2026-07-16T01:00:00Z",
        "from": {"emailAddress": {"address": "sender@example.com"}},
        "sender": {"emailAddress": {"address": "sender@example.com"}},
        "toRecipients": [{"emailAddress": {"address": "to@example.com"}}],
        "ccRecipients": [{"emailAddress": {"address": "cc@example.com"}}],
        "bccRecipients": [{"emailAddress": {"address": "bcc@example.com"}}],
        "body": {"content": ""},
        "bodyPreview": "preview",
        "hasAttachments": False,
        "importance": "high",
        "isRead": True,
        "internetMessageId": "<abc@example.com>",
        "internetMessageHeaders": [{"name": "X-Custom", "value": "1"}],
    }
    helper = Mock()
    helper.make_rest_call_helper.side_effect = [{"value": [email_data]}]
    mocker.patch.object(app_module, "MsGraphHelper", return_value=helper)

    params = Mock(container_count=4294967295)
    params.is_manual_poll.return_value = False
    asset = _asset()

    output = list(app_module.on_poll.__wrapped__(params, Mock(), asset))

    artifact = next(
        item for item in output if getattr(item, "name", None) == "Email Artifact"
    )
    assert artifact.cef["toEmail"] == "to@example.com"
    assert artifact.cef["toRecipients"] == ["to@example.com"]
    assert artifact.cef["ccRecipients"] == ["cc@example.com"]
    assert artifact.cef["bccRecipients"] == ["bcc@example.com"]
    assert artifact.cef["senderEmail"] == "sender@example.com"
    assert artifact.cef["sentDateTime"] == "2026-07-16T00:59:00Z"
    assert artifact.cef["importance"] == "high"
    assert artifact.cef["isRead"] is True
    assert artifact.cef["internetMessageId"] == "<abc@example.com>"
    assert artifact.cef["internetMessageHeaders"] == {"X-Custom": "1"}


def test_on_poll_item_attachment_creates_nested_email_artifact_without_ingest_eml(
    mocker,
):
    helper = Mock()
    helper.make_rest_call_helper.side_effect = [
        {"value": [_email("one", "2026-07-16T01:00:00Z", has_attachments=True)]},
        {
            "value": [
                {
                    "@odata.type": "#microsoft.graph.itemAttachment",
                    "id": "att-1",
                    "name": "Fwd: report",
                }
            ]
        },
        {
            "item": {
                "id": "nested-1",
                "subject": "Nested subject",
                "from": {"emailAddress": {"address": "nested@example.com"}},
            }
        },
    ]
    mocker.patch.object(app_module, "MsGraphHelper", return_value=helper)

    params = Mock(container_count=4294967295)
    params.is_manual_poll.return_value = False
    asset = _asset(extract_attachments=True, ingest_eml=False)

    output = list(app_module.on_poll.__wrapped__(params, Mock(), asset))

    assert helper.make_rest_call_helper.call_count == 3
    expand_endpoint = helper.make_rest_call_helper.call_args_list[2].args[0]
    assert expand_endpoint.endswith(
        "/attachments/att-1?$expand=microsoft.graph.itemAttachment/item"
    )

    email_artifacts = [
        item for item in output if getattr(item, "name", None) == "Email Artifact"
    ]
    assert len(email_artifacts) == 2
    assert email_artifacts[1].cef["subject"] == "Nested subject"
    assert email_artifacts[1].cef["fromEmail"] == "nested@example.com"

    vault_artifacts = [
        item for item in output if getattr(item, "name", None) == "Vault Artifact"
    ]
    assert vault_artifacts == []


def test_on_poll_item_attachment_saves_eml_to_vault_when_ingest_eml_enabled(mocker):
    helper = Mock()
    helper.make_rest_call_helper.side_effect = [
        {"value": [_email("one", "2026-07-16T01:00:00Z", has_attachments=True)]},
        {
            "value": [
                {
                    "@odata.type": "#microsoft.graph.itemAttachment",
                    "id": "att-1",
                    "name": "Fwd: report",
                }
            ]
        },
        {
            "item": {
                "id": "nested-1",
                "subject": "Nested subject",
                "from": {"emailAddress": {"address": "nested@example.com"}},
            }
        },
        b"nested eml bytes",
    ]
    mocker.patch.object(app_module, "MsGraphHelper", return_value=helper)

    soar = Mock()
    soar.vault.create_attachment.return_value = "vault-id-nested"

    params = Mock(container_count=4294967295)
    params.is_manual_poll.return_value = False
    asset = _asset(extract_attachments=True, ingest_eml=True)

    output = []
    for item in app_module.on_poll.__wrapped__(params, soar, asset):
        if isinstance(item, Container):
            item.container_id = 66
        output.append(item)

    soar.vault.create_attachment.assert_called_once_with(
        66, b"nested eml bytes", "Fwd: report.eml"
    )

    vault_artifacts = [
        item for item in output if getattr(item, "name", None) == "Vault Artifact"
    ]
    assert len(vault_artifacts) == 1
    assert vault_artifacts[0].cef["vaultId"] == "vault-id-nested"
