# Copyright (c) 2017-2026 Splunk Inc.

import base64
import io
import json

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions import send_email as send_email_module
from src.actions.send_email import SendEmailParams, send_email


send_email_function = send_email.__wrapped__


class FakeVaultAttachment:
    def __init__(
        self,
        content: bytes,
        *,
        vault_id: str = "vault-id",
        name: str = "report.txt",
        mime_type: str | None = "text/plain",
        size: int | None = None,
    ):
        self.content = content
        self.vault_id = vault_id
        self.name = name
        self.mime_type = mime_type
        self.size = len(content) if size is None else size

    def open(self, mode):
        assert mode == "rb"
        return io.BytesIO(self.content)


def _params(attachments: str = "") -> SendEmailParams:
    return SendEmailParams(
        from_email="analyst@example.com",
        to="recipient@example.com",
        subject="SOAR report",
        body="Attached report",
        attachments=attachments,
    )


def _mock_helper(mocker):
    helper_class = mocker.patch.object(send_email_module, "MsGraphHelper")
    return helper_class, helper_class.return_value


def test_send_email_without_attachments_preserves_direct_sendmail(mocker):
    helper_class, helper = _mock_helper(mocker)
    soar = mocker.Mock()
    asset = mocker.Mock()

    output = send_email_function(_params(), soar, asset)

    helper_class.assert_called_once_with(soar, asset)
    helper.get_token.assert_called_once_with()
    helper.make_rest_call_helper.assert_called_once()
    call = helper.make_rest_call_helper.call_args
    assert call.args[0] == "/users/analyst@example.com/sendMail"
    assert call.kwargs["method"] == "post"
    assert json.loads(call.kwargs["data"])["saveToSentItems"] is True
    assert output.message == "Email sent successfully"


def test_send_email_resolves_vault_in_container_then_uploads_small_file(mocker):
    _, helper = _mock_helper(mocker)
    attachment = FakeVaultAttachment(b"report contents")
    soar = mocker.Mock()
    soar.get_executing_container_id.return_value = 42
    soar.vault.get_attachment.return_value = [attachment]
    helper.make_rest_call_helper.side_effect = [
        {"id": "draft/id"},
        {"id": "attachment-id"},
        {},
    ]

    send_email_function(_params("vault-id"), soar, mocker.Mock())

    soar.vault.get_attachment.assert_called_once_with(
        vault_id="vault-id", container_id=42
    )
    calls = helper.make_rest_call_helper.call_args_list
    assert calls[0].args[0] == "/users/analyst%40example.com/messages"
    assert calls[1].args[0] == (
        "/users/analyst%40example.com/messages/draft%2Fid/attachments"
    )
    attachment_body = json.loads(calls[1].kwargs["data"])
    assert attachment_body == {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "name": "report.txt",
        "contentType": "text/plain",
        "contentBytes": base64.b64encode(b"report contents").decode("ascii"),
        "isInline": False,
    }
    assert calls[2].args[0] == ("/users/analyst%40example.com/messages/draft%2Fid/send")


def test_send_email_falls_back_to_global_vault_lookup(mocker):
    _, helper = _mock_helper(mocker)
    attachment = FakeVaultAttachment(b"report")
    soar = mocker.Mock()
    soar.get_executing_container_id.return_value = 42
    soar.vault.get_attachment.side_effect = [[], [attachment]]
    helper.make_rest_call_helper.side_effect = [{"id": "draft"}, {}, {}]

    send_email_function(_params("vault-id"), soar, mocker.Mock())

    assert soar.vault.get_attachment.call_args_list == [
        mocker.call(vault_id="vault-id", container_id=42),
        mocker.call(vault_id="vault-id"),
    ]


def test_send_email_resolves_all_vault_ids_before_creating_draft(mocker):
    helper_class, _ = _mock_helper(mocker)
    soar = mocker.Mock()
    soar.get_executing_container_id.return_value = 42
    soar.vault.get_attachment.return_value = []

    with pytest.raises(ActionFailure, match="Failed to find Vault entry missing"):
        send_email_function(_params("missing"), soar, mocker.Mock())

    helper_class.assert_not_called()


def test_send_email_rejects_attachment_over_150_mb_before_creating_draft(mocker):
    helper_class, _ = _mock_helper(mocker)
    attachment = FakeVaultAttachment(
        b"",
        vault_id="too-large",
        size=send_email_module.MSGOFFICE365_MAX_ATTACHMENT_SIZE + 1,
    )
    soar = mocker.Mock()
    soar.get_executing_container_id.return_value = 42
    soar.vault.get_attachment.return_value = [attachment]

    with pytest.raises(ActionFailure, match="exceeds the 150 MB attachment limit"):
        send_email_function(_params("too-large"), soar, mocker.Mock())

    helper_class.assert_not_called()


def test_send_email_uses_upload_session_and_two_mb_chunks(mocker, monkeypatch):
    monkeypatch.setattr(send_email_module, "MSGOFFICE365_UPLOAD_SESSION_CUTOFF", 3)
    monkeypatch.setattr(send_email_module, "MSGOFFICE365_UPLOAD_CHUNK_SIZE", 2)
    _, helper = _mock_helper(mocker)
    attachment = FakeVaultAttachment(b"abcde")
    soar = mocker.Mock()
    soar.get_executing_container_id.return_value = 42
    soar.vault.get_attachment.return_value = [attachment]
    helper.make_rest_call_helper.side_effect = [
        {"id": "draft"},
        {"uploadUrl": "https://outlook.office.com/upload/token"},
        {},
    ]

    send_email_function(_params("vault-id"), soar, mocker.Mock())

    assert helper.upload_attachment_chunk.call_args_list == [
        mocker.call("https://outlook.office.com/upload/token", b"ab", "bytes 0-1/5"),
        mocker.call("https://outlook.office.com/upload/token", b"cd", "bytes 2-3/5"),
        mocker.call("https://outlook.office.com/upload/token", b"e", "bytes 4-4/5"),
    ]


def test_send_email_deletes_incomplete_draft_when_attachment_upload_fails(
    mocker, monkeypatch
):
    monkeypatch.setattr(send_email_module, "MSGOFFICE365_UPLOAD_SESSION_CUTOFF", 3)
    _, helper = _mock_helper(mocker)
    attachment = FakeVaultAttachment(b"abc")
    soar = mocker.Mock()
    soar.get_executing_container_id.return_value = 42
    soar.vault.get_attachment.return_value = [attachment]
    helper.make_rest_call_helper.side_effect = [
        {"id": "draft"},
        {"uploadUrl": "https://outlook.office.com/upload/token"},
        {},
    ]
    helper.upload_attachment_chunk.side_effect = ActionFailure("upload failed")

    with pytest.raises(ActionFailure, match="upload failed"):
        send_email_function(_params("vault-id"), soar, mocker.Mock())

    cleanup_call = helper.make_rest_call_helper.call_args_list[-1]
    assert cleanup_call.args[0] == "/users/analyst%40example.com/messages/draft"
    assert cleanup_call.kwargs["method"] == "delete"


def test_attachment_parameter_is_optional_allow_list_vault_id():
    field = SendEmailParams.model_fields["attachments"]

    assert field.default == ""
    assert field.json_schema_extra == {
        "required": False,
        "primary": True,
        "cef_types": ["sha1", "vault id"],
        "allow_list": True,
        "sensitive": False,
    }
