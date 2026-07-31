# Copyright (c) 2017-2026 Splunk Inc.

import base64
from unittest.mock import Mock

from src.actions.get_email import _save_attachments_to_vault, get_email


def test_save_attachments_to_vault_adds_file_attachments_and_records_vault_id():
    soar = Mock()
    soar.get_executing_container_id.return_value = 42
    soar.vault.create_attachment.return_value = "vault-id-123"
    content_bytes = base64.b64encode(b"file contents").decode("utf-8")
    attachments = [
        {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": "evidence.txt",
            "contentBytes": content_bytes,
        }
    ]

    result = _save_attachments_to_vault(attachments, soar)

    soar.vault.create_attachment.assert_called_once_with(
        42, b"file contents", "evidence.txt"
    )
    assert result[0]["vaultId"] == "vault-id-123"
    assert "contentBytes" not in result[0]


def test_save_attachments_to_vault_skips_non_file_attachments():
    soar = Mock()

    attachments = [{"@odata.type": "#microsoft.graph.itemAttachment", "name": "a"}]
    result = _save_attachments_to_vault(attachments, soar)

    soar.get_executing_container_id.assert_not_called()
    soar.vault.create_attachment.assert_not_called()
    assert result == attachments


def test_save_attachments_to_vault_logs_and_continues_on_vault_failure(mocker):
    soar = Mock()
    soar.get_executing_container_id.return_value = 42
    soar.vault.create_attachment.side_effect = Exception("vault unavailable")
    logger = mocker.patch("src.actions.get_email.logger")
    content_bytes = base64.b64encode(b"file contents").decode("utf-8")
    attachments = [
        {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": "evidence.txt",
            "contentBytes": content_bytes,
        }
    ]

    result = _save_attachments_to_vault(attachments, soar)

    assert "vaultId" not in result[0]
    logger.warning.assert_called_once()


def test_get_email_downloads_attachments_and_returns_vault_id(mocker):
    soar = Mock()
    soar.get_executing_container_id.return_value = 7
    soar.vault.create_attachment.return_value = "vault-id-abc"
    content_bytes = base64.b64encode(b"attachment payload").decode("utf-8")

    helper = Mock()
    helper.make_rest_call_helper.side_effect = [
        {"id": "msg-1", "hasAttachments": True},
        {
            "value": [
                {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": "report.pdf",
                    "contentBytes": content_bytes,
                }
            ]
        },
    ]
    mocker.patch("src.actions.get_email.MsGraphHelper", return_value=helper)

    params = Mock(
        id="msg-1",
        email_address="user@example.com",
        get_headers=False,
        download_attachments=True,
    )

    output = get_email(params, soar, Mock())

    soar.vault.create_attachment.assert_called_once_with(
        7, b"attachment payload", "report.pdf"
    )
    assert '"vaultId": "vault-id-abc"' in output.attachments
