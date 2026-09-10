# Copyright (c) 2017-2026 Splunk Inc.
import base64
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.models.vault_attachment import VaultAttachment
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..consts import (
    MSGOFFICE365_MAX_ATTACHMENT_SIZE,
    MSGOFFICE365_UPLOAD_CHUNK_SIZE,
    MSGOFFICE365_UPLOAD_SESSION_CUTOFF,
)
from ..helper import MsGraphHelper, encode_path_segment


logger = getLogger()


class SendEmailParams(Params):
    from_email: str = Param(
        description="From email address",
        required=True,
        cef_types=["email"],
    )
    to: str = Param(
        description="To email addresses (comma-separated)",
        required=True,
        cef_types=["email"],
    )
    cc: str = Param(
        description="CC email addresses (comma-separated)",
        required=False,
        default="",
    )
    bcc: str = Param(
        description="BCC email addresses (comma-separated)",
        required=False,
        default="",
    )
    subject: str = Param(
        description="Email subject",
        required=True,
    )
    body: str = Param(
        description="Email body",
        required=True,
    )
    body_is_html: bool = Param(
        description="Is body HTML",
        required=False,
        default=False,
    )
    attachments: str = Param(
        description="Comma-separated Vault IDs of files to attach (up to 150 MB each)",
        required=False,
        default="",
        allow_list=True,
        primary=True,
        cef_types=["sha1", "vault id"],
    )


class SendEmailOutput(ActionOutput):
    message: str | None = None


def _parse_recipients(email_str: str) -> list:
    if not email_str:
        return []
    emails = [e.strip() for e in email_str.split(",") if e.strip()]
    return [{"emailAddress": {"address": e}} for e in emails]


def _build_message(params: SendEmailParams) -> dict:
    message = {
        "subject": params.subject,
        "body": {
            "contentType": "HTML" if params.body_is_html else "Text",
            "content": params.body,
        },
        "toRecipients": _parse_recipients(params.to),
    }

    if params.cc:
        message["ccRecipients"] = _parse_recipients(params.cc)
    if params.bcc:
        message["bccRecipients"] = _parse_recipients(params.bcc)
    return message


def _parse_vault_ids(attachments: str) -> list[str]:
    return [vault_id.strip() for vault_id in attachments.split(",") if vault_id.strip()]


def _resolve_vault_attachments(
    soar: SOARClient, vault_ids: list[str]
) -> list[VaultAttachment]:
    resolved = []
    container_id = soar.get_executing_container_id()

    for vault_id in vault_ids:
        attachments = soar.vault.get_attachment(
            vault_id=vault_id, container_id=container_id
        )
        if not attachments:
            attachments = soar.vault.get_attachment(vault_id=vault_id)
        if not attachments:
            raise ActionFailure(f"Failed to find Vault entry {vault_id}")

        attachment = attachments[0]
        if attachment.size > MSGOFFICE365_MAX_ATTACHMENT_SIZE:
            raise ActionFailure(
                f"Vault entry {vault_id} exceeds the 150 MB attachment limit"
            )
        resolved.append(attachment)

    return resolved


def _upload_small_attachment(
    helper: MsGraphHelper,
    user_path: str,
    draft_path: str,
    attachment: VaultAttachment,
) -> None:
    try:
        with attachment.open("rb") as attachment_file:
            content = attachment_file.read()
    except OSError as e:
        raise ActionFailure(f"Failed to read Vault entry {attachment.vault_id}") from e
    if len(content) != attachment.size:
        raise ActionFailure(
            f"Vault entry {attachment.vault_id} changed while it was being read"
        )

    endpoint = f"/users/{user_path}/messages/{draft_path}/attachments"
    body = {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "name": attachment.name,
        "contentType": attachment.mime_type or "application/octet-stream",
        "contentBytes": base64.b64encode(content).decode("ascii"),
        "isInline": False,
    }
    helper.make_rest_call_helper(endpoint, method="post", data=json.dumps(body))


def _upload_large_attachment(
    helper: MsGraphHelper,
    user_path: str,
    draft_path: str,
    attachment: VaultAttachment,
) -> None:
    endpoint = (
        f"/users/{user_path}/messages/{draft_path}/attachments/createUploadSession"
    )
    body = {
        "AttachmentItem": {
            "attachmentType": "file",
            "name": attachment.name,
            "contentType": attachment.mime_type or "application/octet-stream",
            "size": attachment.size,
            "isInline": False,
        }
    }
    response = helper.make_rest_call_helper(
        endpoint, method="post", data=json.dumps(body)
    )
    upload_url = response.get("uploadUrl")
    if not upload_url:
        raise ActionFailure(
            f"Microsoft Graph did not create an upload session for Vault entry {attachment.vault_id}"
        )

    try:
        with attachment.open("rb") as attachment_file:
            for start in range(0, attachment.size, MSGOFFICE365_UPLOAD_CHUNK_SIZE):
                expected_size = min(
                    MSGOFFICE365_UPLOAD_CHUNK_SIZE, attachment.size - start
                )
                content = attachment_file.read(expected_size)
                if len(content) != expected_size:
                    raise ActionFailure(
                        f"Vault entry {attachment.vault_id} changed while it was being read"
                    )
                end = start + len(content) - 1
                helper.upload_attachment_chunk(
                    upload_url,
                    content,
                    f"bytes {start}-{end}/{attachment.size}",
                )
    except OSError as e:
        raise ActionFailure(f"Failed to read Vault entry {attachment.vault_id}") from e


def _delete_draft(helper: MsGraphHelper, user_path: str, draft_path: str) -> None:
    endpoint = f"/users/{user_path}/messages/{draft_path}"
    try:
        helper.make_rest_call_helper(endpoint, method="delete")
    except Exception:
        logger.warning("Failed to delete the incomplete email draft")


@app.action(
    description="Send an email, optionally attaching files from the SOAR Vault",
    action_type="generic",
    read_only=False,
)
def send_email(
    params: SendEmailParams, soar: SOARClient, asset: Asset
) -> SendEmailOutput:
    message = _build_message(params)
    vault_ids = _parse_vault_ids(params.attachments)
    attachments = _resolve_vault_attachments(soar, vault_ids) if vault_ids else []

    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    if not attachments:
        endpoint = f"/users/{params.from_email}/sendMail"
        body = {"message": message, "saveToSentItems": True}
        helper.make_rest_call_helper(endpoint, method="post", data=json.dumps(body))
    else:
        user_path = encode_path_segment(params.from_email)
        response = helper.make_rest_call_helper(
            f"/users/{user_path}/messages", method="post", data=json.dumps(message)
        )
        draft_id = response.get("id")
        if not draft_id:
            raise ActionFailure("Microsoft Graph did not return an email draft ID")
        draft_path = encode_path_segment(draft_id)

        try:
            for attachment in attachments:
                if attachment.size < MSGOFFICE365_UPLOAD_SESSION_CUTOFF:
                    _upload_small_attachment(helper, user_path, draft_path, attachment)
                else:
                    _upload_large_attachment(helper, user_path, draft_path, attachment)
        except Exception:
            _delete_draft(helper, user_path, draft_path)
            raise

        helper.make_rest_call_helper(
            f"/users/{user_path}/messages/{draft_path}/send", method="post"
        )

    soar.set_message("Email sent successfully")
    return SendEmailOutput(message="Email sent successfully")
