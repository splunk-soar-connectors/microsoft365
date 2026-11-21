# Copyright (c) 2017-2026 Splunk Inc.

import json
from typing import TYPE_CHECKING

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params


if TYPE_CHECKING:
    from ..app import Asset
from ..consts import (
    MSGOFFICE365_PER_PAGE_COUNT,
    MSGOFFICE365_RECOVERABLE_ITEMS_FOLDERS_FILTER,
    MSGOFFICE365_SELECT_PARAMETER_LIST,
)
from ..helper import (
    GraphPaginationState,
    GraphTokenRejected,
    MsGraphHelper,
    escape_odata_string,
    quote_graph_search_phrase,
    serialize_complex_fields,
)


logger = getLogger()


class RunQueryParams(Params):
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        cef_types=["email"],
    )
    folder: str = Param(
        description="Folder name/path or ID",
        required=False,
        default="Inbox",
    )
    get_folder_id: bool = Param(
        description="Retrieve folder ID from folder name/path",
        required=False,
        default=True,
    )
    subject: str = Param(
        description="Substring to search in subject",
        required=False,
        default="",
    )
    sender: str = Param(
        description="Sender email to search",
        required=False,
        default="",
    )
    body: str = Param(
        description="Substring to search in body",
        required=False,
        default="",
    )
    internet_message_id: str = Param(
        description="Internet Message ID to search",
        required=False,
        default="",
    )
    limit: int = Param(
        description="Maximum number of emails to return (applied separately to the selected folder and, if enabled, to the Recoverable Items folder)",
        required=False,
        default=100,
    )
    search_well_known_folders: bool = Param(
        description="Search in well-known folders",
        required=False,
        default=False,
    )
    search_recoverable_items_folders: bool = Param(
        description="Also search the Recoverable Items deletions folder (soft-deleted items)",
        required=False,
        default=False,
    )


class EmailResult(ActionOutput):
    id: str | None = None
    subject: str | None = None
    sender: str | None = None
    receivedDateTime: str | None = None
    bodyPreview: str | None = None
    hasAttachments: bool | None = None
    internetMessageId: str | None = None
    parentFolderId: str | None = None


class RunQuerySummary(ActionOutput):
    emails_matched: int = 0


def _extract_sender_address(sender_json):
    if not sender_json:
        return None
    try:
        data = json.loads(sender_json) if isinstance(sender_json, str) else sender_json
        return data.get("emailAddress", {}).get("address")
    except (json.JSONDecodeError, AttributeError, ValueError):
        return None


def render_run_query(output: list[EmailResult]) -> dict:
    emails = []
    for item in output:
        emails.append(
            {
                "id": item.id,
                "subject": item.subject,
                "sender_address": _extract_sender_address(item.sender),
                "received_date_time": item.receivedDateTime,
                "body_preview": item.bodyPreview,
                "internet_message_id": item.internetMessageId,
            }
        )

    results = [
        {
            "data": bool(emails),
            "param_email_address": None,
            "param_folder": None,
            "param_get_folder_id": None,
            "param_subject": None,
            "param_body": None,
            "param_sender": None,
            "param_limit": None,
            "param_internet_message_id": None,
            "param_search_recoverable_items_folders": None,
            "emails": emails,
        }
    ]
    return {"results": results}


def _fetch_messages(helper, endpoint, api_params, limit):
    """Fetch up to `limit` messages from a single Graph endpoint."""
    items = []
    next_link = None
    pagination_state = GraphPaginationState()
    page_params = api_params.copy()
    while len(items) < limit:
        resp = helper.make_rest_call_helper(
            endpoint,
            params=page_params,
            nextLink=next_link,
            pagination_state=pagination_state,
        )
        items.extend(resp.get("value", []))

        next_link = resp.get("@odata.nextLink")
        if not next_link:
            break
        page_params = None
    return items[:limit]


def run_query(
    params: RunQueryParams, soar: SOARClient, asset: "Asset"
) -> list[EmailResult]:
    if params.limit is not None and params.limit <= 0:
        raise ValueError("'limit' action parameter must be a positive integer")

    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    folder_id = params.folder
    if params.get_folder_id and params.folder:
        resolved_id = helper.get_folder_id(params.folder, params.email_address)
        if resolved_id:
            folder_id = resolved_id

    if params.search_well_known_folders:
        endpoint = f"/users/{params.email_address}/messages"
    else:
        endpoint = f"/users/{params.email_address}/mailFolders/{folder_id}/messages"

    filters = []
    if params.subject:
        filters.append(f"contains(subject, '{escape_odata_string(params.subject)}')")
    if params.sender:
        filters.append(
            f"from/emailAddress/address eq '{escape_odata_string(params.sender)}'"
        )
    if params.internet_message_id:
        filters.append(
            f"internetMessageId eq '{escape_odata_string(params.internet_message_id)}'"
        )

    search = None
    if params.body:
        search = quote_graph_search_phrase(params.body)

    select_fields = ",".join(MSGOFFICE365_SELECT_PARAMETER_LIST)
    api_params = {"$select": select_fields}
    if filters:
        api_params["$filter"] = " and ".join(filters)
    if search:
        api_params["$search"] = search
    if params.limit:
        api_params["$top"] = str(min(params.limit, MSGOFFICE365_PER_PAGE_COUNT))

    # The selected search scope: any failure here fails the action, as before.
    emails = _fetch_messages(helper, endpoint, api_params, params.limit)

    # Recoverable Items folders are best-effort: a failing folder is skipped so the
    # results from the selected scope are still returned.
    skipped_folders = []
    if params.search_recoverable_items_folders:
        for folder in MSGOFFICE365_RECOVERABLE_ITEMS_FOLDERS_FILTER:
            folder_endpoint = (
                f"/users/{params.email_address}/mailFolders/{folder}/messages"
            )
            try:
                emails.extend(
                    _fetch_messages(helper, folder_endpoint, api_params, params.limit)
                )
            except GraphTokenRejected:
                raise
            except ActionFailure as e:
                logger.warning(f"Skipping Recoverable Items folder '{folder}': {e}")
                skipped_folders.append(folder)

    emails = [serialize_complex_fields(e, ["sender"]) for e in emails]
    message = f"Successfully retrieved {len(emails)} emails"
    if skipped_folders:
        message += f" (skipped Recoverable Items folders: {', '.join(skipped_folders)})"
    soar.set_message(message)
    soar.set_summary(RunQuerySummary(emails_matched=len(emails)))
    return [EmailResult(**e) for e in emails]
