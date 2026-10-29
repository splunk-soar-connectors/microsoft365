# Copyright (c) 2017-2026 Splunk Inc.
from datetime import UTC, datetime, timedelta

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.extras.email.utils import is_ip
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..consts import (
    MAX_END_OFFSET_VAL,
    MSGOFFICE365_MESSAGE_TRACE_DEFAULT_MAX_OFFSET,
    MSGOFFICE365_MESSAGE_TRACE_ENDPOINT,
    MSGOFFICE365_MESSAGE_TRACE_MAX_TOP,
)
from ..helper import (
    GraphPaginationState,
    MsGraphHelper,
    escape_odata_string,
    is_cba_auth,
)


class TraceEmailParams(Params):
    sender_address: str = Param(
        description="The SMTP email address of the user the message was purportedly from",
        required=False,
        default="",
        primary=True,
        cef_types=["email"],
    )
    recipient_address: str = Param(
        description="The SMTP email address of the user that the message was addressed to",
        required=False,
        default="",
        primary=True,
        cef_types=["email"],
    )
    status: str = Param(
        description=(
            "Filter by the message delivery status. One of: gettingStatus, pending, "
            "failed, delivered, expanded, quarantined, filteredAsSpam, unknownFutureValue."
        ),
        required=False,
        default="",
    )
    message_trace_id: str = Param(
        description="An identifier used to get the detailed message transfer trace information",
        required=False,
        default="",
        primary=True,
        cef_types=["office 365 trace id"],
    )
    start_date: str = Param(
        description="Start date of the date range (ISO 8601, e.g. 2026-01-20T00:00:00Z)",
        required=False,
        default="",
    )
    end_date: str = Param(
        description="End date of the date range (ISO 8601, e.g. 2026-01-23T00:00:00Z)",
        required=False,
        default="",
    )
    from_ip: str = Param(
        description="The IPv4 or IPv6 address that transmitted the message to the email system",
        required=False,
        default="",
        primary=True,
        cef_types=["ip", "ipv6"],
    )
    to_ip: str = Param(
        description="The IPv4 or IPv6 address that the email system sent the message to",
        required=False,
        default="",
        primary=True,
        cef_types=["ip", "ipv6"],
    )
    internet_message_id: str = Param(
        description="Filters the results by the Internet Message ID (also known as the Client ID)",
        required=False,
        default="",
        primary=True,
        cef_types=["internet message id"],
    )
    widget_filter: bool = Param(
        description="Remove the angle brackets from the Internet Message ID field",
        required=False,
        default=False,
    )
    range: str = Param(
        description="Email range to return (min_offset-max_offset). Defaults to 0-999",
        required=False,
        default="",
    )


class MessageTraceOutput(ActionOutput):
    id: str | None = None
    senderAddress: str | None = None
    recipientAddress: str | None = None
    messageId: str | None = None
    receivedDateTime: str | None = None
    subject: str | None = None
    size: int | None = None
    fromIP: str | None = None
    toIP: str | None = None
    status: str | None = None


class TraceEmailSummary(ActionOutput):
    emails_found: int = 0


def _validate_range(email_range: str) -> tuple[int, int]:
    """Validate and parse a 'min-max' offset range, mirroring the office365 app."""
    try:
        mini, maxi = (int(x) for x in email_range.split("-"))
    except Exception:
        raise ActionFailure(
            "Unable to parse the range. Please specify the range as min_offset-max_offset"
        ) from None

    if mini < 0 or maxi < 0:
        raise ActionFailure("Invalid min or max offset value specified in range")
    if mini > maxi:
        raise ActionFailure("Invalid range value, min_offset greater than max_offset")
    if maxi > MAX_END_OFFSET_VAL:
        raise ActionFailure(
            f"Invalid range value. The max_offset value cannot be greater than {MAX_END_OFFSET_VAL}"
        )
    return mini, maxi


def _validate_iso_utc(value: str, field: str) -> datetime:
    """Validate and parse a strict ISO-8601 UTC timestamp (YYYY-MM-DDThh:mm:ssZ)."""
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise ActionFailure(
            f"'{field}' must be an ISO 8601 UTC timestamp of the form "
            "YYYY-MM-DDThh:mm:ssZ (e.g. 2026-01-20T00:00:00Z)"
        ) from None


# exchangeMessageTraceStatus enum, keyed by lowercase for case-insensitive input.
_STATUS_CANONICAL = {
    "gettingstatus": "gettingStatus",
    "pending": "pending",
    "failed": "failed",
    "delivered": "delivered",
    "expanded": "expanded",
    "quarantined": "quarantined",
    "filteredasspam": "filteredAsSpam",
    "unknownfuturevalue": "unknownFutureValue",
}
_VALID_STATUS_DISPLAY = ", ".join(_STATUS_CANONICAL.values())


def _single_value(raw_value: str, label: str) -> str:
    """Return the trimmed value; Graph's trace API supports one value per field."""
    value = raw_value.strip()
    if "," in value:
        raise ActionFailure(
            f"'{label}' accepts a single value; multiple values are not supported"
        )
    return value


def _eq_clause(field: str, raw_value: str, label: str) -> str | None:
    value = _single_value(raw_value, label)
    return f"{field} eq '{escape_odata_string(value)}'" if value else None


def _status_clause(raw_value: str) -> str | None:
    value = _single_value(raw_value, "status")
    if not value:
        return None
    mapped = _STATUS_CANONICAL.get(value.lower())
    if mapped is None:
        raise ActionFailure(
            f"Invalid status '{value}'. Valid values are: {_VALID_STATUS_DISPLAY}"
        )
    return f"status eq '{mapped}'"


def _build_filter(params: TraceEmailParams) -> str:
    """Build the Microsoft Graph $filter string from the supplied parameters."""
    if (params.start_date and not params.end_date) or (
        params.end_date and not params.start_date
    ):
        raise ActionFailure(
            "Please specify both the 'start date' and 'end date' parameters"
        )

    clauses = []
    if clause := _eq_clause("senderAddress", params.sender_address, "sender address"):
        clauses.append(clause)
    if clause := _eq_clause(
        "recipientAddress", params.recipient_address, "recipient address"
    ):
        clauses.append(clause)
    if clause := _status_clause(params.status):
        clauses.append(clause)
    if params.message_trace_id:
        clauses.append(f"id eq '{escape_odata_string(params.message_trace_id)}'")
    if params.internet_message_id:
        # Graph stores message IDs with angle brackets; normalize the input.
        bare = params.internet_message_id.strip().strip("<>")
        clauses.append(f"messageId eq '<{escape_odata_string(bare)}>'")
    if params.from_ip:
        if not is_ip(params.from_ip):
            raise ActionFailure(
                f"'from ip' is not a valid IP address: {params.from_ip}"
            )
        clauses.append(f"fromIP eq '{escape_odata_string(params.from_ip)}'")
    if params.to_ip:
        if not is_ip(params.to_ip):
            raise ActionFailure(f"'to ip' is not a valid IP address: {params.to_ip}")
        clauses.append(f"toIP eq '{escape_odata_string(params.to_ip)}'")
    if params.start_date and params.end_date:
        start_dt = _validate_iso_utc(params.start_date, "start date")
        end_dt = _validate_iso_utc(params.end_date, "end date")
        now = datetime.now(UTC)
        if end_dt < start_dt:
            raise ActionFailure("'end date' must not be earlier than 'start date'")
        if end_dt > now:
            raise ActionFailure("'end date' must not be in the future")
        if end_dt - start_dt > timedelta(days=10):
            raise ActionFailure("The date range must not exceed 10 days")
        if start_dt < now - timedelta(days=90):
            raise ActionFailure("'start date' must be within the last 90 days")
        # Re-serialize to a canonical, zero-padded timestamp.
        clauses.append(
            f"receivedDateTime ge {start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')} and "
            f"receivedDateTime le {end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )

    return " and ".join(clauses)


@app.view_handler(template="office365_trace_email.html")
def render_trace_email(output: list[MessageTraceOutput]) -> dict:
    emails = [
        {
            "sender_address": row.senderAddress,
            "recipient_address": row.recipientAddress,
            "subject": row.subject,
            "status": row.status,
            "received_date_time": row.receivedDateTime,
            "from_ip": row.fromIP,
            "to_ip": row.toIP,
            "message_id": row.messageId,
            "id": row.id,
            "size": row.size,
        }
        for row in output
    ]
    return {"results": [{"data": bool(emails), "emails": emails}]}


@app.action(
    description=(
        "Get the message trace for emails (Exchange Online) via the Microsoft Graph "
        "v1.0 message-trace API. Requires a one-time message-trace service principal and "
        "application-only authentication. Query limits: results cover the last 90 days, a "
        "single query can span at most 10 days, and with no date range the last 48 hours "
        "are returned."
    ),
    action_type="investigate",
    read_only=True,
    view_handler=render_trace_email,
)
def trace_email(
    params: TraceEmailParams, soar: SOARClient, asset: Asset
) -> list[MessageTraceOutput]:
    # App-only by design: client credentials or certificate; delegated is rejected.
    if not (asset.admin_access or is_cba_auth(asset)):
        raise ActionFailure(
            "Trace email requires application-only authentication. Use certificate "
            "authentication, or enable 'admin access' with a client secret; delegated "
            "OAuth is not supported for this action."
        )

    mini, maxi = 0, MSGOFFICE365_MESSAGE_TRACE_DEFAULT_MAX_OFFSET
    if params.range:
        mini, maxi = _validate_range(params.range)

    # Validate and build the filter before authenticating so invalid input fails fast.
    filter_str = _build_filter(params)

    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    api_params: dict | None = {
        "$top": str(min(MSGOFFICE365_MESSAGE_TRACE_MAX_TOP, maxi + 1))
    }
    if filter_str:
        api_params["$filter"] = filter_str

    results: list[dict] = []
    next_link = None
    pagination_state = GraphPaginationState()
    while True:
        resp = helper.make_rest_call_helper(
            MSGOFFICE365_MESSAGE_TRACE_ENDPOINT,
            params=api_params,
            nextLink=next_link,
            pagination_state=pagination_state,
        )
        results.extend(resp.get("value", []))

        next_link = resp.get("@odata.nextLink")
        if not next_link or len(results) > maxi:
            break
        api_params = None

    if params.widget_filter:
        for row in results:
            if row.get("messageId"):
                row["messageId"] = row["messageId"].replace(">", "").replace("<", "")

    results = results[mini : maxi + 1]

    soar.set_message(f"Emails found: {len(results)}")
    soar.set_summary(TraceEmailSummary(emails_found=len(results)))
    return [
        MessageTraceOutput(
            id=r.get("id"),
            senderAddress=r.get("senderAddress"),
            recipientAddress=r.get("recipientAddress"),
            messageId=r.get("messageId"),
            receivedDateTime=r.get("receivedDateTime"),
            subject=r.get("subject"),
            size=r.get("size"),
            fromIP=r.get("fromIP"),
            toIP=r.get("toIP"),
            status=r.get("status"),
        )
        for r in results
    ]
