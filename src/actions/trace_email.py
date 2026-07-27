# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..consts import (
    MAX_END_OFFSET_VAL,
    MSGOFFICE365_MESSAGE_TRACE_ENDPOINT,
    MSGOFFICE365_MESSAGE_TRACE_MAX_TOP,
)
from ..helper import MsGraphHelper


class TraceEmailParams(Params):
    sender_address: str = Param(
        description=(
            "The SMTP email address of the user the message was purportedly from. "
            "You can specify multiple values separated by commas."
        ),
        required=False,
        default="",
        primary=True,
        cef_types=["email"],
    )
    recipient_address: str = Param(
        description=(
            "The SMTP email address of the user that the message was addressed to. "
            "You can specify multiple values separated by commas."
        ),
        required=False,
        default="",
        primary=True,
        cef_types=["email"],
    )
    status: str = Param(
        description=(
            "The status corresponds to the Detail field of the last processing step "
            "recorded for the message. You can specify multiple values separated by commas."
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
        description="Email range to return (min_offset-max_offset)",
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


def _escape(value: str) -> str:
    """Escape single quotes for use inside an OData string literal."""
    return value.replace("'", "''")


def _or_clause(field: str, raw_value: str) -> str | None:
    """Build an OData filter clause for one or more comma-separated values."""
    values = [v.strip() for v in raw_value.split(",") if v.strip()]
    if not values:
        return None
    clauses = [f"{field} eq '{_escape(v)}'" for v in values]
    if len(clauses) == 1:
        return clauses[0]
    return "(" + " or ".join(clauses) + ")"


def _build_filter(params: TraceEmailParams) -> str:
    """Translate the action parameters into a Microsoft Graph $filter string.

    Note: Graph supports filtering on id, messageId, receivedDateTime,
    recipientAddress, senderAddress, status, subject and toIP. from_ip is not
    a filterable property, so it is applied client-side against the returned
    fromIP field to preserve parity with the legacy office365 action.
    """
    if (params.start_date and not params.end_date) or (
        params.end_date and not params.start_date
    ):
        raise ActionFailure(
            "Please specify both the 'start date' and 'end date' parameters"
        )

    clauses = []
    if clause := _or_clause("senderAddress", params.sender_address):
        clauses.append(clause)
    if clause := _or_clause("recipientAddress", params.recipient_address):
        clauses.append(clause)
    if clause := _or_clause("status", params.status):
        clauses.append(clause)
    if params.message_trace_id:
        clauses.append(f"id eq '{_escape(params.message_trace_id)}'")
    if params.internet_message_id:
        clauses.append(f"messageId eq '{_escape(params.internet_message_id)}'")
    if params.to_ip:
        clauses.append(f"toIP eq '{_escape(params.to_ip)}'")
    if params.start_date and params.end_date:
        clauses.append(
            f"receivedDateTime ge {params.start_date} and "
            f"receivedDateTime le {params.end_date}"
        )

    return " and ".join(clauses)


@app.action(
    description="Get message trace from the server",
    action_type="investigate",
)
def trace_email(
    params: TraceEmailParams, soar: SOARClient, asset: Asset
) -> list[MessageTraceOutput]:
    mini, maxi = 0, MAX_END_OFFSET_VAL
    if params.range:
        mini, maxi = _validate_range(params.range)

    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    filter_str = _build_filter(params)
    api_params: dict | None = {"$top": str(MSGOFFICE365_MESSAGE_TRACE_MAX_TOP)}
    if filter_str:
        api_params["$filter"] = filter_str

    # The message trace API currently lives under the Graph beta endpoint.
    results: list[dict] = []
    next_link = None
    while True:
        resp = helper.make_rest_call_helper(
            MSGOFFICE365_MESSAGE_TRACE_ENDPOINT,
            params=api_params,
            nextLink=next_link,
            beta=True,
        )
        results.extend(resp.get("value", []))

        next_link = resp.get("@odata.nextLink")
        # Stop early once we have enough rows, but only when we are not doing a
        # client-side from_ip filter (which needs the full result set first).
        if not next_link or (not params.from_ip and len(results) > maxi):
            break
        api_params = None

    # from_ip is not filterable server-side; apply it here for parity.
    if params.from_ip:
        results = [r for r in results if r.get("fromIP") == params.from_ip]

    if params.widget_filter:
        for row in results:
            if row.get("messageId"):
                row["messageId"] = row["messageId"].replace(">", "").replace("<", "")

    results = results[mini : maxi + 1]

    soar.set_message(f"Emails found: {len(results)}")
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
