# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import GraphPaginationState, MsGraphHelper, escape_odata_string


# Graph @odata.type -> legacy mailbox type label.
MEMBER_TYPE_MAP = {
    "#microsoft.graph.user": "Mailbox",
    "#microsoft.graph.group": "PublicDL",
    "#microsoft.graph.orgContact": "Contact",
}

# Mail-capable recipient types only; devices/service principals are excluded.
RECIPIENT_TYPES = set(MEMBER_TYPE_MAP)


class ListAddressesParams(Params):
    group: str = Param(
        description="Distribution List to expand (email address or display name)",
        required=True,
        primary=True,
        cef_types=["email", "exchange distribution list"],
    )
    recursive: bool = Param(
        description="Expand all sub distribution lists",
        required=False,
        default=False,
    )


class DistributionListMember(ActionOutput):
    id: str | None = None
    displayName: str | None = None
    mail: str | None = None
    userPrincipalName: str | None = None
    mailboxType: str | None = None


def _resolve_group_id(helper: MsGraphHelper, group: str) -> str:
    """Resolve a DL email/display name to a group id; error if ambiguous."""
    escaped = escape_odata_string(group)
    # Match only mail-enabled groups; parens are required as OData binds `and` over `or`.
    api_params = {
        "$filter": (
            f"(mail eq '{escaped}' or "
            f"displayName eq '{escaped}' or "
            f"mailNickname eq '{escaped}') and mailEnabled eq true"
        ),
        "$select": "id,displayName,mail,mailNickname",
    }
    value = []
    next_link = None
    pagination_state = GraphPaginationState()
    while True:
        resp = helper.make_rest_call_helper(
            "/groups",
            # nextLink already carries the query; send params only on the first page.
            params=api_params if next_link is None else None,
            nextLink=next_link,
            pagination_state=pagination_state,
        )
        value.extend(resp.get("value", []))
        next_link = resp.get("@odata.nextLink")
        if not next_link:
            break
    if not value:
        raise ActionFailure(
            f"No mail-enabled distribution list found matching '{group}'. The input "
            "might not be a valid distribution list, it may be a mail-disabled security "
            "group, or it may be a dynamic distribution group, which Microsoft Graph "
            "does not expose (dynamic distribution groups are not supported by this "
            "action)."
        )
    if len(value) == 1:
        return value[0]["id"]

    # Multiple matches: fall back to an exact mail/alias match.
    lowered = group.lower()
    exact = [
        g
        for g in value
        if (g.get("mail") or "").lower() == lowered
        or (g.get("mailNickname") or "").lower() == lowered
    ]
    if len(exact) == 1:
        return exact[0]["id"]

    raise ActionFailure(
        f"Multiple distribution lists match '{group}'. Specify the exact email "
        "address or alias (mailNickname) to disambiguate."
    )


@app.action(
    description="Get the email addresses that make up a Distribution List",
    action_type="investigate",
    read_only=True,
)
def list_addresses(
    params: ListAddressesParams, soar: SOARClient, asset: Asset
) -> list[DistributionListMember]:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    group_id = _resolve_group_id(helper, params.group)

    # transitiveMembers lets Graph expand nested lists; members is direct-only.
    membership = "transitiveMembers" if params.recursive else "members"
    endpoint = f"/groups/{group_id}/{membership}"

    members = []
    next_link = None
    pagination_state = GraphPaginationState()
    while True:
        resp = helper.make_rest_call_helper(
            endpoint, nextLink=next_link, pagination_state=pagination_state
        )
        members.extend(resp.get("value", []))
        next_link = resp.get("@odata.nextLink")
        if not next_link:
            break

    results = []
    for member in members:
        odata_type = member.get("@odata.type", "")
        # Skip non-recipient objects (devices, service principals).
        if odata_type not in RECIPIENT_TYPES:
            continue
        # Skip members with no SMTP address; never substitute the UPN for mail.
        mail = member.get("mail")
        if not mail:
            continue
        results.append(
            DistributionListMember(
                id=member.get("id"),
                displayName=member.get("displayName"),
                mail=mail,
                userPrincipalName=member.get("userPrincipalName"),
                mailboxType=MEMBER_TYPE_MAP[odata_type],
            )
        )

    soar.set_message(f"Successfully retrieved {len(results)} addresses")
    return results
