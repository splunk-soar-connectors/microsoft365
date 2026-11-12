# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import (
    GraphPaginationState,
    MsGraphHelper,
    encode_path_segment,
    escape_odata_string,
)


# Graph @odata.type -> legacy mailbox type label. Only these mail-capable types
# are returned; other objects (devices, service principals) are excluded.
MEMBER_TYPE_MAP = {
    "#microsoft.graph.user": "Mailbox",
    "#microsoft.graph.group": "PublicDL",
    "#microsoft.graph.orgContact": "Contact",
}


class ListAddressesParams(Params):
    group: str = Param(
        description="Mail-enabled group to expand (email address or display name)",
        required=True,
        primary=True,
        cef_types=["email", "exchange distribution list"],
    )
    recursive: bool = Param(
        description="Expand all nested groups and return only their members",
        required=False,
        default=False,
    )


class DistributionListMember(ActionOutput):
    id: str | None = None
    displayName: str | None = None
    mail: str | None = OutputField(cef_types=["email"])
    userPrincipalName: str | None = OutputField(
        cef_types=["msgoffice365 user principal name"]
    )
    mailboxType: str | None = None


class ListAddressesSummary(ActionOutput):
    total_entries: int = 0
    members_omitted: int = 0


def _member_mailbox_type(member: dict, odata_type: str) -> str:
    """Microsoft 365 groups carry 'Unified' in groupTypes; other groups act as DLs."""
    if odata_type == "#microsoft.graph.group" and "Unified" in (
        member.get("groupTypes") or []
    ):
        return "GroupMailbox"
    return MEMBER_TYPE_MAP[odata_type]


def _resolve_group_id(helper: MsGraphHelper, group: str) -> str:
    """Resolve a mail-enabled group's email/display name to its id; error if ambiguous."""
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
            f"No mail-enabled group found matching '{group}'. The input might not be "
            "a mail-enabled group, it may be a mail-disabled security group, or it may "
            "be a dynamic distribution group, which Microsoft Graph does not expose "
            "(dynamic distribution groups are not supported by this action)."
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
        f"Multiple groups match '{group}'. Specify the exact email "
        "address or alias (mailNickname) to disambiguate."
    )


@app.view_handler(template="office365_list_addresses.html")
def render_list_addresses(output: list[DistributionListMember]) -> dict:
    members = [
        {
            "mail": member.mail,
            "display_name": member.displayName,
            "mailbox_type": member.mailboxType,
            "user_principal_name": member.userPrincipalName,
            "id": member.id,
        }
        for member in output
    ]
    return {"results": [{"data": bool(members), "members": members}]}


@app.action(
    description=(
        "Expand a mail-enabled group (distribution list, mail-enabled security group, "
        "or Microsoft 365 group) into its members. Takes a group by email address or "
        "display name and returns a record for each mail-capable member (email address, "
        "display name, and mailbox type)."
    ),
    action_type="investigate",
    read_only=True,
    summary_type=ListAddressesSummary,
    view_handler=render_list_addresses,
)
def list_addresses(
    params: ListAddressesParams, soar: SOARClient, asset: Asset
) -> list[DistributionListMember]:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    group_id = _resolve_group_id(helper, params.group)

    # transitiveMembers lets Graph expand nested lists; members is direct-only.
    membership = "transitiveMembers" if params.recursive else "members"
    endpoint = f"/groups/{encode_path_segment(group_id)}/{membership}"

    members = []
    next_link = None
    pagination_state = GraphPaginationState()
    while True:
        resp = helper.make_rest_call_helper(
            endpoint,
            params={"$top": "999"} if next_link is None else None,
            nextLink=next_link,
            pagination_state=pagination_state,
        )
        members.extend(resp.get("value", []))
        next_link = resp.get("@odata.nextLink")
        if not next_link:
            break

    results = []
    skipped = 0
    for member in members:
        odata_type = member.get("@odata.type", "")
        # Skip non-recipient objects (devices, service principals).
        if odata_type not in MEMBER_TYPE_MAP:
            continue
        # Recursive results already include nested groups' members; drop the groups.
        if params.recursive and odata_type == "#microsoft.graph.group":
            continue
        # Skip members with no SMTP address; never substitute the UPN for mail.
        mail = member.get("mail")
        if not mail:
            skipped += 1
            continue
        results.append(
            DistributionListMember(
                id=member.get("id"),
                displayName=member.get("displayName"),
                mail=mail,
                userPrincipalName=member.get("userPrincipalName"),
                mailboxType=_member_mailbox_type(member, odata_type),
            )
        )

    message = f"Successfully retrieved {len(results)} addresses"
    if skipped:
        message += f" ({skipped} members without an email address were omitted)"
    soar.set_message(message)
    soar.set_summary(
        ListAddressesSummary(total_entries=len(results), members_omitted=skipped)
    )
    return results
