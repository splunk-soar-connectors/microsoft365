# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


# Maps the Microsoft Graph directory object type (@odata.type) to a
# human-readable mailbox type, mirroring the mailbox types the legacy
# office365 (EWS) "list addresses" action returned.
MEMBER_TYPE_MAP = {
    "#microsoft.graph.user": "Mailbox",
    "#microsoft.graph.group": "PublicDL",
    "#microsoft.graph.orgContact": "Contact",
    "#microsoft.graph.device": "Device",
    "#microsoft.graph.servicePrincipal": "ServicePrincipal",
}


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
    """Resolve a distribution list email address or display name to a group id."""
    escaped = group.replace("'", "''")
    api_params = {
        "$filter": (
            f"mail eq '{escaped}' or "
            f"displayName eq '{escaped}' or "
            f"mailNickname eq '{escaped}'"
        ),
        "$select": "id,displayName,mail",
    }
    resp = helper.make_rest_call_helper("/groups", params=api_params)
    value = resp.get("value", [])
    if not value:
        raise ActionFailure(
            f"No distribution list found matching '{group}'. "
            "The input parameter might not be a valid distribution list."
        )
    return value[0]["id"]


@app.action(
    description="Get the email addresses that make up a Distribution List",
    action_type="investigate",
)
def list_addresses(
    params: ListAddressesParams, soar: SOARClient, asset: Asset
) -> list[DistributionListMember]:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    group_id = _resolve_group_id(helper, params.group)

    # Graph exposes transitive (recursive) membership through a dedicated
    # endpoint, so we let the service do the recursion when requested rather
    # than walking the hierarchy ourselves.
    membership = "transitiveMembers" if params.recursive else "members"
    endpoint = f"/groups/{group_id}/{membership}"

    members = []
    next_link = None
    while True:
        resp = helper.make_rest_call_helper(endpoint, nextLink=next_link)
        members.extend(resp.get("value", []))
        next_link = resp.get("@odata.nextLink")
        if not next_link:
            break

    results = []
    for member in members:
        odata_type = member.get("@odata.type", "")
        results.append(
            DistributionListMember(
                id=member.get("id"),
                displayName=member.get("displayName"),
                mail=member.get("mail") or member.get("userPrincipalName"),
                userPrincipalName=member.get("userPrincipalName"),
                mailboxType=MEMBER_TYPE_MAP.get(odata_type, odata_type.split(".")[-1]),
            )
        )

    soar.set_message(f"Successfully retrieved {len(results)} addresses")
    return results
