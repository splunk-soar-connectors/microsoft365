# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper
from ._message_rules import list_message_rules, message_rules_endpoint


class UnblockSenderParams(Params):
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        cef_types=["email"],
    )
    sender: str = Param(
        description="Email address of sender to unblock",
        required=True,
        cef_types=["email"],
    )


class UnblockSenderOutput(ActionOutput):
    message: str | None = None


@app.action(
    description="Remove a sender from the blocked senders list",
    action_type="correct",
    read_only=False,
)
def unblock_sender(
    params: UnblockSenderParams, soar: SOARClient, asset: Asset
) -> UnblockSenderOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = message_rules_endpoint(params.email_address)
    display_name = f"Block sender: {params.sender}"
    matching_rules = [
        rule
        for rule in list_message_rules(helper, params.email_address)
        if rule.get("displayName") == display_name
    ]
    if not matching_rules:
        raise ValueError(f"No blocking rule found for sender: {params.sender}")
    if len(matching_rules) > 1:
        raise ValueError(f"Multiple blocking rules found for sender: {params.sender}")

    rule_id = matching_rules[0].get("id")
    if not rule_id:
        raise ValueError("The matching blocking rule is missing its ID")

    delete_endpoint = f"{endpoint}/{rule_id}"
    helper.make_rest_call_helper(delete_endpoint, method="delete")

    remaining_rules = list_message_rules(helper, params.email_address)
    if any(rule.get("id") == rule_id for rule in remaining_rules):
        raise ValueError(
            "Microsoft 365 still returned the blocking rule after deletion"
        )

    soar.set_message(f"Successfully unblocked sender: {params.sender}")
    return UnblockSenderOutput(
        message=f"Successfully unblocked sender: {params.sender}"
    )
