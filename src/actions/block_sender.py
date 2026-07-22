# Copyright (c) 2017-2026 Splunk Inc.
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper
from ._message_rules import list_message_rules, message_rules_endpoint


class BlockSenderParams(Params):
    email_address: str = Param(
        description="User's email address (mailbox)",
        required=True,
        cef_types=["email"],
    )
    sender: str = Param(
        description="Email address of sender to block",
        required=True,
        cef_types=["email"],
    )


class BlockSenderOutput(ActionOutput):
    message: str | None = None


@app.action(
    description="Add a sender to the blocked senders list",
    action_type="contain",
    read_only=False,
)
def block_sender(
    params: BlockSenderParams, soar: SOARClient, asset: Asset
) -> BlockSenderOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = message_rules_endpoint(params.email_address)
    display_name = f"Block sender: {params.sender}"
    if any(
        rule.get("displayName") == display_name
        for rule in list_message_rules(helper, params.email_address)
    ):
        raise ValueError(f"A blocking rule already exists for sender: {params.sender}")

    body = {
        "displayName": display_name,
        "sequence": 1,
        "isEnabled": True,
        "conditions": {"fromAddresses": [{"emailAddress": {"address": params.sender}}]},
        "actions": {"delete": True, "stopProcessingRules": True},
    }

    created_rule = helper.make_rest_call_helper(
        endpoint, method="post", data=json.dumps(body)
    )
    rule_id = created_rule.get("id")
    if not rule_id or created_rule.get("displayName") != display_name:
        raise ValueError(
            "Microsoft 365 did not confirm creation of the intended blocking rule"
        )

    verified_rule = helper.make_rest_call_helper(f"{endpoint}/{rule_id}")
    if (
        verified_rule.get("id") != rule_id
        or verified_rule.get("displayName") != display_name
    ):
        raise ValueError(
            "Microsoft 365 did not return the intended blocking rule after creation"
        )

    soar.set_message(f"Successfully blocked sender: {params.sender}")
    return BlockSenderOutput(message=f"Successfully blocked sender: {params.sender}")
