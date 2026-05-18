# Copyright (c) 2017-2026 Splunk Inc.
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class DisableRuleParams(Params):
    user_id: str = Param(
        description="User ID/Principal name",
        required=True,
        primary=True,
        cef_types=["msgoffice365 user id", "msgoffice365 user principal name", "email"],
    )
    rule_id: str = Param(
        description="Inbox rule ID",
        required=True,
        primary=True,
        cef_types=["msgoffice365 rule id"],
    )


class DisableRuleOutput(ActionOutput):
    pass


@app.action(description="Disable inbox rule by ID", action_type="contain")
def disable_rule(
    params: DisableRuleParams, soar: SOARClient, asset: Asset
) -> DisableRuleOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = (
        f"/users/{params.user_id}/mailFolders/inbox/messageRules/{params.rule_id}"
    )
    helper.make_rest_call_helper(
        endpoint, method="patch", data=json.dumps({"isEnabled": False})
    )

    soar.set_message(f"Successfully disabled rule: {params.rule_id}")
    return DisableRuleOutput()
