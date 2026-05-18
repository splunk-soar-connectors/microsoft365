# Copyright (c) 2017-2026 Splunk Inc.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper


class DeleteRuleParams(Params):
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


class DeleteRuleOutput(ActionOutput):
    pass


@app.action(description="Delete inbox rule by ID", action_type="contain")
def delete_rule(
    params: DeleteRuleParams, soar: SOARClient, asset: Asset
) -> DeleteRuleOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    endpoint = (
        f"/users/{params.user_id}/mailFolders/inbox/messageRules/{params.rule_id}"
    )
    helper.make_rest_call_helper(endpoint, method="delete")

    soar.set_message(f"Successfully deleted rule: {params.rule_id}")
    return DeleteRuleOutput()
