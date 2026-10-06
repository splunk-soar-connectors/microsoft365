# Copyright (c) 2017-2026 Splunk Inc.
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import MsGraphHelper, encode_path_segment


class ReportMessageParams(Params):
    message_id: str = Param(
        description="The ID of the message to report",
        required=True,
        cef_types=["msgoffice365 message id"],
    )
    user_id: str = Param(
        description="The user ID or principal name of the mailbox that holds the message",
        required=True,
        cef_types=["msgoffice365 user id", "msgoffice365 user principal name", "email"],
    )
    is_message_move_requested: bool = Param(
        description="Indicates whether the message should be moved out of current folder",
        required=False,
        default=False,
    )
    report_action: str = Param(
        description="The type of report to submit for the message",
        required=True,
        value_list=["junk", "notJunk", "phish"],
    )


class ReportMessageOutput(ActionOutput):
    message: str | None = None


@app.action(
    description="Report a message as junk, not junk, or phishing to improve mail filtering",
    action_type="contain",
    read_only=False,
)
def report_message(
    params: ReportMessageParams, soar: SOARClient, asset: Asset
) -> ReportMessageOutput:
    helper = MsGraphHelper(soar, asset)
    helper.get_token()

    # reportMessage (beta-only) replaces the deprecated markAsJunk/markAsNotJunk endpoints.
    endpoint = (
        f"/users/{encode_path_segment(params.user_id)}"
        f"/messages/{encode_path_segment(params.message_id)}/reportMessage"
    )
    body = {
        "IsMessageMoveRequested": params.is_message_move_requested,
        "ReportAction": params.report_action,
    }

    helper.make_rest_call_helper(
        endpoint, method="post", data=json.dumps(body), beta=True
    )
    soar.set_message(f"Successfully reported message as {params.report_action}")
    return ReportMessageOutput(
        message=f"Successfully reported message as {params.report_action}"
    )
