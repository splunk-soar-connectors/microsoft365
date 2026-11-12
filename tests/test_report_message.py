# Copyright (c) 2017-2026 Splunk Inc.

import importlib
import json
from unittest.mock import Mock

import pytest

from src.actions.report_message import ReportMessageParams


report_module = importlib.import_module("src.actions.report_message")


def test_not_junk_uses_mark_as_not_junk(mocker):
    helper = Mock()
    mocker.patch.object(report_module, "MsGraphHelper", return_value=helper)
    soar = Mock()

    report_module.report_message.__wrapped__(
        ReportMessageParams(
            message_id="message-id",
            user_id="analyst@example.com",
            report_action="notJunk",
            is_message_move_requested=True,
        ),
        soar,
        Mock(),
    )

    helper.make_rest_call_helper.assert_called_once_with(
        "/users/analyst@example.com/messages/message-id/markAsNotJunk",
        method="post",
        data=json.dumps({"MoveToInbox": True}),
    )


def test_unknown_report_action_fails_without_success(mocker):
    helper = Mock()
    mocker.patch.object(report_module, "MsGraphHelper", return_value=helper)
    soar = Mock()

    with pytest.raises(ValueError, match="Unsupported report action"):
        report_module.report_message.__wrapped__(
            ReportMessageParams(
                message_id="message-id",
                user_id="analyst@example.com",
                report_action="unknown",
            ),
            soar,
            Mock(),
        )

    helper.make_rest_call_helper.assert_not_called()
    soar.set_message.assert_not_called()


@pytest.mark.parametrize(
    ("report_action", "operation", "move_key"),
    [
        ("junk", "markAsJunk", "MoveToJunk"),
        ("notJunk", "markAsNotJunk", "MoveToInbox"),
        ("phish", "markAsJunk", "MoveToJunk"),
    ],
)
@pytest.mark.parametrize("move", [False, True])
def test_report_request_uses_existing_api_and_preserves_move_behavior(
    mocker, report_action, operation, move_key, move
):
    from types import SimpleNamespace

    mocker.patch.object(report_module.MsGraphHelper, "get_token")
    request = mocker.patch.object(
        report_module.MsGraphHelper, "_make_rest_call", return_value={}
    )
    soar = Mock()
    output = report_module.report_message.__wrapped__(
        ReportMessageParams(
            message_id="message-id",
            user_id="user-id",
            report_action=report_action,
            is_message_move_requested=move,
        ),
        soar,
        SimpleNamespace(auth_type="OAuth", retry_count=1, retry_wait_time=1),
    )
    request.assert_called_once_with(
        f"https://graph.microsoft.com/v1.0/users/user-id/messages/message-id/{operation}",
        method="post",
        params=None,
        data=json.dumps({move_key: False if report_action == "phish" else move}),
        download=False,
    )
    assert output.message == f"Successfully reported message as {report_action}"
    soar.set_message.assert_called_once_with(output.message)


def test_failed_report_does_not_claim_success_or_try_another_operation(mocker):
    from soar_sdk.exceptions import ActionFailure

    helper = Mock()
    helper.make_rest_call_helper.side_effect = ActionFailure("API Error 403: denied")
    mocker.patch.object(report_module, "MsGraphHelper", return_value=helper)
    soar = Mock()
    with pytest.raises(ActionFailure, match="403"):
        report_module.report_message.__wrapped__(
            ReportMessageParams(
                message_id="message-id", user_id="user-id", report_action="junk"
            ),
            soar,
            Mock(),
        )
    assert helper.make_rest_call_helper.call_count == 1
    soar.set_message.assert_not_called()
