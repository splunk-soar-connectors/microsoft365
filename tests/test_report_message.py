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
        data=json.dumps({"moveToInbox": True}),
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
