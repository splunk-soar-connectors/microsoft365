# Copyright (c) 2017-2026 Splunk Inc.

import importlib
import json
from unittest.mock import Mock

import pytest

from src.actions.report_message import ReportMessageParams


report_module = importlib.import_module("src.actions.report_message")


def _run(mocker, report_action, move=False):
    helper = Mock()
    mocker.patch.object(report_module, "MsGraphHelper", return_value=helper)
    soar = Mock()
    report_module.report_message.__wrapped__(
        ReportMessageParams(
            message_id="message-id",
            user_id="analyst@example.com",
            report_action=report_action,
            is_message_move_requested=move,
        ),
        soar,
        Mock(),
    )
    return helper, soar


@pytest.mark.parametrize("action", ["junk", "notJunk", "phish"])
def test_report_message_uses_report_message_endpoint(mocker, action):
    # All report actions go through the single reportMessage endpoint (beta).
    helper, soar = _run(mocker, action, move=True)
    helper.make_rest_call_helper.assert_called_once_with(
        "/users/analyst%40example.com/messages/message-id/reportMessage",
        method="post",
        data=json.dumps({"IsMessageMoveRequested": True, "ReportAction": action}),
        beta=True,
    )
    soar.set_message.assert_called_once()


def test_report_message_move_flag_defaults_false(mocker):
    helper, _ = _run(mocker, "junk", move=False)
    sent = json.loads(helper.make_rest_call_helper.call_args.kwargs["data"])
    assert sent == {"IsMessageMoveRequested": False, "ReportAction": "junk"}


def test_report_message_percent_encodes_ids_in_path(mocker):
    # Graph message IDs contain '/', '+', '=' and must be percent-encoded so the
    # path is not split or truncated.
    helper = Mock()
    mocker.patch.object(report_module, "MsGraphHelper", return_value=helper)
    report_module.report_message.__wrapped__(
        ReportMessageParams(
            message_id="AAMk/Ba+Z=",
            user_id="analyst@example.com",
            report_action="junk",
        ),
        Mock(),
        Mock(),
    )
    endpoint = helper.make_rest_call_helper.call_args.args[0]
    assert endpoint == (
        "/users/analyst%40example.com/messages/AAMk%2FBa%2BZ%3D/reportMessage"
    )
