# Copyright (c) 2017-2026 Splunk Inc.

import importlib
import json
from unittest.mock import Mock

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.update_email import UpdateEmailParams


update_module = importlib.import_module("src.actions.update_email")


@pytest.mark.parametrize(
    ("categories", "expected"),
    [
        (["QA", "Second"], '["QA", "Second"]'),
        ([], "[]"),
        ("QA", "QA"),
        ('["QA"]', '["QA"]'),
        ("", ""),
        (None, None),
    ],
)
def test_update_accepts_category_arrays_and_preserves_strings(
    mocker, categories, expected
):
    helper = Mock()
    helper.make_rest_call_helper.return_value = {
        "id": "message-id",
        "isRead": False,
        "categories": categories,
    }
    mocker.patch.object(update_module, "MsGraphHelper", return_value=helper)

    output = update_module.update_email.__wrapped__(
        UpdateEmailParams(
            id="message-id", email_address="analyst@example.com", is_read=False
        ),
        Mock(),
        Mock(),
    )

    assert output.categories == expected
    assert output.id == "message-id"
    assert output.isRead is False
    helper.make_rest_call_helper.assert_called_once_with(
        "/users/analyst@example.com/messages/message-id",
        method="patch",
        data=json.dumps({"isRead": False}),
    )


def test_update_missing_categories_preserves_optional_output(mocker):
    helper = Mock()
    helper.make_rest_call_helper.return_value = {"id": "message-id", "isRead": True}
    mocker.patch.object(update_module, "MsGraphHelper", return_value=helper)
    output = update_module.update_email.__wrapped__(
        UpdateEmailParams(
            id="message-id",
            email_address="analyst@example.com",
            category="QA",
            is_read=True,
        ),
        Mock(),
        Mock(),
    )
    assert output.categories is None
    helper.make_rest_call_helper.assert_called_once_with(
        "/users/analyst@example.com/messages/message-id",
        method="patch",
        data=json.dumps({"categories": ["QA"], "isRead": True}),
    )


def test_update_api_error_is_not_reported_as_success(mocker):
    helper = Mock()
    helper.make_rest_call_helper.side_effect = ActionFailure("API Error 403: denied")
    mocker.patch.object(update_module, "MsGraphHelper", return_value=helper)
    soar = Mock()
    with pytest.raises(ActionFailure, match="403"):
        update_module.update_email.__wrapped__(
            UpdateEmailParams(
                id="message-id", email_address="analyst@example.com", is_read=True
            ),
            soar,
            Mock(),
        )
    helper.make_rest_call_helper.assert_called_once()
    soar.set_message.assert_not_called()


def test_update_without_changes_does_not_patch(mocker):
    helper = Mock()
    mocker.patch.object(update_module, "MsGraphHelper", return_value=helper)
    soar = Mock()
    with pytest.raises(ValueError, match="At least one update parameter"):
        update_module.update_email.__wrapped__(
            UpdateEmailParams(id="message-id", email_address="analyst@example.com"),
            soar,
            Mock(),
        )
    helper.make_rest_call_helper.assert_not_called()
    soar.set_message.assert_not_called()
