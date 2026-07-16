# Copyright (c) 2017-2026 Splunk Inc.

import importlib
from unittest.mock import Mock

import pytest

from src.actions.block_sender import BlockSenderParams
from src.actions.unblock_sender import UnblockSenderParams


block_module = importlib.import_module("src.actions.block_sender")
unblock_module = importlib.import_module("src.actions.unblock_sender")


def test_block_sender_uses_inbox_and_exact_address_condition(mocker):
    helper = Mock()
    helper.make_rest_call_helper.side_effect = [
        {"value": []},
        {"id": "rule-id", "displayName": "Block sender: sender@example.com"},
        {"id": "rule-id", "displayName": "Block sender: sender@example.com"},
    ]
    mocker.patch.object(block_module, "MsGraphHelper", return_value=helper)

    block_module.block_sender.__wrapped__(
        BlockSenderParams(
            email_address="mailbox@example.com", sender="sender@example.com"
        ),
        Mock(),
        Mock(),
    )

    endpoint, kwargs = helper.make_rest_call_helper.call_args_list[1]
    assert endpoint[0] == "/users/mailbox@example.com/mailFolders/inbox/messageRules"
    assert (
        '"fromAddresses": [{"emailAddress": {"address": "sender@example.com"}}]'
        in kwargs["data"]
    )


def test_unblock_sender_rejects_ambiguous_exact_matches(mocker):
    helper = Mock()
    helper.make_rest_call_helper.return_value = {
        "value": [
            {"id": "one", "displayName": "Block sender: sender@example.com"},
            {"id": "two", "displayName": "Block sender: sender@example.com"},
        ]
    }
    mocker.patch.object(unblock_module, "MsGraphHelper", return_value=helper)

    with pytest.raises(ValueError, match="Multiple blocking rules"):
        unblock_module.unblock_sender.__wrapped__(
            UnblockSenderParams(
                email_address="mailbox@example.com", sender="sender@example.com"
            ),
            Mock(),
            Mock(),
        )


def test_unblock_sender_verifies_deleted_rule_is_absent(mocker):
    helper = Mock()
    helper.make_rest_call_helper.side_effect = [
        {
            "value": [
                {"id": "rule-id", "displayName": "Block sender: sender@example.com"}
            ]
        },
        {},
        {"value": []},
    ]
    mocker.patch.object(unblock_module, "MsGraphHelper", return_value=helper)

    unblock_module.unblock_sender.__wrapped__(
        UnblockSenderParams(
            email_address="mailbox@example.com", sender="sender@example.com"
        ),
        Mock(),
        Mock(),
    )

    helper.make_rest_call_helper.assert_any_call(
        "/users/mailbox@example.com/mailFolders/inbox/messageRules/rule-id",
        method="delete",
    )
