# Copyright (c) 2017-2026 Splunk Inc.
"""Unit tests for the 'list addresses' action."""

from unittest.mock import MagicMock, patch

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.list_addresses import ListAddressesParams, list_addresses


def make_params(group="dl@x.com", recursive=False):
    return ListAddressesParams(group=group, recursive=recursive)


def run_action(params, responses):
    """Invoke the raw list_addresses handler with a mocked MsGraphHelper.

    ``list_addresses`` is the SDK-decorated action, which returns a status bool.
    ``__wrapped__`` (preserved by functools.wraps) is the underlying handler,
    which returns the output list we want to assert on.
    """
    soar = MagicMock()
    with patch("src.actions.list_addresses.MsGraphHelper") as helper_cls:
        helper = helper_cls.return_value
        helper.make_rest_call_helper.side_effect = list(responses)
        result = list_addresses.__wrapped__(params, soar, MagicMock())
    return result, helper


GROUP_RESP = {"value": [{"id": "GID", "displayName": "DL", "mail": "dl@x.com"}]}
MEMBERS_RESP = {
    "value": [
        {
            "@odata.type": "#microsoft.graph.user",
            "id": "u1",
            "displayName": "User One",
            "mail": "u1@x.com",
        },
        {
            "@odata.type": "#microsoft.graph.group",
            "id": "g1",
            "displayName": "Sub DL",
            "mail": "sub@x.com",
        },
        {
            "@odata.type": "#microsoft.graph.user",
            "id": "u2",
            "displayName": "User Two",
            "userPrincipalName": "u2@x.com",
        },
    ]
}


def test_list_addresses_returns_all_members():
    result, _ = run_action(make_params(), [GROUP_RESP, MEMBERS_RESP])
    assert len(result) == 3


def test_list_addresses_maps_mailbox_type():
    result, _ = run_action(make_params(), [GROUP_RESP, MEMBERS_RESP])
    assert result[0].mailboxType == "Mailbox"  # user
    assert result[1].mailboxType == "PublicDL"  # group


def test_list_addresses_mail_falls_back_to_upn():
    result, _ = run_action(make_params(), [GROUP_RESP, MEMBERS_RESP])
    assert result[2].mail == "u2@x.com"


def test_list_addresses_non_recursive_uses_members_endpoint():
    _, helper = run_action(make_params(recursive=False), [GROUP_RESP, MEMBERS_RESP])
    assert (
        helper.make_rest_call_helper.call_args_list[1].args[0] == "/groups/GID/members"
    )


def test_list_addresses_recursive_uses_transitive_members_endpoint():
    _, helper = run_action(make_params(recursive=True), [GROUP_RESP, MEMBERS_RESP])
    assert (
        helper.make_rest_call_helper.call_args_list[1].args[0]
        == "/groups/GID/transitiveMembers"
    )


def test_list_addresses_paginates_members():
    page1 = {
        "value": [
            {"@odata.type": "#microsoft.graph.user", "id": "u1", "mail": "u1@x.com"}
        ],
        "@odata.nextLink": "NEXT",
    }
    page2 = {
        "value": [
            {"@odata.type": "#microsoft.graph.user", "id": "u2", "mail": "u2@x.com"}
        ]
    }
    result, _ = run_action(make_params(), [GROUP_RESP, page1, page2])
    assert [r.id for r in result] == ["u1", "u2"]


def test_list_addresses_group_not_found_raises():
    with pytest.raises(ActionFailure):
        run_action(make_params(group="nope"), [{"value": []}])


def test_list_addresses_escapes_quotes_in_group_filter():
    _, helper = run_action(make_params(group="O'Brien"), [GROUP_RESP, MEMBERS_RESP])
    first_call = helper.make_rest_call_helper.call_args_list[0]
    assert "O''Brien" in first_call.kwargs["params"]["$filter"]
