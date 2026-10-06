# Copyright (c) 2017-2026 Splunk Inc.
"""Unit tests for the 'list addresses' action."""

import importlib
from unittest.mock import Mock

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.list_addresses import ListAddressesParams, list_addresses
from src.helper import GraphPaginationState


list_addresses_module = importlib.import_module("src.actions.list_addresses")


def make_params(group="dl@x.com", recursive=False):
    return ListAddressesParams(group=group, recursive=recursive)


def run_action(mocker, params, responses):
    """Invoke the raw list_addresses handler with a mocked MsGraphHelper.

    ``list_addresses`` is the SDK-decorated action; ``__wrapped__`` (preserved by
    functools.wraps) is the underlying handler, which returns the output list.
    """
    helper = Mock()
    helper.make_rest_call_helper.side_effect = list(responses)
    mocker.patch.object(list_addresses_module, "MsGraphHelper", return_value=helper)
    result = list_addresses.__wrapped__(params, Mock(), Mock())
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


def test_list_addresses_returns_mail_capable_members(mocker):
    # u1 and g1 have mail; u2 has only a UPN and is skipped.
    result, _ = run_action(mocker, make_params(), [GROUP_RESP, MEMBERS_RESP])
    assert [r.id for r in result] == ["u1", "g1"]


def test_list_addresses_maps_mailbox_type(mocker):
    result, _ = run_action(mocker, make_params(), [GROUP_RESP, MEMBERS_RESP])
    assert result[0].mailboxType == "Mailbox"  # user
    assert result[1].mailboxType == "PublicDL"  # group


def test_list_addresses_maps_contact_type(mocker):
    members = {
        "value": [
            {
                "@odata.type": "#microsoft.graph.orgContact",
                "id": "c1",
                "displayName": "Contact One",
                "mail": "c1@x.com",
            }
        ]
    }
    result, _ = run_action(mocker, make_params(), [GROUP_RESP, members])
    assert result[0].mailboxType == "Contact"
    assert result[0].mail == "c1@x.com"


def test_list_addresses_skips_members_without_mail(mocker):
    # A member with no mail is dropped, and its UPN is never reported as mail.
    result, _ = run_action(mocker, make_params(), [GROUP_RESP, MEMBERS_RESP])
    assert all(r.id != "u2" for r in result)
    assert all(r.mail for r in result)


def test_list_addresses_resolution_requires_mail_enabled(mocker):
    _, helper = run_action(mocker, make_params(), [GROUP_RESP, MEMBERS_RESP])
    group_filter = helper.make_rest_call_helper.call_args_list[0].kwargs["params"][
        "$filter"
    ]
    assert "mailEnabled eq true" in group_filter


def test_list_addresses_non_recursive_uses_members_endpoint(mocker):
    _, helper = run_action(
        mocker, make_params(recursive=False), [GROUP_RESP, MEMBERS_RESP]
    )
    assert (
        helper.make_rest_call_helper.call_args_list[1].args[0] == "/groups/GID/members"
    )


def test_list_addresses_recursive_uses_transitive_members_endpoint(mocker):
    _, helper = run_action(
        mocker, make_params(recursive=True), [GROUP_RESP, MEMBERS_RESP]
    )
    assert (
        helper.make_rest_call_helper.call_args_list[1].args[0]
        == "/groups/GID/transitiveMembers"
    )


def test_list_addresses_paginates_members(mocker):
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
    result, helper = run_action(mocker, make_params(), [GROUP_RESP, page1, page2])
    assert [r.id for r in result] == ["u1", "u2"]
    # The member-listing calls (after the group-resolution call) must pass a
    # GraphPaginationState, per the helper contract.
    member_calls = helper.make_rest_call_helper.call_args_list[1:]
    assert member_calls
    for call in member_calls:
        assert isinstance(call.kwargs.get("pagination_state"), GraphPaginationState)


def test_list_addresses_group_not_found_raises(mocker):
    with pytest.raises(ActionFailure):
        run_action(mocker, make_params(group="nope"), [{"value": []}])


def test_list_addresses_escapes_quotes_in_group_filter(mocker):
    _, helper = run_action(
        mocker, make_params(group="O'Brien"), [GROUP_RESP, MEMBERS_RESP]
    )
    first_call = helper.make_rest_call_helper.call_args_list[0]
    assert "O''Brien" in first_call.kwargs["params"]["$filter"]


def test_list_addresses_excludes_non_recipient_types(mocker):
    # Devices/service principals are not mail recipients and must be dropped.
    members = {
        "value": [
            {"@odata.type": "#microsoft.graph.user", "id": "u1", "mail": "u1@x.com"},
            {
                "@odata.type": "#microsoft.graph.device",
                "id": "d1",
                "displayName": "Laptop",
            },
            {
                "@odata.type": "#microsoft.graph.servicePrincipal",
                "id": "sp1",
                "displayName": "App",
            },
        ]
    }
    result, _ = run_action(mocker, make_params(), [GROUP_RESP, members])
    assert [r.id for r in result] == ["u1"]


AMBIGUOUS_RESP = {
    "value": [
        {
            "id": "GID1",
            "displayName": "Team",
            "mail": "team-a@x.com",
            "mailNickname": "team-a",
        },
        {
            "id": "GID2",
            "displayName": "Team",
            "mail": "team-b@x.com",
            "mailNickname": "team-b",
        },
    ]
}


def test_list_addresses_ambiguous_display_name_raises(mocker):
    # Multiple groups match a shared display name with no exact alias -> error.
    with pytest.raises(ActionFailure):
        run_action(mocker, make_params(group="Team"), [AMBIGUOUS_RESP])


def test_list_addresses_ambiguous_resolves_by_exact_alias(mocker):
    # An exact mail/alias input resolves deterministically among matches.
    _, helper = run_action(
        mocker, make_params(group="team-b@x.com"), [AMBIGUOUS_RESP, MEMBERS_RESP]
    )
    assert (
        helper.make_rest_call_helper.call_args_list[1].args[0] == "/groups/GID2/members"
    )
