# Copyright (c) 2017-2026 Splunk Inc.

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from soar_sdk.exceptions import ActionFailure

from src.helper import (
    GraphPaginationState,
    MsGraphHelper,
    encode_path_segment,
    escape_odata_string,
    quote_graph_search_phrase,
    validate_graph_next_link,
    validate_graph_page_count,
)


def _helper(mocker):
    asset = SimpleNamespace(auth_type="OAuth", retry_count=3, retry_wait_time=1)
    helper = MsGraphHelper(Mock(), asset)
    mocker.patch.object(helper, "_make_rest_call", return_value={})
    return helper


def test_validate_graph_next_link_accepts_graph_pagination_url():
    next_link = "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"

    assert validate_graph_next_link(next_link) == next_link


@pytest.mark.parametrize(
    "next_link",
    [
        "https://attacker.example/v1.0/users?$skiptoken=abc",
        "https://graph.microsoft.com@attacker.example/v1.0/users",
        "http://graph.microsoft.com/v1.0/users",
        "https://graph.microsoft.com/v1.0/users#fragment",
    ],
)
def test_validate_graph_next_link_rejects_untrusted_url(next_link):
    with pytest.raises(ActionFailure, match="untrusted pagination URL"):
        validate_graph_next_link(next_link)


def test_validate_graph_page_count_rejects_page_after_safety_limit():
    validate_graph_page_count(1000)

    with pytest.raises(ActionFailure, match="1000-page safety limit"):
        validate_graph_page_count(1001)


def test_pagination_state_survives_interleaved_ordinary_requests(mocker):
    helper = _helper(mocker)
    next_link = "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"
    pagination_state = GraphPaginationState()

    helper.make_rest_call_helper("/users", pagination_state=pagination_state)
    helper.make_rest_call_helper("/users/123/messages/456/$value", download=True)
    helper.make_rest_call_helper(
        "/users", nextLink=next_link, pagination_state=pagination_state
    )
    helper.make_rest_call_helper("/users/123/messages/456/attachments")

    with pytest.raises(ActionFailure, match="repeated pagination URL"):
        helper.make_rest_call_helper(
            "/users", nextLink=next_link, pagination_state=pagination_state
        )


def test_pagination_page_limit_survives_interleaved_ordinary_request(mocker):
    helper = _helper(mocker)
    pagination_state = GraphPaginationState(page_count=1000)

    helper.make_rest_call_helper("/users/123/messages/456/attachments")

    with pytest.raises(ActionFailure, match="1000-page safety limit"):
        helper.make_rest_call_helper(
            "/users",
            nextLink="https://graph.microsoft.com/v1.0/users?$skiptoken=last",
            pagination_state=pagination_state,
        )


def test_escape_odata_string_keeps_value_inside_literal():
    assert escape_odata_string("report' or isRead eq false or subject eq '") == (
        "report'' or isRead eq false or subject eq ''"
    )


def test_quote_graph_search_phrase_escapes_quotes_and_backslashes():
    assert quote_graph_search_phrase('invoice\\" OR subject:"password') == (
        '"invoice\\\\\\" OR subject:\\"password"'
    )


def test_encode_path_segment_escapes_graph_id_special_characters():
    assert encode_path_segment("AAMk/AGI2+THk=") == "AAMk%2FAGI2%2BTHk%3D"


def test_get_folder_id_encodes_parent_folder_id_in_child_lookup(mocker):
    helper = _helper(mocker)
    mocker.patch.object(
        helper,
        "make_rest_call_helper",
        side_effect=[
            {"value": [{"id": "parent/id+="}]},
            {"value": [{"id": "child-id"}]},
        ],
    )

    result = helper.get_folder_id("Inbox/Sub", "user@example.com")

    assert result == "child-id"
    second_call_endpoint = helper.make_rest_call_helper.call_args_list[1].args[0]
    assert second_call_endpoint == (
        "/users/user@example.com/mailFolders/parent%2Fid%2B%3D/childFolders"
    )
