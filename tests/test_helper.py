# Copyright (c) 2017-2026 Splunk Inc.

import pytest
from soar_sdk.exceptions import ActionFailure

from src.helper import (
    escape_odata_string,
    quote_graph_search_phrase,
    validate_graph_next_link,
    validate_graph_page_count,
)


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


def test_escape_odata_string_keeps_value_inside_literal():
    assert escape_odata_string("report' or isRead eq false or subject eq '") == (
        "report'' or isRead eq false or subject eq ''"
    )


def test_quote_graph_search_phrase_escapes_quotes_and_backslashes():
    assert quote_graph_search_phrase('invoice\\" OR subject:"password') == (
        '"invoice\\\\\\" OR subject:\\"password"'
    )
