# Copyright (c) 2017-2026 Splunk Inc.
"""Unit tests for the 'trace email' action."""

import importlib
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.trace_email import (
    MSGOFFICE365_MESSAGE_TRACE_ENDPOINT,
    TraceEmailParams,
    _build_filter,
    _or_clause,
    _validate_range,
    trace_email,
)
from src.helper import GraphPaginationState


trace_module = importlib.import_module("src.actions.trace_email")


def make_params(**overrides):
    """Build a real TraceEmailParams instance (all fields have defaults)."""
    return TraceEmailParams(**overrides)


def _iso(days_ago: int) -> str:
    """ISO-8601 UTC timestamp `days_ago` days before now (keeps tests from rotting)."""
    return (datetime.now(UTC) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_action(mocker, params, responses):
    """Invoke the raw trace_email handler with a mocked MsGraphHelper.

    ``trace_email`` is the SDK-decorated action; ``__wrapped__`` (preserved by
    functools.wraps) is the underlying handler, which returns the output list.
    """
    helper = Mock()
    helper.make_rest_call_helper.side_effect = list(responses)
    mocker.patch.object(trace_module, "MsGraphHelper", return_value=helper)
    result = trace_email.__wrapped__(params, Mock(), Mock())
    return result, helper


# --------------------------------------------------------------------------- #
# _or_clause
# --------------------------------------------------------------------------- #
def test_or_clause_single_value():
    assert _or_clause("senderAddress", "a@x.com") == "senderAddress eq 'a@x.com'"


def test_or_clause_multiple_values():
    assert (
        _or_clause("senderAddress", "a@x.com, b@x.com")
        == "(senderAddress eq 'a@x.com' or senderAddress eq 'b@x.com')"
    )


@pytest.mark.parametrize("value", ["", "   ", " , "])
def test_or_clause_empty_returns_none(value):
    assert _or_clause("senderAddress", value) is None


def test_or_clause_escapes_quotes():
    assert _or_clause("senderAddress", "o'x") == "senderAddress eq 'o''x'"


# --------------------------------------------------------------------------- #
# _validate_range
# --------------------------------------------------------------------------- #
def test_validate_range_ok():
    assert _validate_range("0-10") == (0, 10)


@pytest.mark.parametrize("value", ["abc", "10-5", "1", "-1-5"])
def test_validate_range_invalid(value):
    with pytest.raises(ActionFailure):
        _validate_range(value)


# --------------------------------------------------------------------------- #
# _build_filter
# --------------------------------------------------------------------------- #
def test_build_filter_combines_conditions():
    start, end = _iso(5), _iso(2)
    f = _build_filter(
        make_params(
            sender_address="a@x.com",
            recipient_address="b@y.com",
            status="delivered",
            start_date=start,
            end_date=end,
        )
    )
    assert "senderAddress eq 'a@x.com'" in f
    assert "recipientAddress eq 'b@y.com'" in f
    assert "status eq 'delivered'" in f
    assert "receivedDateTime ge " in f
    assert "receivedDateTime le " in f


def test_build_filter_includes_from_ip():
    # from_ip is server-side filterable in Graph (fromIP supports $filter eq).
    assert "fromIP eq '8.8.8.8'" in _build_filter(make_params(from_ip="8.8.8.8"))


def test_build_filter_rejects_invalid_from_ip():
    with pytest.raises(ActionFailure):
        _build_filter(make_params(from_ip="not-an-ip"))


def test_build_filter_single_field_clauses():
    assert _build_filter(make_params(message_trace_id="gid")) == "id eq 'gid'"
    assert _build_filter(make_params(internet_message_id="<a>")) == "messageId eq '<a>'"
    assert _build_filter(make_params(to_ip="1.2.3.4")) == "toIP eq '1.2.3.4'"


def test_build_filter_requires_both_dates():
    with pytest.raises(ActionFailure):
        _build_filter(make_params(start_date=_iso(3)))
    with pytest.raises(ActionFailure):
        _build_filter(make_params(end_date=_iso(3)))


def test_build_filter_rejects_bad_date_format():
    with pytest.raises(ActionFailure):
        _build_filter(make_params(start_date="2026-01-01", end_date="2026-01-02"))


def test_build_filter_rejects_end_before_start():
    with pytest.raises(ActionFailure, match="earlier than"):
        _build_filter(make_params(start_date=_iso(2), end_date=_iso(5)))


def test_build_filter_rejects_window_over_10_days():
    with pytest.raises(ActionFailure, match="10 days"):
        _build_filter(make_params(start_date=_iso(20), end_date=_iso(2)))


def test_build_filter_rejects_start_older_than_90_days():
    with pytest.raises(ActionFailure, match="90 days"):
        _build_filter(make_params(start_date=_iso(100), end_date=_iso(95)))


def test_build_filter_rejects_future_end_date():
    future = (datetime.now(UTC) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(ActionFailure, match="future"):
        _build_filter(make_params(start_date=_iso(1), end_date=future))


def test_build_filter_rejects_invalid_to_ip():
    with pytest.raises(ActionFailure):
        _build_filter(make_params(to_ip="not-an-ip"))


def test_build_filter_canonicalizes_status_casing():
    # Any input casing normalizes to the Graph enum's canonical spelling.
    assert "status eq 'delivered'" in _build_filter(make_params(status="Delivered"))
    assert "status eq 'delivered'" in _build_filter(make_params(status="DELIVERED"))
    assert "status eq 'filteredAsSpam'" in _build_filter(
        make_params(status="filteredasspam")
    )


def test_build_filter_accepts_multiple_statuses():
    f = _build_filter(make_params(status="delivered, failed"))
    assert "status eq 'delivered'" in f
    assert "status eq 'failed'" in f


def test_build_filter_rejects_invalid_status():
    with pytest.raises(ActionFailure, match="Valid values are"):
        _build_filter(make_params(status="bogus"))


def test_build_filter_rejects_mixed_valid_and_invalid_status():
    with pytest.raises(ActionFailure, match="bogus"):
        _build_filter(make_params(status="delivered, bogus"))


# --------------------------------------------------------------------------- #
# trace_email handler
# --------------------------------------------------------------------------- #
def test_trace_email_uses_v1_message_trace_endpoint(mocker):
    _, helper = run_action(mocker, make_params(), [{"value": []}])
    call = helper.make_rest_call_helper.call_args
    # The message trace API now lives under the Graph v1.0 endpoint (no beta flag).
    assert not call.kwargs.get("beta")
    assert call.args[0] == MSGOFFICE365_MESSAGE_TRACE_ENDPOINT


def test_trace_email_pushes_from_ip_into_server_side_filter(mocker):
    resp = {"value": [{"id": "1", "fromIP": "8.8.8.8"}]}
    _, helper = run_action(mocker, make_params(from_ip="8.8.8.8"), [resp])
    first_call = helper.make_rest_call_helper.call_args_list[0]
    assert "fromIP eq '8.8.8.8'" in first_call.kwargs["params"]["$filter"]


def test_trace_email_paginates_across_pages(mocker):
    page1 = {
        "value": [
            {"id": "1", "messageId": "<m1>"},
            {"id": "2", "messageId": "<m2>"},
        ],
        "@odata.nextLink": "NEXT",
    }
    page2 = {"value": [{"id": "3", "messageId": "<m3>"}]}
    result, helper = run_action(mocker, make_params(), [page1, page2])
    assert [r.id for r in result] == ["1", "2", "3"]
    # Every paginated call must pass a GraphPaginationState (the helper contract).
    for call in helper.make_rest_call_helper.call_args_list:
        assert isinstance(call.kwargs.get("pagination_state"), GraphPaginationState)


def test_trace_email_rejects_invalid_from_ip(mocker):
    with pytest.raises(ActionFailure):
        run_action(mocker, make_params(from_ip="not-an-ip"), [{"value": []}])


def test_trace_email_sets_emails_found_summary(mocker):
    resp = {"value": [{"id": "1"}, {"id": "2"}]}
    helper = Mock()
    helper.make_rest_call_helper.side_effect = [resp]
    mocker.patch.object(trace_module, "MsGraphHelper", return_value=helper)
    soar = Mock()
    trace_email.__wrapped__(make_params(), soar, Mock())
    assert soar.set_summary.call_args.args[0].emails_found == 2


def test_trace_email_widget_filter_strips_brackets(mocker):
    resp = {"value": [{"id": "1", "messageId": "<m1>"}]}
    result, _ = run_action(mocker, make_params(widget_filter=True), [resp])
    assert result[0].messageId == "m1"


def test_trace_email_range_slices_results(mocker):
    resp = {"value": [{"id": str(i)} for i in range(5)]}
    result, _ = run_action(mocker, make_params(range="1-2"), [resp])
    assert [r.id for r in result] == ["1", "2"]


def test_trace_email_range_stops_pagination_early(mocker):
    # Once enough rows for maxi are collected, no further page is fetched.
    page1 = {
        "value": [{"id": "0"}, {"id": "1"}, {"id": "2"}],
        "@odata.nextLink": "NEXT",
    }
    page2 = {"value": [{"id": "3"}]}  # must not be requested
    result, helper = run_action(mocker, make_params(range="1-2"), [page1, page2])
    assert [r.id for r in result] == ["1", "2"]
    assert helper.make_rest_call_helper.call_count == 1


def test_trace_email_range_slices_across_pages(mocker):
    page1 = {"value": [{"id": "0"}, {"id": "1"}], "@odata.nextLink": "NEXT"}
    page2 = {"value": [{"id": "2"}, {"id": "3"}]}
    result, _ = run_action(mocker, make_params(range="1-3"), [page1, page2])
    assert [r.id for r in result] == ["1", "2", "3"]


def test_trace_email_maps_output_fields(mocker):
    resp = {
        "value": [
            {
                "id": "abc",
                "senderAddress": "s@x.com",
                "recipientAddress": "r@x.com",
                "messageId": "<mid>",
                "receivedDateTime": "2026-01-01T00:00:00Z",
                "subject": "hello",
                "size": 1234,
                "fromIP": "8.8.8.8",
                "toIP": "9.9.9.9",
                "status": "delivered",
            }
        ]
    }
    result, _ = run_action(mocker, make_params(), [resp])
    row = result[0]
    assert row.id == "abc"
    assert row.senderAddress == "s@x.com"
    assert row.recipientAddress == "r@x.com"
    assert row.messageId == "<mid>"
    assert row.size == 1234
    assert row.fromIP == "8.8.8.8"
    assert row.toIP == "9.9.9.9"
    assert row.status == "delivered"
