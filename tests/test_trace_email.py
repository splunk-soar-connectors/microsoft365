# Copyright (c) 2017-2026 Splunk Inc.
"""Unit tests for the 'trace email' action."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.trace_email import (
    MSGOFFICE365_MESSAGE_TRACE_ENDPOINT,
    TraceEmailParams,
    _build_filter,
    _escape,
    _or_clause,
    _validate_range,
    trace_email,
)
from src.helper import GraphPaginationState


def make_params(**overrides):
    """Build a real TraceEmailParams instance (all fields have defaults)."""
    return TraceEmailParams(**overrides)


def _iso(days_ago: int) -> str:
    """ISO-8601 UTC timestamp `days_ago` days before now (keeps tests from rotting)."""
    return (datetime.now(UTC) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_action(params, responses):
    """Invoke the raw trace_email handler with a mocked MsGraphHelper.

    ``trace_email`` is the SDK-decorated action, which returns a status bool and
    pushes outputs into the actions manager. ``__wrapped__`` (preserved by
    functools.wraps) is the underlying handler, which returns the output list we
    want to assert on.
    """
    soar = MagicMock()
    with patch("src.actions.trace_email.MsGraphHelper") as helper_cls:
        helper = helper_cls.return_value
        helper.make_rest_call_helper.side_effect = list(responses)
        result = trace_email.__wrapped__(params, soar, MagicMock())
    return result, helper


# --------------------------------------------------------------------------- #
# _escape
# --------------------------------------------------------------------------- #
def test_escape_doubles_single_quotes():
    assert _escape("o'brien") == "o''brien"
    assert _escape("plain") == "plain"


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
    assert f"receivedDateTime ge {start} and receivedDateTime le {end}" in f


def test_build_filter_excludes_from_ip():
    # from_ip is not server-side filterable in Graph.
    assert "fromIP" not in _build_filter(make_params(from_ip="8.8.8.8"))


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
    with pytest.raises(ActionFailure):
        _build_filter(make_params(start_date=_iso(2), end_date=_iso(5)))


def test_build_filter_rejects_window_over_10_days():
    with pytest.raises(ActionFailure):
        _build_filter(make_params(start_date=_iso(20), end_date=_iso(2)))


def test_build_filter_rejects_start_older_than_90_days():
    with pytest.raises(ActionFailure):
        _build_filter(make_params(start_date=_iso(100), end_date=_iso(95)))


def test_build_filter_rejects_invalid_to_ip():
    with pytest.raises(ActionFailure):
        _build_filter(make_params(to_ip="not-an-ip"))


# --------------------------------------------------------------------------- #
# trace_email handler
# --------------------------------------------------------------------------- #
def test_trace_email_uses_beta_message_trace_endpoint():
    _, helper = run_action(make_params(), [{"value": []}])
    call = helper.make_rest_call_helper.call_args
    assert call.kwargs["beta"] is True
    assert call.args[0] == MSGOFFICE365_MESSAGE_TRACE_ENDPOINT


def test_trace_email_paginates_and_filters_from_ip():
    page1 = {
        "value": [
            {"id": "1", "messageId": "<m1>", "fromIP": "8.8.8.8"},
            {"id": "2", "messageId": "<m2>", "fromIP": "9.9.9.9"},
        ],
        "@odata.nextLink": "NEXT",
    }
    page2 = {"value": [{"id": "3", "messageId": "<m3>", "fromIP": "8.8.8.8"}]}
    result, helper = run_action(make_params(from_ip="8.8.8.8"), [page1, page2])
    assert [r.id for r in result] == ["1", "3"]
    # Every paginated call must pass a GraphPaginationState (the helper contract).
    for call in helper.make_rest_call_helper.call_args_list:
        assert isinstance(call.kwargs.get("pagination_state"), GraphPaginationState)


def test_trace_email_rejects_invalid_from_ip():
    with pytest.raises(ActionFailure):
        run_action(make_params(from_ip="not-an-ip"), [{"value": []}])


def test_trace_email_sets_emails_found_summary():
    resp = {"value": [{"id": "1"}, {"id": "2"}]}
    soar = MagicMock()
    with patch("src.actions.trace_email.MsGraphHelper") as helper_cls:
        helper_cls.return_value.make_rest_call_helper.side_effect = [resp]
        trace_email.__wrapped__(make_params(), soar, MagicMock())
    assert soar.set_summary.call_args.args[0].emails_found == 2


def test_trace_email_widget_filter_strips_brackets():
    resp = {"value": [{"id": "1", "messageId": "<m1>"}]}
    result, _ = run_action(make_params(widget_filter=True), [resp])
    assert result[0].messageId == "m1"


def test_trace_email_range_slices_results():
    resp = {"value": [{"id": str(i)} for i in range(5)]}
    result, _ = run_action(make_params(range="1-2"), [resp])
    assert [r.id for r in result] == ["1", "2"]


def test_trace_email_maps_output_fields():
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
    result, _ = run_action(make_params(), [resp])
    row = result[0]
    assert row.senderAddress == "s@x.com"
    assert row.size == 1234
    assert row.status == "delivered"
