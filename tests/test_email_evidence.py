# Copyright (c) 2017-2026 Splunk Inc.

from types import SimpleNamespace

from src import app as app_module


def test_extract_inner_email_falls_back_after_parse_failure(mocker):
    mocker.patch.object(
        app_module,
        "extract_email_data",
        side_effect=ValueError("corrupt attached email"),
    )
    outer = SimpleNamespace(
        attachments=[SimpleNamespace(filename="reported.msg", content=b"broken")]
    )

    assert app_module._extract_inner_email(outer, "message-id") is None


def test_merge_email_urls_preserves_inner_and_outer_evidence():
    assert app_module._merge_email_urls(
        ["https://inner.example", "https://shared.example"],
        ["https://outer.example", "https://shared.example"],
    ) == [
        "https://inner.example",
        "https://shared.example",
        "https://outer.example",
    ]


def test_embedded_email_attachment_detection_is_case_insensitive():
    assert app_module._is_embedded_email_attachment("report.EML")
    assert app_module._is_embedded_email_attachment("report.msg")
    assert not app_module._is_embedded_email_attachment("payload.zip")


def test_trusted_reporter_requires_exact_configured_address():
    configured = "analyst@example.com, Reporter@Example.org"

    assert app_module._is_trusted_reporter("ANALYST@example.com", configured)
    assert app_module._is_trusted_reporter("reporter@example.org", configured)
    assert not app_module._is_trusted_reporter("attacker@example.com", configured)
    assert not app_module._is_trusted_reporter(None, configured)
    assert not app_module._is_trusted_reporter("analyst@example.com", "")
