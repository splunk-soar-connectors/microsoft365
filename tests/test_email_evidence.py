# Copyright (c) 2017-2026 Splunk Inc.

from types import SimpleNamespace

import pytest

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


def test_jmr_unwrap_setting_is_exposed_in_es_asset_settings():
    configuration = app_module.Asset.to_json_schema()

    assert configuration["unwrap_jmr_reported_message"]["category"] == "connectivity"


def _jmr_original(
    inner_message_id="<original-message@example.com>",
    network_message_id="original-network-id",
    inner_body="Original body",
    sender="Original Sender <sender@example.com>",
):
    inner_identifiers = []
    if inner_message_id:
        inner_identifiers.append(f"Message-ID: {inner_message_id}")
    if network_message_id:
        inner_identifiers.append(
            f"X-MS-Exchange-Organization-Network-Message-Id: {network_message_id}"
        )
    identifier_headers = "\n".join(inner_identifiers)

    from_header = f"From: {sender}\n" if sender else ""
    return f"""{from_header}To: recipient@example.com
Cc: copied@example.com
Bcc: hidden@example.com
Subject: Original subject
Date: Thu, 20 Aug 2026 10:00:00 +0000
{identifier_headers}
MIME-Version: 1.0
Content-Type: text/plain

{inner_body}""".encode()


def _jmr_wrapper(
    outer_message_id="<JMR.report@microsoft.com>",
    disposition="attachment",
    extra_rfc822_child="",
):
    disposition_header = f"Content-Disposition: {disposition}\n" if disposition else ""
    return f"""From: MOD Administrator <admin@example.com>
To: abuse@example.com
Message-ID: {outer_message_id}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=outer

--outer
Content-Type: text/plain

Microsoft report metadata
--outer
Content-Type: message/rfc822
{disposition_header}
From: Original Sender <sender@example.com>
To: recipient@example.com
Subject: Original subject

Original body
{extra_rfc822_child}--outer--
""".encode()


def _jmr_report(
    sender="MOD Administrator <admin@example.com>",
    body="Microsoft report metadata",
    message_id="<JMR.report@microsoft.com>",
):
    return SimpleNamespace(
        headers=SimpleNamespace(
            from_address=sender,
            to="abuse@example.com",
            cc=None,
            bcc=None,
            subject="Reported message",
            message_id=message_id,
            date="Thu, 20 Aug 2026 10:01:00 +0000",
        ),
        body=SimpleNamespace(plain_text=body, html=None),
    )


def test_extract_jmr_inner_email_projects_original_message():
    original = _jmr_original()
    result = app_module._extract_jmr_inner_email(
        _jmr_wrapper(), original, _jmr_report(), "wrapper-graph-id"
    )

    assert result is not None
    parsed, reporter, raw_email = result
    assert parsed.headers.email_id == "original-network-id"
    assert parsed.headers.message_id == "<original-message@example.com>"
    assert reporter.from_ == "admin@example.com"
    assert reporter.to == "abuse@example.com"
    assert reporter.cc is None
    assert reporter.bcc is None
    assert reporter.subject == "Reported message"
    assert reporter.message_id == "<JMR.report@microsoft.com>"
    assert reporter.id == "wrapper-graph-id"
    assert reporter.body == "Microsoft report metadata"
    assert reporter.date == "Thu, 20 Aug 2026 10:01:00 +0000"
    assert raw_email == original


def test_extract_jmr_inner_email_id_falls_back_to_original_message_id():
    result = app_module._extract_jmr_inner_email(
        _jmr_wrapper(),
        _jmr_original(network_message_id=None),
        _jmr_report(),
        "wrapper-graph-id",
    )

    assert result is not None
    parsed, reporter, _ = result
    assert parsed.headers.email_id == "<original-message@example.com>"
    assert reporter.id == "wrapper-graph-id"
    assert reporter.message_id == "<JMR.report@microsoft.com>"


def test_extract_jmr_inner_email_does_not_reuse_outer_id():
    result = app_module._extract_jmr_inner_email(
        _jmr_wrapper(),
        _jmr_original(inner_message_id=None, network_message_id=None),
        _jmr_report(),
        "wrapper-graph-id",
    )

    assert result is not None
    parsed, reporter, _ = result
    assert parsed.headers.email_id is None
    assert reporter.id == "wrapper-graph-id"
    assert reporter.message_id == "<JMR.report@microsoft.com>"


def test_extract_jmr_inner_email_truncates_reporter_body():
    result = app_module._extract_jmr_inner_email(
        _jmr_wrapper(),
        _jmr_original(),
        _jmr_report(body="x" * 600),
        "wrapper-graph-id",
    )

    assert result is not None
    _, reporter, _ = result
    assert reporter.body == "x" * 500


def test_extract_jmr_inner_email_does_not_unwrap_non_jmr_messages(mocker):
    extract = mocker.patch.object(app_module, "extract_email_data")

    assert (
        app_module._extract_jmr_inner_email(
            _jmr_wrapper(outer_message_id="<not-jmr@example.com>"),
            _jmr_original(),
            _jmr_report(),
            "wrapper-graph-id",
        )
        is None
    )
    extract.assert_not_called()


@pytest.mark.parametrize("disposition", ["attachment", "inline", None])
def test_extract_jmr_inner_email_accepts_direct_child(disposition):
    inner_raw = (
        b"From: Original Sender <sender@example.com>\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: A deliberately folded source header\r\n"
        b"\tthat must remain folded exactly this way\r\n"
        b"Message-ID: <original-message@example.com>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Original body with trailing spaces  \r\n"
    )

    result = app_module._extract_jmr_inner_email(
        _jmr_wrapper(disposition=disposition),
        inner_raw,
        _jmr_report(),
        "wrapper-graph-id",
    )

    assert result is not None
    assert result[2] == inner_raw


def test_extract_jmr_inner_email_uses_reporter_when_original_sender_is_missing():
    result = app_module._extract_jmr_inner_email(
        _jmr_wrapper(),
        _jmr_original(sender=None),
        _jmr_report(sender="Reporting User <reporter@example.com>"),
        "wrapper-graph-id",
    )

    assert result is not None
    parsed, reporter, _ = result
    assert parsed.headers.from_address is None
    assert reporter.from_ == "reporter@example.com"


def test_extract_jmr_inner_email_falls_back_when_reporter_is_missing():
    result = app_module._extract_jmr_inner_email(
        _jmr_wrapper(),
        _jmr_original(),
        _jmr_report(sender=None),
        "wrapper-graph-id",
    )

    assert result is None


def test_extract_jmr_inner_email_rejects_ambiguous_direct_children():
    second_child = """--outer
Content-Type: message/rfc822
Content-Disposition: inline

From: Other Sender <other@example.com>
To: recipient@example.com
Subject: Other subject

Other body
"""

    assert (
        app_module._extract_jmr_inner_email(
            _jmr_wrapper(extra_rfc822_child=second_child),
            _jmr_original(),
            _jmr_report(),
            "wrapper-graph-id",
        )
        is None
    )
