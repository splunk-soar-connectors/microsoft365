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


def test_jmr_unwrap_setting_is_exposed_in_es_asset_settings():
    configuration = app_module.Asset.to_json_schema()

    assert configuration["unwrap_jmr_reported_message"]["category"] == "connectivity"


def _jmr_wrapper(
    outer_message_id="<JMR.report@microsoft.com>",
    inner_message_id="<original-message@example.com>",
    network_message_id="original-network-id",
    inner_body="Original body",
):
    inner_identifiers = []
    if inner_message_id:
        inner_identifiers.append(f"Message-ID: {inner_message_id}")
    if network_message_id:
        inner_identifiers.append(
            f"X-MS-Exchange-Organization-Network-Message-Id: {network_message_id}"
        )
    identifier_headers = "\n".join(inner_identifiers)

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
Content-Disposition: attachment

From: Original Sender <sender@example.com>
To: recipient@example.com
Cc: copied@example.com
Bcc: hidden@example.com
Subject: Original subject
Date: Thu, 20 Aug 2026 10:00:00 +0000
{identifier_headers}
MIME-Version: 1.0
Content-Type: text/plain

{inner_body}
--outer--
""".encode()


def test_extract_jmr_inner_email_projects_original_message():
    result = app_module._extract_jmr_inner_email(_jmr_wrapper())

    assert result is not None
    parsed, reporter, raw_email = result
    assert parsed.headers.email_id == "original-network-id"
    assert parsed.headers.message_id == "<original-message@example.com>"
    assert reporter.from_ == "sender@example.com"
    assert reporter.to == "recipient@example.com"
    assert reporter.cc == "copied@example.com"
    assert reporter.bcc == "hidden@example.com"
    assert reporter.subject == "Original subject"
    assert reporter.message_id == "<original-message@example.com>"
    assert reporter.id == "original-network-id"
    assert reporter.body == "Original body"
    assert reporter.date == "Thu, 20 Aug 2026 10:00:00 +0000"
    assert raw_email.startswith(b"From: Original Sender <sender@example.com>")


def test_extract_jmr_inner_email_id_falls_back_to_original_message_id():
    result = app_module._extract_jmr_inner_email(_jmr_wrapper(network_message_id=None))

    assert result is not None
    parsed, reporter, _ = result
    assert parsed.headers.email_id == "<original-message@example.com>"
    assert reporter.id == "<original-message@example.com>"
    assert reporter.message_id == "<original-message@example.com>"


def test_extract_jmr_inner_email_does_not_reuse_outer_id():
    result = app_module._extract_jmr_inner_email(
        _jmr_wrapper(inner_message_id=None, network_message_id=None)
    )

    assert result is not None
    parsed, reporter, _ = result
    assert parsed.headers.email_id is None
    assert reporter.id is None
    assert reporter.message_id is None


def test_extract_jmr_inner_email_truncates_reporter_body():
    result = app_module._extract_jmr_inner_email(_jmr_wrapper(inner_body="x" * 600))

    assert result is not None
    _, reporter, _ = result
    assert reporter.body == "x" * 500


def test_extract_jmr_inner_email_does_not_unwrap_non_jmr_messages(mocker):
    extract = mocker.patch.object(app_module, "extract_email_data")

    assert (
        app_module._extract_jmr_inner_email(
            _jmr_wrapper(outer_message_id="<not-jmr@example.com>")
        )
        is None
    )
    extract.assert_not_called()


def test_extract_jmr_inner_email_requires_a_direct_attachment(mocker):
    extract = mocker.patch.object(app_module, "extract_email_data")
    raw_email = _jmr_wrapper().replace(
        b"Content-Disposition: attachment", b"Content-Disposition: inline"
    )

    assert app_module._extract_jmr_inner_email(raw_email) is None
    extract.assert_not_called()
