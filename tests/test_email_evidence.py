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


def test_jmr_unwrap_setting_uses_ingest_category():
    configuration = app_module.Asset.to_json_schema()

    assert configuration["unwrap_jmr_reported_message"]["category"] == "ingest"


def _outer_email_data():
    return SimpleNamespace(
        headers=SimpleNamespace(
            from_address="MOD Administrator <admin@example.com>",
            to="abuse@example.com",
            cc=None,
            bcc=None,
            subject="Phishing: report",
            message_id="<JMR.report@microsoft.com>",
            date="Thu, 20 Aug 2026 11:47:51 +0000",
        ),
        body=SimpleNamespace(plain_text="Microsoft report metadata", html=None),
    )


def _jmr_wrapper(message_id="<JMR.report@microsoft.com>"):
    return f"""From: MOD Administrator <admin@example.com>
To: abuse@example.com
Message-ID: {message_id}
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
Subject: Original subject
MIME-Version: 1.0
Content-Type: text/plain

Original body
--outer--
""".encode()


def test_extract_jmr_inner_email_uses_unnamed_direct_rfc822_attachment(mocker):
    inner = SimpleNamespace()
    extract = mocker.patch.object(app_module, "extract_email_data", return_value=inner)

    result = app_module._extract_jmr_inner_email(
        _jmr_wrapper(), _outer_email_data(), "message-id"
    )

    assert result is not None
    parsed, reporter, raw_email = result
    assert parsed is inner
    assert reporter.from_ == "admin@example.com"
    assert reporter.to == "abuse@example.com"
    assert raw_email.startswith(b"From: Original Sender <sender@example.com>")
    assert extract.call_args.args[0] == raw_email
    assert extract.call_args.args[1] == "message-id"


def test_extract_jmr_inner_email_does_not_unwrap_non_jmr_messages(mocker):
    extract = mocker.patch.object(app_module, "extract_email_data")

    assert (
        app_module._extract_jmr_inner_email(
            _jmr_wrapper("<not-jmr@example.com>"), _outer_email_data(), "message-id"
        )
        is None
    )
    extract.assert_not_called()


def test_extract_jmr_inner_email_requires_a_direct_attachment(mocker):
    extract = mocker.patch.object(app_module, "extract_email_data")
    raw_email = _jmr_wrapper().replace(
        b"Content-Disposition: attachment", b"Content-Disposition: inline"
    )

    assert (
        app_module._extract_jmr_inner_email(
            raw_email, _outer_email_data(), "message-id"
        )
        is None
    )
    extract.assert_not_called()
