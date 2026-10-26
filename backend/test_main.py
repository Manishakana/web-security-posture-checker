from fastapi import HTTPException

from backend.main import html_findings, observed_controls, public_host, score, security_header_findings


def test_private_destinations_are_rejected():
    try:
        public_host("127.0.0.1")
    except HTTPException as error:
        assert error.status_code == 400
    else:
        raise AssertionError("Loopback must be blocked")


def test_missing_headers_create_findings():
    findings = security_header_findings({})
    assert any(item["key"] == "content-security-policy" for item in findings)
    assert any(item["key"] == "strict-transport-security" for item in findings)


def test_mixed_content_is_reported_on_https_pages():
    findings = html_findings(b'<img src="http://assets.example/image.png">', "https://example.com")
    assert findings[0]["key"] == "mixed-content"


def test_score_weights_severity():
    result, status = score([{"severity": "high"}, {"severity": "medium"}, {"severity": "low"}])
    assert result == 76
    assert status == "Needs attention"


def test_observed_controls_include_configured_headers():
    controls = observed_controls({"content-security-policy": "default-src 'self'", "referrer-policy": "same-origin"})
    assert controls == [
        {"name": "content-security-policy", "value": "default-src 'self'"},
        {"name": "referrer-policy", "value": "same-origin"},
    ]
