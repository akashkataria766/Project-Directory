from app import app
from url_checker import analyze_url, check_google_safebrowsing


def test_home_page_loads():
    response = app.test_client().get("/")

    assert response.status_code == 200


def test_suspicious_url_is_checked_without_external_api():
    response = app.test_client().post(
        "/", data={"url": "http://192.168.1.1/login"}
    )

    assert response.status_code == 200
    assert b"Unsafe or suspicious address" in response.data


def test_missing_url_is_rejected():
    response = app.test_client().post("/", data={"url": ""})

    assert response.status_code == 200
    assert b"A URL is required" in response.data


def test_bare_ip_address_is_supported():
    response = app.test_client().post("/", data={"url": "192.168.1.1"})

    assert response.status_code == 200
    assert b"https://192.168.1.1" in response.data


def test_bare_domain_is_normalized_and_not_marked_invalid():
    result = analyze_url("example.com")

    assert result["normalized"] == "https://example.com"
    assert result["checks"][1]["status"] == "safe"
    assert result["status_counts"]["danger"] == 0
    assert result["status_counts"]["warning"] == 1
    assert result["status_counts"]["safe"] >= 2


def test_security_indicators_lower_score():
    result = analyze_url("http://user:password@example.com:8080/%0a-login")

    assert result["overall"] in {"warning", "danger"}
    assert result["score"] < 100
    assert any(check["name"] == "Credential protection" and check["status"] == "danger" for check in result["checks"])


def test_malformed_port_is_rejected():
    result = analyze_url("https://example.com:not-a-port")

    assert result["overall"] == "danger"
    assert result["status_counts"]["danger"] >= 1


def test_brand_lookalike_is_flagged():
    result = analyze_url("go0gle.com")

    assert result["overall"] == "danger"
    assert any("resembles 'google'" in check["detail"] for check in result["checks"])


def test_real_brand_domain_is_not_flagged_as_lookalike():
    result = analyze_url("google.com")

    assert not any(check["name"] == "Brand impersonation" and check["status"] == "danger" for check in result["checks"])


def test_invalid_hostname_does_not_crash():
    result = analyze_url("https://[invalid")

    assert result["overall"] == "danger"
    assert result["status_counts"]["danger"] >= 1


def test_rejected_api_key_has_a_safe_message(monkeypatch):
    class RejectedResponse:
        status_code = 401
        text = "secret response details"

    monkeypatch.setattr("url_checker.requests.post", lambda *args, **kwargs: RejectedResponse())

    is_suspicious, reason = check_google_safebrowsing("https://example.com", "invalid")

    assert is_suspicious is False
    assert "rejected the API key" in reason
    assert "secret" not in reason
