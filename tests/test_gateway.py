"""
Integration tests for SecureScript Reverse-Proxy WAF Gateway.
"""

from fastapi.testclient import TestClient
from securescript.proxy.gateway import waf_app

client = TestClient(waf_app)


def test_waf_gateway_proxies_live_vercel_site():
    response = client.get("/")
    assert response.status_code == 200
    assert "Contact Us" in response.text
    assert "SecureScript WAF" in response.text
    assert response.headers.get("X-Protected-By") == "SecureScript-Hybrid-WAF"


def test_waf_gateway_blocks_reflected_xss_query():
    response = client.get("/?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E")
    assert response.status_code == 403
    assert "Access Denied by SecureScript WAF" in response.text
    assert "Incident ID:" in response.text


def test_waf_gateway_blocks_malicious_form_submission():
    payload = {
        "name": "Attacker",
        "email": "attacker@evil.com",
        "message": "<img src=x onerror=alert(1)>"
    }
    response = client.post("/api/submit", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert data["status"] == 403
    assert "details" in data
    assert data["details"]["detection_stage"] == "Fast-Path Lexical Analyzer"


def test_waf_gateway_allows_clean_form_payload():
    # If the clean payload passes inspection, it reaches upstream
    # Even if Render is sleeping/down (e.g. 503), WAF verdict is NOT 403
    payload = {
        "name": "Alice Smith",
        "email": "alice@example.com",
        "message": "Hello, I would like to inquire about your product pricing."
    }
    response = client.post("/api/submit", json=payload)
    assert response.status_code != 403  # Not blocked by WAF
