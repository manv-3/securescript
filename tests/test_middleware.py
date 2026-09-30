"""
Integration tests for SecureScript ASGI Interception Middleware.
"""

import pytest
from fastapi.testclient import TestClient

from securescript.middleware.asgi import demo_app


class TestXSSInterceptionMiddleware:

    def setup_method(self):
        self.client = TestClient(demo_app)

    def test_benign_get_query_passed(self):
        """Standard benign query parameter returns 200 OK."""
        response = self.client.get("/search?q=python+programming")
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        assert response.headers.get("X-Protected-By") == "SecureScript-Hybrid-WAF"

    def test_xss_query_blocked_http_403(self):
        """XSS query parameter returns 403 Forbidden."""
        response = self.client.get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
        assert response.status_code == 403
        data = response.json()
        assert data["error"] == "Forbidden - XSS Threat Detected"
        assert "incident_location" in data["details"]

    def test_benign_post_json_passed(self):
        """Clean JSON payload passes without interference."""
        payload = {"username": "john_doe", "bio": "Security enthusiast & developer"}
        response = self.client.post("/submit", json=payload)
        assert response.status_code == 200
        assert response.json()["status"] == "received"

    def test_xss_in_post_json_blocked(self):
        """Malicious string inside JSON body is intercepted and blocked."""
        payload = {"comment": "<img src=x onerror=alert(document.cookie)>"}
        response = self.client.post("/submit", json=payload)
        assert response.status_code == 403
        data = response.json()
        assert data["status"] == 403
        assert "comment" in data["details"]["incident_location"]

    def test_xss_in_nested_json_blocked(self):
        """Recursively checks and blocks nested arrays and dictionaries."""
        payload = {
            "metadata": {
                "tags": ["tech", "<svg onload=alert(1)>", "coding"]
            }
        }
        response = self.client.post("/submit", json=payload)
        assert response.status_code == 403

    def test_xss_in_user_agent_header_blocked(self):
        """Attacks injected via User-Agent are detected and blocked."""
        headers = {"User-Agent": "<script>alert('ua-xss')</script>"}
        response = self.client.get("/search?q=normal", headers=headers)
        assert response.status_code == 403
        assert "user-agent" in response.json()["details"]["incident_location"]
