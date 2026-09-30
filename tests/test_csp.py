"""
Unit tests for SecureScript W3C CSP Violation Reporting and DOM-XSS Correlation.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from securescript.telemetry.csp import router, correlator


@pytest.fixture
def app_with_csp():
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(app_with_csp):
    return TestClient(app_with_csp)


class TestCSPTelemetry:

    def setup_method(self):
        correlator.events.clear()

    def test_ingest_standard_w3c_csp_report(self, client):
        """Standard W3C CSP report with script-src inline violation is flagged as DOM-XSS."""
        payload = {
            "csp-report": {
                "document-uri": "https://example.com/checkout",
                "referrer": "",
                "violated-directive": "script-src-elem",
                "effective-directive": "script-src-elem",
                "original-policy": "default-src 'self'; script-src 'self'",
                "disposition": "enforce",
                "blocked-uri": "inline",
                "line-number": 42,
                "script-sample": "alert(document.cookie)"
            }
        }
        response = client.post("/api/v1/csp-report", json=payload)
        assert response.status_code == 204

        # Check recorded event
        events = correlator.get_events(1)
        assert len(events) == 1
        event = events[0]
        assert event.is_dom_xss_indicator is True
        assert event.severity in ("HIGH", "CRITICAL")
        assert event.details.script_sample == "alert(document.cookie)"

    def test_ingest_eval_sink_violation(self, client):
        """Violation involving 'eval' sink must be flagged with CRITICAL severity."""
        payload = {
            "csp-report": {
                "document-uri": "https://example.com/dashboard",
                "violated-directive": "script-src",
                "effective-directive": "script-src",
                "blocked-uri": "eval",
                "script-sample": "eval(userInput)"
            }
        }
        response = client.post("/api/v1/csp-report", json=payload)
        assert response.status_code == 204

        events = correlator.get_events(1)
        assert len(events) == 1
        assert events[0].severity == "CRITICAL"
        assert events[0].is_dom_xss_indicator is True

    def test_reporting_api_v1_array_format(self, client):
        """Handles W3C Reporting API array format cleanly."""
        payload = [
            {
                "type": "csp-violation",
                "age": 5,
                "url": "https://example.com/profile",
                "body": {
                    "documentURL": "https://example.com/profile",
                    "blockedURL": "inline",
                    "violatedDirective": "script-src-attr",
                    "sample": "onclick=exploit()"
                }
            }
        ]
        response = client.post("/api/v1/csp-report", json=payload)
        assert response.status_code == 204
        assert len(correlator.events) == 1
        assert correlator.events[0].is_dom_xss_indicator is True

    def test_csp_stats_and_listing(self, client):
        """Telemetry endpoints return accurate aggregated statistics."""
        # Post 2 events
        client.post("/api/v1/csp-report", json={
            "csp-report": {"blocked-uri": "inline", "violated-directive": "script-src"}
        })
        client.post("/api/v1/csp-report", json={
            "csp-report": {"blocked-uri": "https://cdn.example.com", "violated-directive": "img-src"}
        })

        # Test listing
        list_resp = client.get("/api/v1/csp-events")
        assert list_resp.status_code == 200
        assert list_resp.json()["count"] == 2

        # Test stats
        stats_resp = client.get("/api/v1/csp-stats")
        assert stats_resp.status_code == 200
        stats = stats_resp.json()["stats"]
        assert stats["total_violations"] == 2
        assert stats["dom_xss_indicators"] == 1
