"""
Unit tests for SecureScript SIEM Telemetry and Event Export.
"""

from fastapi.testclient import TestClient
from securescript.middleware.asgi import demo_app

client = TestClient(demo_app)


def test_siem_incident_recording_on_block():
    # Trigger a block
    resp = client.get("/search?q=<script>alert('siem-test')</script>")
    assert resp.status_code == 403

    # Query SIEM events
    events_resp = client.get("/api/v1/siem/events")
    assert events_resp.status_code == 200
    data = events_resp.json()
    assert data["status"] == "success"
    assert data["total_buffered"] > 0
    recent = data["events"][0]
    assert recent["action"] == "BLOCKED"
    assert "query_param" in recent["url_path"]


def test_siem_cef_export():
    resp = client.get("/api/v1/siem/export/cef")
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "CEF:0"
    assert len(data["lines"]) > 0
    assert "CEF:0|HCL|SecureScript" in data["lines"][0]


def test_siem_ecs_export():
    resp = client.get("/api/v1/siem/export/ecs")
    assert resp.status_code == 200
    data = resp.json()
    assert "Elastic Common Schema" in data["format"]
    assert len(data["records"]) > 0
    record = data["records"][0]
    assert "@timestamp" in record
    assert "event" in record
    assert record["event"]["type"] == ["access", "denied"]
