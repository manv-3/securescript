"""
Tests for SecureScript Security Operations & Analytics Dashboard.
"""

from fastapi.testclient import TestClient
from securescript.middleware.asgi import demo_app

client = TestClient(demo_app)


def test_dashboard_ui_html():
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "SecureScript Hybrid WAF" in response.text
    assert "Interactive Payload Inspection Sandbox" in response.text


def test_dashboard_stats_api():
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_analyzed" in data
    assert "total_blocked" in data
    assert "fast_path_latency_avg_ms" in data
    assert "neural_latency_avg_ms" in data
    assert "csp_telemetry" in data


def test_dashboard_simulate_malicious_payload():
    payload = {"payload": "<script>alert(1)</script>"}
    response = client.post("/api/dashboard/simulate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "BLOCK"
    assert data["detection_stage"] == "Fast-Path Lexical Analyzer"
    assert "<script" in data["tokens_detected"]


def test_dashboard_simulate_benign_payload():
    payload = {"payload": "Hello world, looking for product ID 123"}
    response = client.post("/api/dashboard/simulate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "PASS"
    assert data["confidence_score"] == 0.0
