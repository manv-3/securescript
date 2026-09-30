"""
SecureScript SIEM & Enterprise Telemetry Streaming Engine.

Exports structured security event logs compliant with:
- ECS (Elastic Common Schema) JSON format for ELK, Splunk, Datadog
- CEF (Common Event Format) for ArcSight and enterprise SOCs
- RFC 5424 Syslog output
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query

logger = logging.getLogger("securescript.siem")
siem_router = APIRouter(prefix="/api/v1/siem", tags=["SIEM Telemetry"])


@dataclass
class SecurityIncidentEvent:
    """ECS and CEF compliant structured security incident record."""
    event_id: str
    timestamp: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    action: str    # "BLOCKED", "AUDITED", "PASSED"
    client_ip: str
    http_method: str
    url_path: str
    detection_stage: str  # "Fast-Path Lexer" or "PyTorch Bi-LSTM"
    confidence_score: float
    trigger_tokens: List[str]
    attack_category: str  # "Reflected XSS", "DOM XSS", "Polyglot XSS", "Encoding Evasion"
    raw_payload: str
    normalized_payload: str
    latency_ms: float

    def to_ecs_json(self) -> str:
        """Converts the security record to Elastic Common Schema (ECS) JSON."""
        ecs = {
            "@timestamp": self.timestamp,
            "event": {
                "id": self.event_id,
                "category": ["intrusion_detection", "threat"],
                "type": ["access", "denied" if self.action == "BLOCKED" else "allowed"],
                "outcome": "failure" if self.action == "BLOCKED" else "success",
                "severity": 9 if self.severity == "CRITICAL" else 7,
                "duration": int(self.latency_ms * 1_000_000),  # nanoseconds
            },
            "rule": {
                "name": f"SecureScript {self.detection_stage}",
                "description": f"XSS attack prevented: {self.attack_category}",
            },
            "source": {
                "ip": self.client_ip,
            },
            "url": {
                "path": self.url_path,
            },
            "http": {
                "request": {
                    "method": self.http_method,
                }
            },
            "threat": {
                "indicator": {
                    "type": "payload",
                    "description": self.raw_payload[:120],
                },
                "tactic": {
                    "name": "Initial Access",
                    "id": "TA0001",
                },
                "technique": {
                    "name": "Exploit Public-Facing Application: XSS",
                    "id": "T1190",
                }
            },
            "securescript": {
                "confidence": self.confidence_score,
                "trigger_tokens": self.trigger_tokens,
                "normalized_payload": self.normalized_payload[:150],
            }
        }
        return json.dumps(ecs)

    def to_cef(self) -> str:
        """Converts record to ArcSight Common Event Format (CEF)."""
        # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
        ext = (
            f"src={self.client_ip} act={self.action} app=HTTP requestMethod={self.http_method} "
            f"cs1Label=DetectionStage cs1={self.detection_stage} "
            f"cfp1Label=Confidence cfp1={self.confidence_score:.4f} "
            f"msg={self.attack_category}"
        )
        return f"CEF:0|HCL|SecureScript|0.3.0|XSS-001|Cross-Site Scripting Detected|8|{ext}"


class SIEMCollector:
    """Manages active security incident logs and SIEM output buffers."""

    def __init__(self, max_buffer_size: int = 500):
        self.max_buffer_size = max_buffer_size
        self.events: List[SecurityIncidentEvent] = []

    def record_incident(
        self,
        action: str,
        client_ip: str,
        http_method: str,
        url_path: str,
        detection_stage: str,
        confidence_score: float,
        trigger_tokens: List[str],
        raw_payload: str,
        normalized_payload: str,
        latency_ms: float,
        attack_category: str = "Cross-Site Scripting (XSS)",
        severity: str = "HIGH"
    ) -> SecurityIncidentEvent:
        event = SecurityIncidentEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity=severity,
            action=action,
            client_ip=client_ip,
            http_method=http_method,
            url_path=url_path,
            detection_stage=detection_stage,
            confidence_score=round(confidence_score, 4),
            trigger_tokens=trigger_tokens,
            attack_category=attack_category,
            raw_payload=raw_payload,
            normalized_payload=normalized_payload,
            latency_ms=round(latency_ms, 3)
        )
        self.events.append(event)
        if len(self.events) > self.max_buffer_size:
            self.events.pop(0)

        logger.info(f"[SIEM CEF] {event.to_cef()}")
        return event

    def get_events(self, limit: int = 50, action_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        evs = self.events
        if action_filter:
            evs = [e for e in evs if e.action.upper() == action_filter.upper()]
        return [asdict(e) for e in reversed(evs[-limit:])]


# Global SIEM collector instance
siem_collector = SIEMCollector()


@siem_router.get("/events")
def list_siem_events(
    limit: int = Query(default=20, le=100),
    action: Optional[str] = Query(default=None)
):
    """Returns recent SIEM incident events in structured format."""
    return {
        "status": "success",
        "total_buffered": len(siem_collector.events),
        "events": siem_collector.get_events(limit=limit, action_filter=action)
    }


@siem_router.get("/export/cef")
def export_cef_stream(limit: int = Query(default=20, le=100)):
    """Exports recent events formatted as ArcSight Common Event Format (CEF)."""
    cef_lines = [e.to_cef() for e in reversed(siem_collector.events[-limit:])]
    return {
        "format": "CEF:0",
        "count": len(cef_lines),
        "lines": cef_lines
    }


@siem_router.get("/export/ecs")
def export_ecs_stream(limit: int = Query(default=20, le=100)):
    """Exports recent events formatted as Elastic Common Schema (ECS) JSON objects."""
    ecs_objects = [json.loads(e.to_ecs_json()) for e in reversed(siem_collector.events[-limit:])]
    return {
        "format": "Elastic Common Schema (ECS) v8.x",
        "count": len(ecs_objects),
        "records": ecs_objects
    }
