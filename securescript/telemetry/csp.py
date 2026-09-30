"""
SecureScript W3C CSP Violation Reporting Endpoint & DOM-XSS Correlation Engine.

Conforms to W3C Content Security Policy Level 3 and Reporting API specifications.
Captures, analyzes, and isolates client-side DOM-based XSS attacks occurring in
browser sinks (innerHTML, eval, document.write) invisible to network perimeter WAFs.
"""

from __future__ import annotations

import datetime
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("securescript.telemetry.csp")

router = APIRouter(prefix="/api/v1", tags=["CSP Telemetry"])


class CSPReportDetails(BaseModel):
    """Represents the inner body of a W3C CSP report."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    document_uri: Optional[str] = Field(default=None, alias="document-uri")
    referrer: Optional[str] = None
    violated_directive: Optional[str] = Field(default=None, alias="violated-directive")
    effective_directive: Optional[str] = Field(default=None, alias="effective-directive")
    original_policy: Optional[str] = Field(default=None, alias="original-policy")
    disposition: Optional[str] = "enforce"
    blocked_uri: Optional[str] = Field(default=None, alias="blocked-uri")
    line_number: Optional[int] = Field(default=None, alias="line-number")
    column_number: Optional[int] = Field(default=None, alias="column-number")
    source_file: Optional[str] = Field(default=None, alias="source-file")
    status_code: Optional[int] = Field(default=None, alias="status-code")
    script_sample: Optional[str] = Field(default=None, alias="script-sample")


class CSPViolationEvent(BaseModel):
    """Internal enriched representation of a logged CSP violation."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    details: CSPReportDetails
    is_dom_xss_indicator: bool = False
    severity: str = "MEDIUM"
    risk_summary: str = ""


class DOMXSSCorrelator:
    """
    In-memory correlation engine that analyzes browser CSP telemetry
    to detect active DOM-based XSS exploitation attempts.
    """

    def __init__(self, max_history: int = 1000):
        self.events: List[CSPViolationEvent] = []
        self.max_history = max_history

    def _normalize_raw_keys(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalizes both kebab-case (CSP Level 2/3) and camelCase (Reporting API v1)."""
        normalized: Dict[str, Any] = {}
        key_mapping = {
            "documenturl": "document-uri",
            "document-uri": "document-uri",
            "document_uri": "document-uri",
            "blockedurl": "blocked-uri",
            "blocked-uri": "blocked-uri",
            "blocked_uri": "blocked-uri",
            "violateddirective": "violated-directive",
            "violated-directive": "violated-directive",
            "violated_directive": "violated-directive",
            "effectivedirective": "effective-directive",
            "effective-directive": "effective-directive",
            "effective_directive": "effective-directive",
            "originalpolicy": "original-policy",
            "original-policy": "original-policy",
            "sample": "script-sample",
            "script-sample": "script-sample",
            "script_sample": "script-sample",
            "linenumber": "line-number",
            "line-number": "line-number",
            "sourcefile": "source-file",
            "source-file": "source-file",
        }
        for k, v in data.items():
            clean_k = k.lower().replace("-", "").replace("_", "")
            mapped_k = key_mapping.get(clean_k, k)
            normalized[mapped_k] = v
        return normalized

    def analyze_and_record(
        self,
        raw_report: Dict[str, Any],
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> CSPViolationEvent:
        """Parses and enriches an incoming CSP report."""
        # Unpack "csp-report" key if wrapped
        inner_data = raw_report.get("csp-report", raw_report)
        normalized_data = self._normalize_raw_keys(inner_data)
        details = CSPReportDetails(**normalized_data)

        # Heuristic determination of DOM-based XSS
        is_dom = False
        severity = "MEDIUM"
        reasons: List[str] = []

        violated = (details.violated_directive or "").lower()
        effective = (details.effective_directive or "").lower()
        blocked = (details.blocked_uri or "").lower()
        sample = (details.script_sample or "").lower()

        # Check for inline script execution attempts
        if "script-src" in effective or "script-src" in violated:
            if blocked in ("inline", "eval", "") or "'unsafe-inline'" in (details.original_policy or ""):
                is_dom = True
                severity = "HIGH"
                reasons.append("Inline script injection attempt intercepted by browser CSP")

        # Check for eval() / Function() sink invocation
        if blocked == "eval" or "unsafe-eval" in sample or "eval" in sample:
            is_dom = True
            severity = "CRITICAL"
            reasons.append("Dangerous JavaScript execution sink (eval/Function) invoked")

        # Check for dangerous event handler attributes
        if "script-src-attr" in effective or "script-src-attr" in violated:
            is_dom = True
            severity = "HIGH"
            reasons.append("Inline DOM event handler execution triggered")

        if not is_dom:
            reasons.append(f"Standard resource policy violation: {violated or effective}")

        event = CSPViolationEvent(
            client_ip=client_ip,
            user_agent=user_agent,
            details=details,
            is_dom_xss_indicator=is_dom,
            severity=severity,
            risk_summary="; ".join(reasons)
        )

        self.events.append(event)
        if len(self.events) > self.max_history:
            self.events.pop(0)

        logger.warning(
            f"[SecureScript CSP] [{severity}] DOM-XSS: {is_dom} from IP={client_ip} | {event.risk_summary}"
        )
        return event

    def get_events(self, limit: int = 50) -> List[CSPViolationEvent]:
        """Returns the most recent events."""
        return list(reversed(self.events[-limit:]))

    def get_stats(self) -> Dict[str, Any]:
        """Aggregates security metrics across received CSP events."""
        total = len(self.events)
        dom_xss_count = sum(1 for e in self.events if e.is_dom_xss_indicator)
        critical_count = sum(1 for e in self.events if e.severity == "CRITICAL")
        high_count = sum(1 for e in self.events if e.severity == "HIGH")

        return {
            "total_violations": total,
            "dom_xss_indicators": dom_xss_count,
            "critical_severity": critical_count,
            "high_severity": high_count,
            "recent_events_count": min(total, 50)
        }


# Global correlator instance
correlator = DOMXSSCorrelator()


@router.post("/csp-report", status_code=204)
async def ingest_csp_report(
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
):
    """
    Ingests W3C Content Security Policy violation reports.
    Accepts application/csp-report, application/reports+json, and application/json.
    """
    try:
        body_bytes = await request.body()
        if not body_bytes:
            return Response(status_code=204)

        report_json = json.loads(body_bytes.decode("utf-8", errors="ignore"))
        client_ip = request.client.host if request.client else "unknown"

        # Handle Reporting API array format vs single CSP report
        if isinstance(report_json, list):
            for item in report_json:
                if isinstance(item, dict):
                    body = item.get("body", item)
                    correlator.analyze_and_record(body, client_ip=client_ip, user_agent=user_agent)
        elif isinstance(report_json, dict):
            correlator.analyze_and_record(report_json, client_ip=client_ip, user_agent=user_agent)

    except Exception as e:
        logger.debug(f"Malformed CSP report ingested: {e}")

    # W3C specification recommends 204 No Content for report ingestion
    return Response(status_code=204)


@router.get("/csp-events")
def list_csp_events(limit: int = 50):
    """Returns recent recorded CSP events for SIEM and dashboard integration."""
    return {"status": "success", "count": len(correlator.events), "events": correlator.get_events(limit)}


@router.get("/csp-stats")
def get_csp_stats():
    """Returns aggregate summary metrics of client-side violations."""
    return {"status": "success", "stats": correlator.get_stats()}
