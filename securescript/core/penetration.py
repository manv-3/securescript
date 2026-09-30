"""
SecureScript Automated End-to-End Penetration Testing Harness.

Simulates a real-world adversarial assessment against a target application
protected by the SecureScript hybrid interception middleware.
Evaluates:
- Reflected XSS via Query Parameters
- Stored XSS via JSON Request Bodies
- Header-based XSS via User-Agent and Referer
- Client-side DOM-XSS via CSP Reporting Telemetry
- Multi-layer nested polyglots and obfuscations
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from fastapi.testclient import TestClient

from securescript.middleware.asgi import demo_app


@dataclass
class PenetrationTestReport:
    """Summary metrics of the automated penetration test run."""
    total_attacks_attempted: int
    attacks_blocked_http_403: int
    attacks_mitigated_csp: int
    benign_requests_attempted: int
    benign_passed_http_200: int
    defense_efficacy_rate: float
    avg_latency_ms: float
    detailed_findings: List[Dict[str, Any]]


class PenetrationTester:
    """Automated security scanner simulating real-world attacker payloads."""

    def __init__(self):
        self.client = TestClient(demo_app)

    def run_full_penetration_suite(self) -> PenetrationTestReport:
        findings = []
        latencies = []

        blocked_count = 0
        csp_count = 0
        benign_passed = 0

        # Attack Vectors
        test_cases = [
            # Reflected XSS vectors
            {"type": "Reflected XSS", "method": "GET", "url": "/search?q=%3Cscript%3Ealert('reflected')%3C/script%3E"},
            {"type": "Reflected Polyglot", "method": "GET", "url": "/search?q=jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/--></textarea></title></xmp><svg/onload=alert(1)>"},
            {"type": "Reflected Double-Encoded", "method": "GET", "url": "/search?q=%253Cimg%2520src=x%2520onerror=alert(1)%253E"},

            # Stored XSS vectors (JSON bodies)
            {"type": "Stored XSS in JSON", "method": "POST", "url": "/submit", "json": {"title": "Article", "content": "<svg onload=alert(1)>"}},
            {"type": "Stored XSS in Nested Field", "method": "POST", "url": "/submit", "json": {"user": {"metadata": {"bio": "<body onload=alert('nested')>"}}}},
            {"type": "Stored XSS Base64 Data URI", "method": "POST", "url": "/submit", "json": {"file": "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>"}},

            # Header-based XSS vectors
            {"type": "Header Injection (User-Agent)", "method": "GET", "url": "/search?q=test", "headers": {"User-Agent": "<script>alert('ua-vector')</script>"}},
            {"type": "Header Injection (Referer)", "method": "GET", "url": "/search?q=test", "headers": {"Referer": "javascript:alert('referer')"}},

            # Client-side DOM-XSS Telemetry
            {"type": "DOM-XSS Sink Telemetry", "method": "POST", "url": "/api/v1/csp-report", "json": {"csp-report": {"blocked-uri": "eval", "violated-directive": "script-src"}}},
        ]

        # Benign baseline requests
        benign_cases = [
            {"method": "GET", "url": "/search?q=machine+learning+cybersecurity"},
            {"method": "GET", "url": "/search?q=price+<=+500+and+rating+>=+4.5"},
            {"method": "POST", "url": "/submit", "json": {"name": "Alice Smith", "message": "Can you provide the invoice for order #12345?"}},
            {"method": "GET", "url": "/search?q=SELECT+*+FROM+products+WHERE+id+<+50"},
            {"method": "GET", "url": "/dashboard"},
        ]

        # 1. Execute Attack Payloads
        for tc in test_cases:
            t0 = time.perf_counter()
            m = tc["method"]
            url = tc["url"]
            hdrs = tc.get("headers", {})
            json_body = tc.get("json")

            if m == "GET":
                resp = self.client.get(url, headers=hdrs)
            else:
                resp = self.client.post(url, json=json_body, headers=hdrs)

            lat = (time.perf_counter() - t0) * 1000.0
            latencies.append(lat)

            if tc["type"] == "DOM-XSS Sink Telemetry":
                is_defended = resp.status_code == 204
                if is_defended:
                    csp_count += 1
            else:
                is_defended = resp.status_code == 403
                if is_defended:
                    blocked_count += 1

            findings.append({
                "test_type": tc["type"],
                "target_endpoint": url,
                "status_code": resp.status_code,
                "mitigated": is_defended,
                "latency_ms": round(lat, 3)
            })

        # 2. Execute Benign Cases
        for bc in benign_cases:
            t0 = time.perf_counter()
            m = bc["method"]
            url = bc["url"]
            json_body = bc.get("json")

            if m == "GET":
                resp = self.client.get(url)
            else:
                resp = self.client.post(url, json=json_body)

            lat = (time.perf_counter() - t0) * 1000.0
            latencies.append(lat)

            if resp.status_code == 200:
                benign_passed += 1

        total_atks = len(test_cases)
        total_ben = len(benign_cases)
        total_mitigated = blocked_count + csp_count

        efficacy = (total_mitigated / total_atks) * 100.0 if total_atks else 0.0

        return PenetrationTestReport(
            total_attacks_attempted=total_atks,
            attacks_blocked_http_403=blocked_count,
            attacks_mitigated_csp=csp_count,
            benign_requests_attempted=total_ben,
            benign_passed_http_200=benign_passed,
            defense_efficacy_rate=round(efficacy, 2),
            avg_latency_ms=round(sum(latencies) / len(latencies), 3),
            detailed_findings=findings
        )


if __name__ == "__main__":
    print("=" * 70)
    print("      SecureScript Automated Penetration Testing Suite")
    print("=" * 70)
    tester = PenetrationTester()
    report = tester.run_full_penetration_suite()

    print(f"\nAttacks Attempted:          {report.total_attacks_attempted}")
    print(f"Network Attacks Blocked:    {report.attacks_blocked_http_403} (HTTP 403)")
    print(f"DOM-XSS Reports Ingested:   {report.attacks_mitigated_csp} (CSP 204)")
    print(f"Total Defense Efficacy:     {report.defense_efficacy_rate}%")
    print(f"\nBenign Queries Tested:      {report.benign_requests_attempted}")
    print(f"Benign Queries Passed:      {report.benign_passed_http_200} / {report.benign_requests_attempted}")
    print(f"Average Response Latency:   {report.avg_latency_ms} ms")

    print("\nDetailed Attack Assessment Log:")
    for f in report.detailed_findings:
        stat = "BLOCKED [403]" if f["status_code"] == 403 else ("INGESTED [204]" if f["status_code"] == 204 else "PASSED")
        print(f"  * {f['test_type']:<28} -> {stat:<15} ({f['latency_ms']} ms)")
