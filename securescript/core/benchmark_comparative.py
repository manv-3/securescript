"""
SecureScript Comparative Benchmark Suite.

Benchmarks the SecureScript 3-Tier Hybrid Framework against traditional
Regular Expression-based Web Application Firewalls (OWASP CRS / ModSecurity pattern baseline).

Evaluates:
1. Detection Rate (Recall) on plain, obfuscated, and polyglot XSS attacks.
2. False Positive Rate (FPR) on technical prose, math inequalities, and code.
3. Obfuscation Evasion Resilience (URL, HTML entity, Base64, whitespace).
4. Request processing latency (ms).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from securescript.core.adversarial import (
    ADVERSARIAL_ATTACK_SUITE,
    COMPLEX_BENIGN_SUITE,
    AdversarialEvaluator,
)


class LegacyRegexWAF:
    """
    Simulates a traditional Regex-based WAF (similar to default ModSecurity / OWASP CRS rules)
    without recursive normalization or neural contextual reasoning.
    """

    PATTERNS = [
        re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
        re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript:\s*", re.IGNORECASE),
        re.compile(r"on(load|error|click|mouseover|focus|toggle)\s*=", re.IGNORECASE),
        re.compile(r"<\s*(img|svg|iframe|body|object|embed)[^>]+>", re.IGNORECASE),
        re.compile(r"alert\s*\(.*?\)", re.IGNORECASE),
        re.compile(r"document\.cookie", re.IGNORECASE),
    ]

    def inspect(self, payload: str) -> Tuple[str, str, float]:
        """
        Inspects payload using static regex rules without recursive unquoting.
        Returns: Tuple of (action ["BLOCK" or "PASS"], reason, latency_ms)
        """
        t0 = time.perf_counter()
        for pattern in self.PATTERNS:
            if pattern.search(payload):
                lat = (time.perf_counter() - t0) * 1000.0
                return "BLOCK", f"Matched regex pattern: {pattern.pattern}", lat

        lat = (time.perf_counter() - t0) * 1000.0
        return "PASS", "No regex match", lat


@dataclass
class ComparativeStudyResult:
    """Comparative metrics across SecureScript vs. Legacy Regex WAF."""
    securescript_detection_rate: float
    legacy_regex_detection_rate: float
    securescript_fpr: float
    legacy_regex_fpr: float
    securescript_avg_latency_ms: float
    legacy_regex_avg_latency_ms: float
    attacks_evading_regex_but_blocked_by_securescript: List[str]
    benign_flagged_by_regex_but_passed_by_securescript: List[str]


class ComparativeBenchmark:
    """Orchestrates side-by-side comparative testing."""

    def __init__(self):
        self.legacy_waf = LegacyRegexWAF()
        self.securescript = AdversarialEvaluator()

    def run_study(self) -> ComparativeStudyResult:
        evaded_regex_blocked_ss = []
        ss_blocked = 0
        regex_blocked = 0

        ss_latencies = []
        regex_latencies = []

        # 1. Attack evaluation
        for atk in ADVERSARIAL_ATTACK_SUITE:
            ss_verdict, _, ss_lat = self.securescript.inspect_pipeline(atk)
            reg_verdict, _, reg_lat = self.legacy_waf.inspect(atk)

            ss_latencies.append(ss_lat)
            regex_latencies.append(reg_lat)

            if ss_verdict == "BLOCK":
                ss_blocked += 1
            if reg_verdict == "BLOCK":
                regex_blocked += 1

            if reg_verdict == "PASS" and ss_verdict == "BLOCK":
                evaded_regex_blocked_ss.append(atk)

        # 2. Benign evaluation
        flagged_regex_passed_ss = []
        ss_benign_passed = 0
        regex_benign_passed = 0

        for ben in COMPLEX_BENIGN_SUITE:
            ss_verdict, _, ss_lat = self.securescript.inspect_pipeline(ben)
            reg_verdict, _, reg_lat = self.legacy_waf.inspect(ben)

            ss_latencies.append(ss_lat)
            regex_latencies.append(reg_lat)

            if ss_verdict == "PASS":
                ss_benign_passed += 1
            if reg_verdict == "PASS":
                regex_benign_passed += 1

            if reg_verdict == "BLOCK" and ss_verdict == "PASS":
                flagged_regex_passed_ss.append(ben)

        total_atk = len(ADVERSARIAL_ATTACK_SUITE)
        total_ben = len(COMPLEX_BENIGN_SUITE)

        ss_det = (ss_blocked / total_atk) * 100.0 if total_atk else 0.0
        reg_det = (regex_blocked / total_atk) * 100.0 if total_atk else 0.0

        ss_fpr = ((total_ben - ss_benign_passed) / total_ben) * 100.0 if total_ben else 0.0
        reg_fpr = ((total_ben - regex_benign_passed) / total_ben) * 100.0 if total_ben else 0.0

        return ComparativeStudyResult(
            securescript_detection_rate=round(ss_det, 2),
            legacy_regex_detection_rate=round(reg_det, 2),
            securescript_fpr=round(ss_fpr, 2),
            legacy_regex_fpr=round(reg_fpr, 2),
            securescript_avg_latency_ms=round(sum(ss_latencies) / len(ss_latencies), 3),
            legacy_regex_avg_latency_ms=round(sum(regex_latencies) / len(regex_latencies), 3),
            attacks_evading_regex_but_blocked_by_securescript=evaded_regex_blocked_ss,
            benign_flagged_by_regex_but_passed_by_securescript=flagged_regex_passed_ss,
        )


if __name__ == "__main__":
    print("=" * 70)
    print("     SecureScript vs. Legacy Regex WAF: Comparative Study")
    print("=" * 70)
    study = ComparativeBenchmark()
    res = study.run_study()

    print(f"\nDetection Rate (Recall):")
    print(f"  - SecureScript:  {res.securescript_detection_rate}%")
    print(f"  - Legacy Regex:  {res.legacy_regex_detection_rate}%")

    print(f"\nFalse Positive Rate (FPR):")
    print(f"  - SecureScript:  {res.securescript_fpr}%")
    print(f"  - Legacy Regex:  {res.legacy_regex_fpr}%")

    print(f"\nAverage Inspection Latency:")
    print(f"  - SecureScript:  {res.securescript_avg_latency_ms} ms")
    print(f"  - Legacy Regex:  {res.legacy_regex_avg_latency_ms} ms")

    print(f"\nAttacks that Evaded Regex but were BLOCKED by SecureScript ({len(res.attacks_evading_regex_but_blocked_by_securescript)}):")
    for a in res.attacks_evading_regex_but_blocked_by_securescript[:5]:
        print(f"  [+] {a[:75]}...")

    if res.benign_flagged_by_regex_but_passed_by_securescript:
        print(f"\nBenign Queries Flagged by Regex (False Positives) but PASSED by SecureScript:")
        for b in res.benign_flagged_by_regex_but_passed_by_securescript:
            print(f"  [-] {b[:75]}")
