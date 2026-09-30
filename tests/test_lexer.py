"""
Unit tests and SLA latency benchmarks for SecureScript Fast-Path Lexer.
"""

import time
import pytest
from securescript.core.lexer import FastPathLexer, LexerVerdict, LexerContext, inspect_fast_path


class TestFastPathLexer:

    def setup_method(self):
        self.lexer = FastPathLexer()

    def test_benign_plain_text(self):
        """Benign queries with standard text should PASS instantly."""
        result = self.lexer.inspect("search term query for user profile")
        assert result.verdict == LexerVerdict.PASS
        assert not result.state_switch

    def test_safe_mathematical_inequality(self):
        """Equations with '<' and '>' must NOT trigger false positives."""
        result = self.lexer.inspect("score > 50 and score < 100")
        assert result.verdict == LexerVerdict.PASS
        assert not result.state_switch

    def test_overt_script_tag(self):
        """Standard <script> tag with execution body must BLOCK."""
        result = self.lexer.inspect("<script>alert('XSS')</script>")
        assert result.verdict == LexerVerdict.BLOCK
        assert result.state_switch
        assert LexerContext.SCRIPT_TAG in result.contexts_detected

    def test_inline_event_handler(self):
        """Event handlers (onerror=, onload=) with calls must BLOCK."""
        result = self.lexer.inspect("<img src=x onerror=alert(document.cookie)>")
        assert result.verdict == LexerVerdict.BLOCK
        assert LexerContext.EVENT_HANDLER in result.contexts_detected
        assert LexerContext.DANGEROUS_CALL in result.contexts_detected

    def test_pseudo_protocol_vector(self):
        """javascript: pseudo-protocols must BLOCK."""
        result = self.lexer.inspect("javascript:alert(1)")
        assert result.verdict == LexerVerdict.BLOCK
        assert LexerContext.PSEUDO_PROTOCOL in result.contexts_detected

    def test_svg_vector(self):
        """<svg onload=...> must BLOCK."""
        result = self.lexer.inspect("<svg onload=alert(1)>")
        assert result.verdict == LexerVerdict.BLOCK
        assert LexerContext.SCRIPT_TAG in result.contexts_detected

    def test_ambiguous_markup_tag(self):
        """Benign formatting tags without handlers trigger SUSPICIOUS for DL review."""
        result = self.lexer.inspect("<b>Important announcement</b>")
        assert result.verdict == LexerVerdict.SUSPICIOUS
        assert LexerContext.HTML_TAG in result.contexts_detected

    def test_latency_sla_under_2ms(self):
        """
        NFR-1 Latency SLA: Fast-path inspection must strictly execute in < 2ms.
        Evaluated across 500 diverse payloads.
        """
        payloads = [
            "John Doe",
            "SELECT * FROM users",
            "<script>alert(1)</script>",
            "x < y and y > z",
            "<img src=x onerror=alert(1)>",
            "javascript:void(0)",
            "normal query string with parameters",
            "<iframe src='http://evil.com'></iframe>",
            "100% genuine message with &amp; entity",
            "test_param=value&id=42&sort=asc"
        ]

        times = []
        for _ in range(50):
            for p in payloads:
                t0 = time.perf_counter()
                self.lexer.inspect(p)
                dt = (time.perf_counter() - t0) * 1000.0
                times.append(dt)

        avg_latency = sum(times) / len(times)
        max_latency = max(times)

        # Average latency must be well under 1ms, peak well under 2ms
        assert avg_latency < 1.0, f"Average latency too high: {avg_latency:.4f} ms"
        assert max_latency < 2.0, f"Peak latency exceeded 2ms SLA: {max_latency:.4f} ms"
