"""
SecureScript Fast-Path Lexer & Grammar State Switch Detector.

This module provides a deterministic, sub-millisecond (< 2ms) lexical parser
that tracks parser context transitions to differentiate inert data literals
from active script execution syntax.

Contexts tracked:
- DATA: Literal text, mathematical comparisons (e.g., 'x < y and y > z')
- HTML_TAG: Standard markup tags (<p>, <b>, <div>)
- SCRIPT_TAG: Executable script containers (<script>, <iframe>, <object>, <embed>)
- EVENT_HANDLER: Inline JavaScript triggers (onload=, onerror=, onclick=)
- PSEUDO_PROTOCOL: URI execution sinks (javascript:, vbscript:, data:text/html)
- DANGEROUS_CALL: Direct execution sinks (eval(), alert(), document.cookie)
"""

from __future__ import annotations

import enum
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


class LexerVerdict(str, enum.Enum):
    """Classification verdict from the fast-path lexer."""
    PASS = "PASS"             # Provably clean data literal (< 2ms fast exit)
    SUSPICIOUS = "SUSPICIOUS" # Ambiguous/edge-case syntax -> Forward to Neural Classifier
    BLOCK = "BLOCK"           # Overt, deterministically confirmed XSS vector


class LexerContext(str, enum.Enum):
    """Grammar contexts during tokenization."""
    DATA = "DATA"
    HTML_TAG = "HTML_TAG"
    SCRIPT_TAG = "SCRIPT_TAG"
    EVENT_HANDLER = "EVENT_HANDLER"
    PSEUDO_PROTOCOL = "PSEUDO_PROTOCOL"
    DANGEROUS_CALL = "DANGEROUS_CALL"


@dataclass
class LexerResult:
    """Detailed output of fast-path lexical inspection."""
    verdict: LexerVerdict
    tokens: List[str] = field(default_factory=list)
    contexts_detected: List[LexerContext] = field(default_factory=list)
    state_switch: bool = False
    latency_ms: float = 0.0
    reason: str = ""


class FastPathLexer:
    """
    Finite-State Automaton (FSM) Lexer for sub-millisecond XSS inspection.
    """

    # Pre-compiled high-velocity patterns
    SCRIPT_TAG_RE = re.compile(r"<\s*(?:/\s*)?(script|iframe|object|embed|applet|svg|style|meta)\b", re.IGNORECASE)
    EVENT_HANDLER_RE = re.compile(r"\bon[a-z]{3,20}\s*=", re.IGNORECASE)
    PSEUDO_PROTOCOL_RE = re.compile(r"(?:javascript|vbscript|data\s*:\s*text/html)\s*:", re.IGNORECASE)
    DANGEROUS_CALL_RE = re.compile(
        r"\b(?:eval|alert|prompt|confirm|Function|setTimeout|setInterval)\s*\(|"
        r"\b(?:document\.(?:cookie|location|write)|window\.location)\b",
        re.IGNORECASE
    )
    HTML_TAG_RE = re.compile(r"<\s*(?:/\s*)?[a-zA-Z][a-zA-Z0-9]*\b[^>]*>", re.IGNORECASE)

    # Heuristic for mathematical or harmless inequality expressions (e.g. 5 < 10)
    SAFE_INEQUALITY_RE = re.compile(r"^\s*[\d\w_]+\s*[<>]=?\s*[\d\w_]+(?:\s*(?:and|or|&&|\|\|)\s*[\d\w_]+\s*[<>]=?\s*[\d\w_]+)*\s*$", re.IGNORECASE)

    def __init__(self):
        pass

    def inspect(self, text: str) -> LexerResult:
        """
        Inspects normalized text with sub-millisecond execution.
        
        Args:
            text: Normalized input string from RecursiveNormalizer.
            
        Returns:
            LexerResult indicating PASS, SUSPICIOUS, or BLOCK.
        """
        start_time = time.perf_counter()

        if not text or not text.strip():
            latency = (time.perf_counter() - start_time) * 1000.0
            return LexerResult(
                verdict=LexerVerdict.PASS,
                tokens=[],
                contexts_detected=[LexerContext.DATA],
                state_switch=False,
                latency_ms=latency,
                reason="Empty or whitespace payload"
            )

        contexts: List[LexerContext] = []
        tokens: List[str] = []

        # 1. Check for safe mathematical expressions early
        if ("<" in text or ">" in text) and self.SAFE_INEQUALITY_RE.match(text):
            latency = (time.perf_counter() - start_time) * 1000.0
            return LexerResult(
                verdict=LexerVerdict.PASS,
                tokens=[text],
                contexts_detected=[LexerContext.DATA],
                state_switch=False,
                latency_ms=latency,
                reason="Safe mathematical inequality or logical comparison"
            )

        # 2. Fast check: If no '<', quotes, or colon exist, it's overwhelmingly clean data
        if not any(c in text for c in ("<", "\"", "'", "`", ":")):
            # Check for standalone dangerous calls e.g., document.cookie or alert(1)
            dangerous_match = self.DANGEROUS_CALL_RE.search(text)
            if not dangerous_match:
                latency = (time.perf_counter() - start_time) * 1000.0
                return LexerResult(
                    verdict=LexerVerdict.PASS,
                    tokens=[],
                    contexts_detected=[LexerContext.DATA],
                    state_switch=False,
                    latency_ms=latency,
                    reason="No structural HTML or execution delimiters present"
                )

        # 3. Context Evaluation: Script containers
        script_match = self.SCRIPT_TAG_RE.search(text)
        if script_match:
            contexts.append(LexerContext.SCRIPT_TAG)
            tokens.append(script_match.group(0))

        # 4. Context Evaluation: Inline event handlers (onload=, onerror=, etc.)
        event_matches = self.EVENT_HANDLER_RE.findall(text)
        if event_matches:
            contexts.append(LexerContext.EVENT_HANDLER)
            tokens.extend(event_matches)

        # 5. Context Evaluation: Pseudo-protocol execution sinks
        protocol_match = self.PSEUDO_PROTOCOL_RE.search(text)
        if protocol_match:
            contexts.append(LexerContext.PSEUDO_PROTOCOL)
            tokens.append(protocol_match.group(0))

        # 6. Context Evaluation: Dangerous JS functions / sinks
        dangerous_matches = self.DANGEROUS_CALL_RE.findall(text)
        if dangerous_matches:
            contexts.append(LexerContext.DANGEROUS_CALL)
            tokens.extend(dangerous_matches)

        # 7. Check for general HTML markup tags
        if not contexts and self.HTML_TAG_RE.search(text):
            contexts.append(LexerContext.HTML_TAG)

        # Determine Verdict
        has_state_switch = len(contexts) > 0

        if not has_state_switch:
            verdict = LexerVerdict.PASS
            reason = "No execution contexts or structural delimiters detected"
        else:
            # Deterministic BLOCK conditions:
            # - Explicit <script> tag with dangerous calls or payload content
            # - Tag with event handler AND dangerous call or executable body
            # - javascript: pseudo-protocol with execution call
            is_overt_script = LexerContext.SCRIPT_TAG in contexts and (
                LexerContext.DANGEROUS_CALL in contexts or "/" in text or "(" in text
            )
            is_overt_event = LexerContext.EVENT_HANDLER in contexts and (
                LexerContext.DANGEROUS_CALL in contexts or "(" in text or "=" in text
            )
            is_overt_protocol = LexerContext.PSEUDO_PROTOCOL in contexts

            if is_overt_script or is_overt_event or is_overt_protocol:
                verdict = LexerVerdict.BLOCK
                reason = f"Deterministic XSS syntax detected: {', '.join(t.value for t in contexts)}"
            else:
                # Ambiguous edge cases: Send to Deep Learning classifier
                verdict = LexerVerdict.SUSPICIOUS
                reason = f"Ambiguous markup or tokens detected ({', '.join(t.value for t in contexts)})"

        latency = (time.perf_counter() - start_time) * 1000.0

        return LexerResult(
            verdict=verdict,
            tokens=tokens,
            contexts_detected=contexts or [LexerContext.DATA],
            state_switch=has_state_switch,
            latency_ms=latency,
            reason=reason
        )


# Global default instance
_default_lexer = FastPathLexer()


def inspect_fast_path(text: str) -> LexerResult:
    """
    Convenience function to inspect normalized text using FastPathLexer.
    
    Args:
        text: Normalized input text.
        
    Returns:
        LexerResult with verdict and latency metrics.
    """
    return _default_lexer.inspect(text)
