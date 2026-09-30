"""
SecureScript Recursive Normalization Engine.

Recursively decodes and neutralizes multi-pass obfuscations including:
- Multi-layer URL encoding (e.g., %2527 -> %27 -> ')
- HTML numeric and character entities (e.g., &quot;, &#x3C;, &#60;)
- Base64-encoded payload blocks and data URIs (e.g., data:text/html;base64,...)
- Unicode escape sequences (e.g., \\u003c, \\x3c)
- Full-width unicode homoglyphs via NFKC normalization
- Null bytes and zero-width non-printable characters

Enforces a strict recursion depth limit (k = 4) to ensure deterministic runtime
and prevent Denial-of-Service / catastrophic backtracking.
"""

from __future__ import annotations

import base64
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Set


@dataclass
class NormalizationResult:
    """Represents the output of the recursive normalization process."""
    original: str
    normalized: str
    iterations: int
    encodings_detected: List[str] = field(default_factory=list)
    is_modified: bool = False


class RecursiveNormalizer:
    """
    Multi-stage recursive de-obfuscation engine.
    
    Attributes:
        max_depth: Maximum recursion depth to prevent infinite loops (default k=4).
    """

    # Regex to detect Base64 data URIs
    DATA_URI_PATTERN = re.compile(
        r"data:[^,;]*?(?:;charset=[^,;]+)?(?:;base64)?,([A-Za-z0-9+/=]{4,})",
        re.IGNORECASE
    )

    # Regex for JavaScript hex escapes: \xHH
    HEX_ESCAPE_PATTERN = re.compile(r"\\x([0-9a-fA-F]{2})")

    # Regex for JavaScript unicode escapes: \uHHHH
    UNICODE_ESCAPE_PATTERN = re.compile(r"\\u([0-9a-fA-F]{4})")

    # Null bytes and control characters (excluding standard tabs and line breaks)
    NULL_CONTROL_PATTERN = re.compile(r"[\x00\x01-\x08\x0b\x0c\x0e-\x1f\x7f]")

    def __init__(self, max_depth: int = 4):
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        self.max_depth = max_depth

    def _strip_null_and_control(self, text: str) -> tuple[str, bool]:
        """Strips null bytes and non-printable control characters."""
        cleaned = self.NULL_CONTROL_PATTERN.sub("", text)
        return cleaned, cleaned != text

    def _decode_url(self, text: str) -> tuple[str, bool]:
        """Performs URL unquoting."""
        if "%" in text:
            decoded = urllib.parse.unquote(text)
            return decoded, decoded != text
        return text, False

    def _decode_html_entities(self, text: str) -> tuple[str, bool]:
        """Decodes standard and numerical HTML entities."""
        if "&" in text:
            decoded = html.unescape(text)
            return decoded, decoded != text
        return text, False

    def _decode_unicode_and_hex_escapes(self, text: str) -> tuple[str, bool]:
        """Decodes JS-style \\xHH and \\uHHHH sequences."""
        modified = False

        # Decode \xHH
        def replace_hex(match: re.Match) -> str:
            nonlocal modified
            try:
                char = chr(int(match.group(1), 16))
                modified = True
                return char
            except ValueError:
                return match.group(0)

        step1 = self.HEX_ESCAPE_PATTERN.sub(replace_hex, text)

        # Decode \uHHHH
        def replace_unicode(match: re.Match) -> str:
            nonlocal modified
            try:
                char = chr(int(match.group(1), 16))
                modified = True
                return char
            except ValueError:
                return match.group(0)

        step2 = self.UNICODE_ESCAPE_PATTERN.sub(replace_unicode, step1)
        return step2, modified

    def _decode_base64_data_uris(self, text: str) -> tuple[str, bool]:
        """Decodes Base64 payloads inside data: URIs."""
        modified = False

        def replace_data_uri(match: re.Match) -> str:
            nonlocal modified
            b64_content = match.group(1)
            try:
                # Add padding if required
                missing_padding = len(b64_content) % 4
                if missing_padding:
                    b64_content += "=" * (4 - missing_padding)
                
                decoded_bytes = base64.b64decode(b64_content, validate=True)
                # Attempt to decode as UTF-8 / ASCII text
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                
                # Check if decoded payload contains meaningful readable characters
                if decoded_str and any(c in decoded_str for c in "<>&\"'=/"):
                    modified = True
                    return decoded_str
            except Exception:
                pass
            return match.group(0)

        result = self.DATA_URI_PATTERN.sub(replace_data_uri, text)
        return result, modified

    def _normalize_unicode_compatibility(self, text: str) -> tuple[str, bool]:
        """
        Normalizes unicode compatibility characters (e.g. full-width ＜ to <).
        """
        normalized = unicodedata.normalize("NFKC", text)
        return normalized, normalized != text

    def normalize(self, text: str) -> NormalizationResult:
        """
        Recursively processes and de-obfuscates the input string up to max_depth.
        
        Args:
            text: Raw input payload or query string.
            
        Returns:
            NormalizationResult with canonical representation and metadata.
        """
        if not text:
            return NormalizationResult(original="", normalized="", iterations=0)

        current = text
        detected_encodings: Set[str] = set()
        iterations = 0

        for depth in range(1, self.max_depth + 1):
            iterations = depth
            previous = current

            # 1. Strip null bytes & control chars
            current, has_nulls = self._strip_null_and_control(current)
            if has_nulls:
                detected_encodings.add("null_bytes")

            # 2. Decode Unicode homoglyphs (NFKC)
            current, has_unicode_nfkc = self._normalize_unicode_compatibility(current)
            if has_unicode_nfkc:
                detected_encodings.add("unicode_homoglyphs")

            # 3. Decode URL encoding
            current, has_url = self._decode_url(current)
            if has_url:
                detected_encodings.add("url_encoding")

            # 4. Decode HTML numeric & named entities
            current, has_html = self._decode_html_entities(current)
            if has_html:
                detected_encodings.add("html_entities")

            # 5. Decode JS \\xHH and \\uHHHH escape sequences
            current, has_escapes = self._decode_unicode_and_hex_escapes(current)
            if has_escapes:
                detected_encodings.add("js_escapes")

            # 6. Decode Base64 data URIs
            current, has_b64 = self._decode_base64_data_uris(current)
            if has_b64:
                detected_encodings.add("base64_data_uri")

            # Convergence Check: If output hasn't changed this iteration, stop early
            if current == previous:
                # If convergence happened after the first pass, adjust iteration count
                if depth > 1:
                    iterations = depth - 1
                break

        return NormalizationResult(
            original=text,
            normalized=current,
            iterations=iterations,
            encodings_detected=sorted(list(detected_encodings)),
            is_modified=(current != text)
        )


# Global default instance
_default_normalizer = RecursiveNormalizer(max_depth=4)


def normalize(text: str, max_depth: int = 4) -> NormalizationResult:
    """
    Convenience function to normalize text using RecursiveNormalizer.
    
    Args:
        text: Untrusted string input.
        max_depth: Maximum recursion depth (default 4).
    """
    if max_depth == 4:
        return _default_normalizer.normalize(text)
    return RecursiveNormalizer(max_depth=max_depth).normalize(text)
