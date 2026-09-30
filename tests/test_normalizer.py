"""
Unit tests for SecureScript Recursive Normalization Engine.
"""

import pytest
from securescript.core.normalizer import RecursiveNormalizer, normalize


class TestRecursiveNormalizer:

    def setup_method(self):
        self.normalizer = RecursiveNormalizer(max_depth=4)

    def test_benign_plain_text(self):
        """Plain benign input should pass through unchanged."""
        text = "Hello world! This is a simple query parameter."
        result = self.normalizer.normalize(text)
        assert result.normalized == text
        assert not result.is_modified
        assert result.iterations == 1
        assert len(result.encodings_detected) == 0

    def test_single_url_encoding(self):
        """Standard single URL encoding is decoded in 1 pass."""
        payload = "%3Cscript%3Ealert(1)%3C/script%3E"
        expected = "<script>alert(1)</script>"
        result = self.normalizer.normalize(payload)
        assert result.normalized == expected
        assert result.is_modified
        assert "url_encoding" in result.encodings_detected

    def test_double_url_encoding(self):
        """Double-layer URL encoding should resolve to plaintext."""
        payload = "%253Cscript%253E"  # %25 -> % -> %3C -> <
        expected = "<script>"
        result = self.normalizer.normalize(payload)
        assert result.normalized == expected
        assert result.iterations >= 2
        assert "url_encoding" in result.encodings_detected

    def test_triple_url_encoding(self):
        """Triple nested URL encoding should resolve to plaintext."""
        payload = "%25253Cscript%25253E"
        expected = "<script>"
        result = self.normalizer.normalize(payload)
        assert result.normalized == expected
        assert result.iterations >= 3
        assert "url_encoding" in result.encodings_detected

    def test_html_named_entities(self):
        """HTML named entities (&lt;, &gt;, &quot;) should decode properly."""
        payload = "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"
        expected = '<script>alert("xss")</script>'
        result = self.normalizer.normalize(payload)
        assert result.normalized == expected
        assert "html_entities" in result.encodings_detected

    def test_html_numeric_and_hex_entities(self):
        """Decimal and hexadecimal numeric character references decode properly."""
        payload = "&#60;script&#62;&#x61;&#x6c;&#x65;&#x72;&#x74;(1)&#60;/script&#62;"
        expected = "<script>alert(1)</script>"
        result = self.normalizer.normalize(payload)
        assert result.normalized == expected
        assert "html_entities" in result.encodings_detected

    def test_unicode_and_hex_escapes(self):
        """JavaScript-style \\uHHHH and \\xHH escapes are decoded."""
        payload = r"\x3c\x73\x63\x72\x69\x70\x74\x3e\u0061\u006c\u0065\u0072\u0074(1)\x3c/\x73\x63\x72\x69\x70\x74\x3e"
        expected = "<script>alert(1)</script>"
        result = self.normalizer.normalize(payload)
        assert result.normalized == expected
        assert "js_escapes" in result.encodings_detected

    def test_unicode_fullwidth_homoglyphs(self):
        """NFKC normalization should map full-width brackets to standard brackets."""
        payload = "＜img src=x onerror=alert(1)＞"
        expected = "<img src=x onerror=alert(1)>"
        result = self.normalizer.normalize(payload)
        assert result.normalized == expected
        assert "unicode_homoglyphs" in result.encodings_detected

    def test_null_byte_stripping(self):
        """Null bytes intended to bypass naive WAF filters are stripped."""
        payload = "<scr\x00ipt>ale\x00rt(1)</scr\x00ipt>"
        expected = "<script>alert(1)</script>"
        result = self.normalizer.normalize(payload)
        assert result.normalized == expected
        assert "null_bytes" in result.encodings_detected

    def test_base64_data_uri_decoding(self):
        """Base64 payloads inside data URIs should be extracted and decoded."""
        # PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== decodes to <script>alert(1)</script>
        payload = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
        expected = "<script>alert(1)</script>"
        result = self.normalizer.normalize(payload)
        assert result.normalized == expected
        assert "base64_data_uri" in result.encodings_detected

    def test_mixed_nested_polyglot(self):
        """Tests mixed encodings: URL encoding wrapping HTML entities."""
        # %26%23x3c%3B decodes via URL to &#x3c; which decodes via HTML to <
        payload = "%26%23x3c%3Bscript%26%23x3e%3B"
        expected = "<script>"
        result = self.normalizer.normalize(payload)
        assert result.normalized == expected
        assert "url_encoding" in result.encodings_detected
        assert "html_entities" in result.encodings_detected

    def test_max_depth_enforcement(self):
        """Enforces that recursion never exceeds max_depth (k=4)."""
        normalizer_depth_2 = RecursiveNormalizer(max_depth=2)
        # 4 layers of URL encoding: %2525253C -> %25253C -> %253C -> %3C -> <
        payload = "%2525253C"
        result = normalizer_depth_2.normalize(payload)
        assert result.iterations <= 2
        # After 2 iterations, should be %253C, not fully resolved to <
        assert result.normalized == "%253C"

    def test_empty_string(self):
        """Gracefully handle empty input."""
        result = normalize("")
        assert result.normalized == ""
        assert result.iterations == 0
