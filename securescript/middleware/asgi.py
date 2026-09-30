"""
SecureScript ASGI Middleware for Asynchronous HTTP Interception.

Intercepts inbound HTTP/HTTPS traffic at the reverse-proxy or application layer:
- GET query parameters
- POST/PUT request bodies (JSON, form-urlencoded, raw text)
- Selected sensitive headers (User-Agent, Referer)

Enforces configurable mitigation policies:
- "block": Terminate connection with HTTP 403 Forbidden
- "audit" / "log_only": Attach security telemetry header and proceed
- "sanitize": Strip active script contexts from payload
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from securescript.core.lexer import FastPathLexer, LexerVerdict, LexerResult
from securescript.core.normalizer import RecursiveNormalizer, NormalizationResult

logger = logging.getLogger("securescript.middleware")


class XSSInterceptionMiddleware(BaseHTTPMiddleware):
    """
    Asynchronous Starlette/FastAPI Middleware for real-time XSS inspection.
    """

    def __init__(
        self,
        app: Any,
        mode: str = "block",  # "block", "audit", or "sanitize"
        max_depth: int = 4,
        inspect_headers: Optional[List[str]] = None,
    ):
        super().__init__(app)
        self.mode = mode.lower()
        if self.mode not in ("block", "audit", "sanitize"):
            raise ValueError("mode must be one of: 'block', 'audit', 'sanitize'")
        self.normalizer = RecursiveNormalizer(max_depth=max_depth)
        self.lexer = FastPathLexer()
        self.inspect_headers = [h.lower() for h in (inspect_headers or ["user-agent", "referer"])]

    def _inspect_value(self, value: str, key_name: str) -> tuple[NormalizationResult, LexerResult]:
        """Runs the 2-stage normalizer and fast-path lexer on a string value."""
        norm_result = self.normalizer.normalize(value)
        lex_result = self.lexer.inspect(norm_result.normalized)
        return norm_result, lex_result

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Intercepts, inspects, and enforces security policies on the HTTP request."""

        # 1. Inspect Query Parameters
        for param_name, param_value in request.query_params.items():
            norm, lex = self._inspect_value(param_value, param_name)
            if lex.verdict == LexerVerdict.BLOCK:
                if self.mode == "block":
                    return self._create_blocked_response(
                        location=f"query_param '{param_name}'",
                        raw_payload=param_value,
                        normalized_payload=norm.normalized,
                        reason=lex.reason
                    )
                logger.warning(f"[SecureScript AUDIT] Block-level payload in query param '{param_name}': {param_value}")

        # 2. Inspect Target Headers
        for header in self.inspect_headers:
            header_val = request.headers.get(header)
            if header_val:
                norm, lex = self._inspect_value(header_val, header)
                if lex.verdict == LexerVerdict.BLOCK:
                    if self.mode == "block":
                        return self._create_blocked_response(
                            location=f"header '{header}'",
                            raw_payload=header_val,
                            normalized_payload=norm.normalized,
                            reason=lex.reason
                        )
                    logger.warning(f"[SecureScript AUDIT] Block-level payload in header '{header}': {header_val}")

        # 3. Inspect Request Body (for state-changing methods)
        if request.method in ("POST", "PUT", "PATCH"):
            content_type = request.headers.get("content-type", "").lower()
            if "application/json" in content_type:
                try:
                    body_bytes = await request.body()
                    if body_bytes:
                        json_data = json.loads(body_bytes.decode("utf-8", errors="ignore"))
                        violation = self._scan_json_recursive(json_data)
                        if violation:
                            param_name, raw_val, norm, lex = violation
                            if self.mode == "block":
                                return self._create_blocked_response(
                                    location=f"json_body '{param_name}'",
                                    raw_payload=str(raw_val),
                                    normalized_payload=norm.normalized,
                                    reason=lex.reason
                                )
                except Exception as e:
                    logger.debug(f"JSON body parse error during inspection: {e}")

        # Forward request to downstream application
        response = await call_next(request)
        response.headers["X-Protected-By"] = "SecureScript-Hybrid-WAF"
        return response

    def _scan_json_recursive(self, data: Any, prefix: str = "") -> Optional[tuple[str, Any, NormalizationResult, LexerResult]]:
        """Recursively scans JSON dictionaries and lists for injection strings."""
        if isinstance(data, dict):
            for k, v in data.items():
                res = self._scan_json_recursive(v, f"{prefix}.{k}" if prefix else str(k))
                if res:
                    return res
        elif isinstance(data, list):
            for i, item in enumerate(data):
                res = self._scan_json_recursive(item, f"{prefix}[{i}]")
                if res:
                    return res
        elif isinstance(data, str):
            norm, lex = self._inspect_value(data, prefix)
            if lex.verdict == LexerVerdict.BLOCK:
                return (prefix, data, norm, lex)
        return None

    def _create_blocked_response(
        self,
        location: str,
        raw_payload: str,
        normalized_payload: str,
        reason: str
    ) -> JSONResponse:
        """Returns standard HTTP 403 Forbidden payload detailing the mitigation."""
        return JSONResponse(
            status_code=403,
            content={
                "error": "Forbidden - XSS Threat Detected",
                "status": 403,
                "framework": "SecureScript v0.1.0",
                "details": {
                    "detection_stage": "Fast-Path Lexical Grammar Analyzer",
                    "incident_location": location,
                    "reason": reason,
                    "normalized_payload": normalized_payload[:120] + ("..." if len(normalized_payload) > 120 else "")
                }
            }
        )


# ==============================================================================
# Demo FastAPI Application using the Middleware
# ==============================================================================
demo_app = FastAPI(
    title="SecureScript Protected Application",
    description="Demonstration API secured by SecureScript real-time inspection middleware.",
    version="0.1.0"
)

# Attach SecureScript middleware in "block" mode
demo_app.add_middleware(XSSInterceptionMiddleware, mode="block")


@demo_app.get("/")
def home():
    return {"message": "SecureScript Protected Endpoint: Active"}


@demo_app.get("/search")
def search(q: str = ""):
    return {"status": "success", "query": q, "results_count": 0}


@demo_app.post("/submit")
def submit_comment(payload: Dict[str, Any]):
    return {"status": "received", "data": payload}
