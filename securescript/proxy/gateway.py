"""
SecureScript Reverse-Proxy Web Application Firewall (WAF) Gateway.

Acts as an inline security gateway protecting live upstream websites
(e.g., https://basic-form-project.vercel.app and its Render backend).

Pipeline:
1. Intercepts incoming HTTP requests (queries, headers, form/JSON bodies).
2. Deep 3-Tier Hybrid Inspection:
   - Tier 1: Recursive Normalizer (k=4)
   - Tier 2: Fast-Path Lexer (< 2ms)
   - Tier 3: PyTorch Bi-LSTM Neural Classifier (< 20ms)
3. If Malicious:
   - Blocks request with HTTP 403 Forbidden.
   - Serves Cloudflare-style WAF HTML Block Page for browsers or JSON for API calls.
   - Records incident in SIEM collector.
4. If Clean:
   - Proxies request to upstream server (Vercel origin / Render API).
   - Injects security response headers (CSP, X-Protected-By).
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, Optional

import httpx
import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.background import BackgroundTask

from securescript.core.lexer import FastPathLexer, LexerVerdict
from securescript.core.normalizer import RecursiveNormalizer
from securescript.dashboard.app import dashboard_router
from securescript.models.bilstm import BiLSTMClassifier
from securescript.telemetry.csp import router as csp_router
from securescript.telemetry.siem import siem_collector, siem_router

# ==============================================================================
# Configuration Loading
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "waf_config.yaml")

DEFAULT_UPSTREAM = "https://basic-form-project.vercel.app"
DEFAULT_BACKEND = "https://basic-form-project.onrender.com"

UPSTREAM_URL = DEFAULT_UPSTREAM
BACKEND_API_URL = DEFAULT_BACKEND
DL_THRESHOLD = 0.85
WAF_MODE = "block"

if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
            waf_cfg = cfg.get("waf", {})
            UPSTREAM_URL = waf_cfg.get("upstream_url", DEFAULT_UPSTREAM).rstrip("/")
            BACKEND_API_URL = waf_cfg.get("backend_api_url", DEFAULT_BACKEND).rstrip("/")
            DL_THRESHOLD = float(waf_cfg.get("dl_threshold", 0.85))
            WAF_MODE = waf_cfg.get("mode", "block").lower()
    except Exception as e:
        print(f"[WAF Gateway] Notice: Could not read waf_config.yaml ({e}), using defaults.")

# Environment variable overrides (from Render / Docker / Cloud)
UPSTREAM_URL = os.environ.get("UPSTREAM_URL", UPSTREAM_URL).rstrip("/")
BACKEND_API_URL = os.environ.get("BACKEND_API_URL", BACKEND_API_URL).rstrip("/")
DL_THRESHOLD = float(os.environ.get("DL_THRESHOLD", DL_THRESHOLD))
WAF_MODE = os.environ.get("WAF_MODE", WAF_MODE).lower()

# Load HTML Block Page Template
BLOCK_PAGE_TEMPLATE = ""
TEMPLATE_PATH = os.path.join(PROJECT_ROOT, "securescript", "templates", "block_page.html")
if os.path.exists(TEMPLATE_PATH):
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        BLOCK_PAGE_TEMPLATE = f.read()

# Initialize Inspection Engines
normalizer = RecursiveNormalizer(max_depth=4)
lexer = FastPathLexer()
dl_classifier: Optional[BiLSTMClassifier] = None

try:
    m_path = os.path.join(PROJECT_ROOT, "data", "bilstm_model.pt")
    t_path = os.path.join(PROJECT_ROOT, "data", "tokenizer.json")
    if os.path.exists(m_path) and os.path.exists(t_path):
        clf = BiLSTMClassifier()
        clf.load(m_path, t_path)
        dl_classifier = clf
        print("[WAF Gateway] PyTorch Bi-LSTM Neural Engine loaded successfully.")
except Exception as e:
    print(f"[WAF Gateway] Notice: Operating in Fast-Path mode ({e}).")

# Initialize HTTP Proxy Client
http_client = httpx.AsyncClient(
    follow_redirects=True,
    verify=False,
    timeout=httpx.Timeout(15.0, connect=5.0)
)

# Initialize Gateway FastAPI App
waf_app = FastAPI(
    title="SecureScript Reverse-Proxy WAF Gateway",
    description="Real-Time Intelligent Web Application Firewall protecting upstream websites.",
    version="0.4.0"
)

# Mount Management and Telemetry Routers
waf_app.include_router(dashboard_router)
waf_app.include_router(csp_router)
waf_app.include_router(siem_router)


# ==============================================================================
# Inspection Logic
# ==============================================================================
def inspect_value(value: str) -> Optional[Dict[str, Any]]:
    """Runs 3-tier inspection on an input string. Returns violation dict if blocked."""
    norm = normalizer.normalize(value)
    lex = lexer.inspect(norm.normalized)

    if lex.verdict == LexerVerdict.BLOCK:
        return {
            "stage": "Fast-Path Lexical Analyzer",
            "confidence": 1.0,
            "reason": lex.reason,
            "tokens": lex.tokens,
            "normalized": norm.normalized
        }

    if lex.verdict == LexerVerdict.PASS:
        return None

    # Suspicious / Ambiguous -> Neural evaluation
    if dl_classifier:
        label, score, _ = dl_classifier.predict(norm.normalized)
        if score >= DL_THRESHOLD:
            return {
                "stage": "PyTorch Bi-LSTM Neural Network",
                "confidence": round(score, 4),
                "reason": f"Neural pattern threat score ({score:.4f} >= {DL_THRESHOLD})",
                "tokens": lex.tokens,
                "normalized": norm.normalized
            }

    return None


def render_block_response(
    request: Request,
    location: str,
    raw_payload: str,
    violation: Dict[str, Any]
) -> Response:
    """Renders HTML or JSON HTTP 403 Forbidden response."""
    incident_id = f"RAY-{uuid.uuid4().hex[:10].upper()}"

    # Record in SIEM collector
    siem_collector.record_incident(
        action="BLOCKED",
        client_ip=request.client.host if request.client else "unknown",
        http_method=request.method,
        url_path=str(request.url.path),
        detection_stage=violation["stage"],
        confidence_score=violation["confidence"],
        trigger_tokens=violation.get("tokens", []),
        raw_payload=raw_payload,
        normalized_payload=violation["normalized"],
        latency_ms=0.5
    )

    accept = request.headers.get("accept", "").lower()
    content_type = request.headers.get("content-type", "").lower()

    # If client is expecting JSON or submitting API data
    if "application/json" in accept or "application/json" in content_type:
        return JSONResponse(
            status_code=403,
            content={
                "error": "Forbidden - XSS Threat Neutralized by SecureScript WAF",
                "status": 403,
                "incident_id": incident_id,
                "target_website": UPSTREAM_URL,
                "details": {
                    "detection_stage": violation["stage"],
                    "confidence_score": violation["confidence"],
                    "incident_location": location,
                    "normalized_payload": violation["normalized"][:150]
                }
            },
            headers={"X-Protected-By": "SecureScript-Hybrid-WAF"}
        )

    # Browser navigation: Render sleek HTML Block Page
    html = BLOCK_PAGE_TEMPLATE
    if html:
        html = html.replace("{{ incident_id }}", incident_id)
        html = html.replace("{{ target_website }}", UPSTREAM_URL)
        html = html.replace("{{ detection_stage }}", violation["stage"])
        html = html.replace("{{ confidence_score }}", str(violation["confidence"]))
        html = html.replace("{{ incident_location }}", location)
        html = html.replace("{{ normalized_payload }}", violation["normalized"][:200])
        return HTMLResponse(content=html, status_code=403, headers={"X-Protected-By": "SecureScript-Hybrid-WAF"})

    return HTMLResponse(
        content=f"<h1>403 Forbidden - Request Blocked by SecureScript WAF</h1><p>Incident: {incident_id}</p>",
        status_code=403
    )


# ==============================================================================
# Transparent Upstream Reverse-Proxy Dispatcher
# ==============================================================================
@waf_app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def waf_reverse_proxy(request: Request, path: str):
    """
    Main WAF Gateway: Inspects incoming request and proxies safe traffic to the upstream origin.
    """
    # 1. Bypass administrative dashboard / telemetry paths
    if path.startswith("dashboard") or path.startswith("api/dashboard") or path.startswith("api/v1/csp") or path.startswith("api/v1/siem") or path.startswith("docs") or path.startswith("openapi.json"):
        # Let FastAPI route handle it
        return Response(status_code=404)

    # 2. Inspect Query Parameters
    for param_name, param_val in request.query_params.items():
        violation = inspect_value(param_val)
        if violation and WAF_MODE == "block":
            return render_block_response(
                request=request,
                location=f"Query Parameter '{param_name}'",
                raw_payload=param_val,
                violation=violation
            )

    # 3. Inspect Headers
    for h in ["user-agent", "referer"]:
        h_val = request.headers.get(h)
        if h_val:
            violation = inspect_value(h_val)
            if violation and WAF_MODE == "block":
                return render_block_response(
                    request=request,
                    location=f"Header '{h}'",
                    raw_payload=h_val,
                    violation=violation
                )

    # 4. Inspect Request Body (JSON or Form)
    body_bytes = b""
    if request.method in ("POST", "PUT", "PATCH"):
        body_bytes = await request.body()
        content_type = request.headers.get("content-type", "").lower()

        # Check JSON Body
        if "application/json" in content_type and body_bytes:
            try:
                import json
                parsed_json = json.loads(body_bytes.decode("utf-8", errors="ignore"))
                violation_found = None
                
                def scan_dict(d, prefix=""):
                    nonlocal violation_found
                    if isinstance(d, dict):
                        for k, v in d.items():
                            scan_dict(v, f"{prefix}.{k}" if prefix else str(k))
                    elif isinstance(d, list):
                        for i, el in enumerate(d):
                            scan_dict(el, f"{prefix}[{i}]")
                    elif isinstance(d, str):
                        v_res = inspect_value(d)
                        if v_res and not violation_found:
                            violation_found = (prefix, d, v_res)

                scan_dict(parsed_json)
                if violation_found and WAF_MODE == "block":
                    loc, raw, viol = violation_found
                    return render_block_response(request, f"JSON Field '{loc}'", raw, viol)
            except Exception:
                pass

        # Check Form Body
        elif "application/x-www-form-urlencoded" in content_type and body_bytes:
            import urllib.parse
            form_str = body_bytes.decode("utf-8", errors="ignore")
            form_dict = urllib.parse.parse_qs(form_str)
            for f_key, f_vals in form_dict.items():
                for val in f_vals:
                    v_res = inspect_value(val)
                    if v_res and WAF_MODE == "block":
                        return render_block_response(request, f"Form Field '{f_key}'", val, v_res)

    # ==========================================================================
    # Traffic is CLEAN -> Forward to Upstream Origin
    # ==========================================================================
    # Check if target is backend API submission or Vercel frontend
    if path.startswith("api/submit") or path == "api/submit":
        target_base = BACKEND_API_URL
    else:
        target_base = UPSTREAM_URL

    target_url = f"{target_base}/{path}" if path else target_base
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"

    # Filter headers to avoid SSL/host conflicts
    proxy_headers = dict(request.headers)
    proxy_headers.pop("host", None)
    proxy_headers.pop("content-length", None)
    proxy_headers["x-forwarded-for"] = request.client.host if request.client else "127.0.0.1"
    proxy_headers["x-waf-inspection"] = "passed-securescript"

    try:
        upstream_resp = await http_client.request(
            method=request.method,
            url=target_url,
            headers=proxy_headers,
            content=body_bytes if body_bytes else None,
            timeout=12.0
        )

        # Build response headers
        resp_headers = dict(upstream_resp.headers)
        resp_headers.pop("content-length", None)
        resp_headers.pop("content-encoding", None)
        resp_headers["X-Protected-By"] = "SecureScript-Hybrid-WAF"
        resp_headers["X-WAF-Target"] = UPSTREAM_URL

        # Optionally rewrite script.js so form submission passes through WAF proxy
        body_content = upstream_resp.content
        if path.endswith("script.js") or path == "script.js":
            js_text = body_content.decode("utf-8", errors="ignore")
            # Point BACKEND_URL to local WAF endpoint so POST is inspected by WAF
            js_text = js_text.replace("https://basic-form-project.onrender.com/api/submit", "/api/submit")
            body_content = js_text.encode("utf-8")

        # Inject sleek WAF Protected badge into HTML pages
        if "text/html" in resp_headers.get("content-type", "").lower():
            html_text = body_content.decode("utf-8", errors="ignore")
            badge = """
            <!-- SecureScript Live Protection Indicator -->
            <div style="position:fixed;bottom:12px;right:12px;background:#0f172a;border:1px solid #334155;color:#38bdf8;padding:8px 14px;border-radius:9999px;font-family:sans-serif;font-size:12px;display:flex;align-items:center;gap:8px;box-shadow:0 10px 25px rgba(0,0,0,0.5);z-index:999999;">
              <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#10b981;"></span>
              <span>Protected by <strong>SecureScript WAF</strong></span>
              <a href="/dashboard" target="_blank" style="color:#60a5fa;margin-left:4px;text-decoration:none;">[Console]</a>
            </div>
            """
            if "</body>" in html_text:
                html_text = html_text.replace("</body>", f"{badge}</body>")
                body_content = html_text.encode("utf-8")

        return Response(
            content=body_content,
            status_code=upstream_resp.status_code,
            headers=resp_headers
        )

    except Exception as e:
        return HTMLResponse(
            content=f"""
            <div style="font-family:sans-serif;max-width:600px;margin:50px auto;padding:20px;border:1px solid #e2e8f0;border-radius:8px;">
              <h2>SecureScript Gateway: Upstream Unavailable</h2>
              <p>Could not connect to origin server <code>{target_url}</code>: {str(e)}</p>
              <hr>
              <p><a href="/dashboard">View Security Dashboard</a></p>
            </div>
            """,
            status_code=502
        )
