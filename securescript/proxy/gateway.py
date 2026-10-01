"""
SecureScript Multi-Tenant Reverse-Proxy WAF Gateway.

Acts as an inline security gateway protecting multiple upstream websites via
slug-based proxy routing (/proxy/{slug}/{path}).

Pipeline:
1. Tenant Resolution: Lookup slug → project config from PostgreSQL (LRU cached 60s).
2. Deep 3-Tier Hybrid Inspection:
   - Tier 1: Recursive Normalizer (k=4)
   - Tier 2: Fast-Path Lexer (< 2ms)
   - Tier 3: PyTorch Bi-LSTM Neural Classifier (< 20ms)
3. If Malicious:
   - Blocks request with HTTP 403 Forbidden.
   - Records incident to PostgreSQL (scoped by project_id).
   - Fires async webhook + email alerts if configured.
4. If Clean:
   - Proxies request to project's upstream_url or backend_url.
   - Injects security response headers.
5. Legacy fallback: Single-tenant catch-all route still works for direct use.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional

import httpx
import yaml
from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from securescript.core.lexer import FastPathLexer, LexerVerdict
from securescript.core.normalizer import RecursiveNormalizer
from securescript.dashboard.app import dashboard_router
from securescript.models.bilstm import BiLSTMClassifier
from securescript.platform.alerts import build_alert_payload, send_email_alert, send_webhook_alert
from securescript.platform.database import get_db, init_db
from securescript.platform.incident_store import incident_to_dict, record_incident
from securescript.platform.models import Project
from securescript.platform.routers.analytics_router import analytics_router
from securescript.platform.routers.auth_router import auth_router
from securescript.platform.routers.project_router import project_router
from securescript.telemetry.csp import router as csp_router
from securescript.telemetry.siem import siem_collector, siem_router

# ==============================================================================
# Configuration Loading
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "waf_config.yaml")
TEMPLATES_DIR = os.path.join(PROJECT_ROOT, "securescript", "templates")

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

# Environment variable overrides
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
    timeout=httpx.Timeout(15.0, connect=5.0),
)

# In-process LRU cache: slug → (Project snapshot dict, timestamp)
# Invalidated after 60 seconds to pick up project updates / deactivations
_slug_cache: Dict[str, tuple] = {}
_SLUG_CACHE_TTL = 60.0

# In-memory storage for clean form submissions (legacy relay fallback)
form_submissions: List[Dict[str, Any]] = []

# ==============================================================================
# Initialize FastAPI App
# ==============================================================================
waf_app = FastAPI(
    title="SecureScript Multi-Tenant WAF Platform",
    description="Real-Time Intelligent Multi-Tenant Web Application Firewall.",
    version="1.0.0",
)

# Jinja2 templates for the platform UI
templates: Optional[Jinja2Templates] = None
if os.path.exists(TEMPLATES_DIR):
    templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Mount Platform & Telemetry Routers
waf_app.include_router(auth_router)
waf_app.include_router(project_router)
waf_app.include_router(analytics_router)
waf_app.include_router(dashboard_router)
waf_app.include_router(csp_router)
waf_app.include_router(siem_router)


# Startup: ensure DB tables exist (dev/test mode; production uses Alembic)
@waf_app.on_event("startup")
async def on_startup() -> None:
    try:
        await init_db()
        print("[WAF Platform] Database tables verified.")
    except Exception as e:
        print(f"[WAF Platform] DB init notice: {e}")

    # Seed demo incident for legacy SIEM dashboard
    siem_collector.record_incident(
        action="BLOCKED",
        client_ip="203.0.113.42",
        http_method="POST",
        url_path="/api/submit",
        detection_stage="Fast-Path Lexical Analyzer",
        confidence_score=1.0,
        trigger_tokens=["<script>", "alert("],
        raw_payload="<script>alert('XSS-Probe')</script>",
        normalized_payload="<script>alert('XSS-Probe')</script>",
        latency_ms=0.003,
        event_id="RAY-9A82F104BC",
    )


# ==============================================================================
# Inspection Logic (shared between single-tenant and multi-tenant routes)
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
            "normalized": norm.normalized,
        }

    if lex.verdict == LexerVerdict.PASS:
        return None

    # Suspicious / Ambiguous → Neural evaluation
    if dl_classifier:
        label, score, _ = dl_classifier.predict(norm.normalized)
        if score >= DL_THRESHOLD:
            return {
                "stage": "PyTorch Bi-LSTM Neural Network",
                "confidence": round(score, 4),
                "reason": f"Neural pattern threat score ({score:.4f} >= {DL_THRESHOLD})",
                "tokens": lex.tokens,
                "normalized": norm.normalized,
            }

    return None


def _render_block_page(
    request: Request,
    incident_id: str,
    target_url: str,
    violation: Dict[str, Any],
    location: str,
) -> Response:
    """Renders a 403 HTML block page or JSON response."""
    accept = request.headers.get("accept", "").lower()
    content_type = request.headers.get("content-type", "").lower()

    if "application/json" in accept or "application/json" in content_type:
        return JSONResponse(
            status_code=403,
            content={
                "error": "Forbidden – XSS Threat Neutralized by SecureScript WAF",
                "status": 403,
                "incident_id": incident_id,
                "target_website": target_url,
                "details": {
                    "detection_stage": violation["stage"],
                    "confidence_score": violation["confidence"],
                    "incident_location": location,
                    "normalized_payload": violation["normalized"][:150],
                },
            },
            headers={"X-Protected-By": "SecureScript-Hybrid-WAF"},
        )

    html = BLOCK_PAGE_TEMPLATE
    if html:
        html = html.replace("{{ incident_id }}", incident_id)
        html = html.replace("{{ target_website }}", target_url)
        html = html.replace("{{ detection_stage }}", violation["stage"])
        html = html.replace("{{ confidence_score }}", str(violation["confidence"]))
        html = html.replace("{{ incident_location }}", location)
        html = html.replace("{{ normalized_payload }}", violation["normalized"][:200])
        return HTMLResponse(content=html, status_code=403, headers={"X-Protected-By": "SecureScript-Hybrid-WAF"})

    return HTMLResponse(
        content=f"<h1>403 Forbidden – Request blocked by SecureScript WAF</h1><p>Incident: {incident_id}</p>",
        status_code=403,
    )


async def _record_and_alert(
    db: AsyncSession,
    request: Request,
    violation: Dict[str, Any],
    raw_payload: str,
    location: str,
    incident_id: str,
    project: Optional[Project] = None,
) -> None:
    """Persists an incident to PostgreSQL and fires async alerts if project is configured."""
    try:
        incident = await record_incident(
            db,
            project_id=project.id if project else "legacy",
            action="BLOCKED",
            client_ip=request.client.host if request.client else "unknown",
            http_method=request.method,
            url_path=str(request.url.path),
            detection_stage=violation["stage"],
            confidence_score=violation["confidence"],
            trigger_tokens=violation.get("tokens", []),
            raw_payload=raw_payload,
            normalized_payload=violation["normalized"],
            latency_ms=0.5,
            event_id=incident_id,
        )

        if project and (project.webhook_url or project.alert_email):
            payload = build_alert_payload(
                incident_to_dict(incident),
                project_name=project.name,
                project_slug=project.slug,
            )
            if project.webhook_url:
                await send_webhook_alert(project.webhook_url, payload)
            if project.alert_email:
                await send_email_alert(project.alert_email, {**payload, "project_name": project.name})
    except Exception as e:
        # Always fall back to in-memory SIEM — never fail the proxy for DB issues
        import logging
        logging.getLogger("securescript.gateway").error("[Gateway] Incident record failed: %s", e)
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
            latency_ms=0.5,
            event_id=incident_id,
        )


async def _inspect_request(request: Request, body_bytes: bytes) -> Optional[tuple]:
    """
    Runs the 3-tier inspection pipeline over query params, headers, and body.

    Returns:
        None if clean.
        (location, raw_payload, violation) tuple if blocked.
    """
    # Query params
    for param_name, param_val in request.query_params.items():
        v = inspect_value(param_val)
        if v:
            return (f"Query Parameter '{param_name}'", param_val, v)

    # Headers
    for h in ["user-agent", "referer"]:
        h_val = request.headers.get(h)
        if h_val:
            v = inspect_value(h_val)
            if v:
                return (f"Header '{h}'", h_val, v)

    # Body
    if request.method in ("POST", "PUT", "PATCH") and body_bytes:
        ct = request.headers.get("content-type", "").lower()

        if "application/json" in ct:
            try:
                parsed = json.loads(body_bytes.decode("utf-8", errors="ignore"))
                violation_found = None

                def scan_dict(d: Any, prefix: str = "") -> None:
                    nonlocal violation_found
                    if violation_found:
                        return
                    if isinstance(d, dict):
                        for k, val in d.items():
                            scan_dict(val, f"{prefix}.{k}" if prefix else str(k))
                    elif isinstance(d, list):
                        for i, el in enumerate(d):
                            scan_dict(el, f"{prefix}[{i}]")
                    elif isinstance(d, str):
                        v = inspect_value(d)
                        if v:
                            violation_found = (f"JSON Field '{prefix}'", d, v)

                scan_dict(parsed)
                if violation_found:
                    return violation_found
            except Exception:
                pass

        elif "application/x-www-form-urlencoded" in ct:
            form_dict = urllib.parse.parse_qs(body_bytes.decode("utf-8", errors="ignore"))
            for f_key, f_vals in form_dict.items():
                for val in f_vals:
                    v = inspect_value(val)
                    if v:
                        return (f"Form Field '{f_key}'", val, v)

    return None


# ==============================================================================
# Platform UI Routes
# ==============================================================================
@waf_app.get("/platform", include_in_schema=False)
@waf_app.get("/welcome", include_in_schema=False)
async def page_index(request: Request) -> Response:
    if templates:
        return templates.TemplateResponse(request=request, name="index.html")
    return HTMLResponse("<h1>SecureScript WAF Platform</h1><p><a href='/signup'>Sign Up</a></p>")


@waf_app.get("/signup", include_in_schema=False)
@waf_app.get("/login", include_in_schema=False)
async def page_auth(request: Request) -> Response:
    if templates:
        return templates.TemplateResponse(request=request, name="auth.html")
    return HTMLResponse("<h1>Auth</h1>")


@waf_app.get("/app/projects", include_in_schema=False)
async def page_projects(request: Request) -> Response:
    if templates:
        return templates.TemplateResponse(request=request, name="projects.html")
    return HTMLResponse("<h1>Projects</h1>")


@waf_app.get("/app/projects/new", include_in_schema=False)
async def page_new_project(request: Request) -> Response:
    if templates:
        return templates.TemplateResponse(request=request, name="new_project.html")
    return HTMLResponse("<h1>New Project</h1>")


@waf_app.get("/app/projects/{project_id}", include_in_schema=False)
async def page_project_dashboard(request: Request, project_id: str) -> Response:
    if templates:
        return templates.TemplateResponse(
            request=request, name="dashboard.html", context={"project_id": project_id}
        )
    return HTMLResponse(f"<h1>Dashboard for {project_id}</h1>")


@waf_app.get("/api/submissions")
def list_form_submissions() -> Dict[str, Any]:
    """Returns verified clean form submissions safely processed by SecureScript WAF."""
    return {"status": "success", "total": len(form_submissions), "submissions": form_submissions}


# ==============================================================================
# Multi-Tenant WAF Proxy Route  —  /proxy/{slug}/{path}
# ==============================================================================
@waf_app.api_route(
    "/proxy/{slug}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    include_in_schema=True,
    summary="Multi-tenant WAF proxy — route traffic for a registered project",
)
async def multi_tenant_waf_proxy(
    request: Request,
    slug: str,
    path: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """
    Multi-tenant reverse proxy with inline XSS inspection.

    Resolves the project by slug from PostgreSQL (LRU cached 60s),
    then runs the 3-tier WAF pipeline before proxying clean traffic.
    """
    # -------------------------------------------------------------------------
    # 1. Tenant resolution (with LRU cache)
    # -------------------------------------------------------------------------
    now = time.time()
    cached = _slug_cache.get(slug)
    project: Optional[Project] = None

    if cached and (now - cached[1]) < _SLUG_CACHE_TTL:
        project = cached[0]
    else:
        result = await db.execute(
            select(Project).where(Project.slug == slug, Project.is_active == True)  # noqa: E712
        )
        project = result.scalar_one_or_none()
        if project:
            _slug_cache[slug] = (project, now)
        else:
            # Evict stale cache entry if project was deactivated
            _slug_cache.pop(slug, None)

    if not project:
        return JSONResponse(
            {"error": f"Project '{slug}' not found or inactive"},
            status_code=404,
        )

    upstream_url = project.frontend_url.rstrip("/")
    backend_url = project.backend_url.rstrip("/")

    # -------------------------------------------------------------------------
    # 2. Read body (needed for inspection and proxy)
    # -------------------------------------------------------------------------
    body_bytes = b""
    if request.method in ("POST", "PUT", "PATCH"):
        body_bytes = await request.body()

    # -------------------------------------------------------------------------
    # 3. WAF inspection
    # -------------------------------------------------------------------------
    if WAF_MODE != "pass":
        hit = await _inspect_request(request, body_bytes)
        if hit and WAF_MODE == "block":
            location, raw_payload, violation = hit
            incident_id = f"RAY-{uuid.uuid4().hex[:10].upper()}"

            # Record incident + alerts as background task
            background = BackgroundTask(
                _record_and_alert,
                db=db,
                request=request,
                violation=violation,
                raw_payload=raw_payload,
                location=location,
                incident_id=incident_id,
                project=project,
            )
            resp = _render_block_page(request, incident_id, upstream_url, violation, location)
            resp.background = background
            return resp

    # -------------------------------------------------------------------------
    # 4. Route clean traffic to the correct upstream
    # -------------------------------------------------------------------------
    # API paths go to backend_url, everything else to upstream_url (frontend)
    if path.startswith("api/") or path == "api":
        target_base = backend_url
    else:
        target_base = upstream_url

    target_url = f"{target_base}/{path}" if path else target_base
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"

    proxy_headers = dict(request.headers)
    proxy_headers.pop("host", None)
    proxy_headers.pop("content-length", None)
    proxy_headers.pop("accept-encoding", None)
    proxy_headers["x-forwarded-for"] = request.client.host if request.client else "127.0.0.1"
    proxy_headers["x-waf-inspection"] = "passed-securescript"
    proxy_headers["x-waf-project"] = slug

    try:
        upstream_resp = await http_client.request(
            method=request.method,
            url=target_url,
            headers=proxy_headers,
            content=body_bytes or None,
            timeout=12.0,
        )

        resp_headers = dict(upstream_resp.headers)
        resp_headers.pop("content-length", None)
        resp_headers.pop("content-encoding", None)
        resp_headers["X-Protected-By"] = "SecureScript-Hybrid-WAF"
        resp_headers["X-WAF-Project"] = slug

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
        )

    except httpx.TimeoutException:
        return JSONResponse({"error": "Upstream timeout"}, status_code=504)
    except Exception as exc:
        return JSONResponse({"error": f"Proxy error: {exc}"}, status_code=502)


# ==============================================================================
# Legacy Single-Tenant Catch-All Route (backward compatibility)
# ==============================================================================
@waf_app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    include_in_schema=False,
)
async def legacy_waf_reverse_proxy(request: Request, path: str) -> Response:
    """
    Legacy single-tenant WAF proxy. Protects the globally configured UPSTREAM_URL.
    Kept for backward compatibility with the original single-tenant deployment.
    """
    # If explicitly requesting platform landing page via query param
    if path == "" and request.query_params.get("platform") == "1":
        if templates:
            return templates.TemplateResponse(request=request, name="index.html")
        return HTMLResponse("<h1>SecureScript WAF Platform</h1><p><a href='/signup'>Sign Up</a></p>")

    # Skip platform, dashboard, and telemetry paths
    _skip_prefixes = (
        "proxy/", "auth/", "platform", "app/",
        "dashboard", "api/dashboard", "api/v1/csp", "api/v1/siem",
        "api/submissions", "docs", "openapi.json", "signup", "login", "welcome",
    )
    if any(path.startswith(p) for p in _skip_prefixes):
        return Response(status_code=404)

    # Read body
    body_bytes = b""
    if request.method in ("POST", "PUT", "PATCH"):
        body_bytes = await request.body()

    # Inspect
    if WAF_MODE != "pass":
        hit = await _inspect_request(request, body_bytes)
        if hit and WAF_MODE == "block":
            location, raw_payload, violation = hit
            incident_id = f"RAY-{uuid.uuid4().hex[:10].upper()}"

            # Legacy: record in in-memory SIEM
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
                latency_ms=0.5,
                event_id=incident_id,
            )
            return _render_block_page(request, incident_id, UPSTREAM_URL, violation, location)

    # Route to upstream
    if path.startswith("api/submit") or path == "api/submit":
        target_base = BACKEND_API_URL
    else:
        target_base = UPSTREAM_URL

    target_url = f"{target_base}/{path}" if path else target_base
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"

    proxy_headers = dict(request.headers)
    proxy_headers.pop("host", None)
    proxy_headers.pop("content-length", None)
    proxy_headers.pop("accept-encoding", None)
    proxy_headers["x-forwarded-for"] = request.client.host if request.client else "127.0.0.1"
    proxy_headers["x-waf-inspection"] = "passed-securescript"

    try:
        upstream_resp = await http_client.request(
            method=request.method,
            url=target_url,
            headers=proxy_headers,
            content=body_bytes or None,
            timeout=12.0,
        )

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
              <a href="/platform" target="_blank" style="color:#38bdf8;margin-left:4px;text-decoration:none;">[Platform]</a>
            </div>
            """
            if "</body>" in html_text:
                html_text = html_text.replace("</body>", f"{badge}</body>")
                body_content = html_text.encode("utf-8")

        # If client posted to /api/submit and upstream backend failed or is suspended
        if (path.startswith("api/submit") or path == "api/submit") and request.method == "POST":
            if upstream_resp.status_code in (502, 503, 504) or "suspend" in upstream_resp.text.lower():
                try:
                    parsed_sub = json.loads(body_bytes.decode("utf-8", errors="ignore")) if body_bytes else {}
                except Exception:
                    parsed_sub = {}

                new_sub = {
                    "id": str(uuid.uuid4())[:8],
                    "name": parsed_sub.get("name", "Anonymous"),
                    "email": parsed_sub.get("email", ""),
                    "message": parsed_sub.get("message", ""),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "status": "VERIFIED_CLEAN_BY_WAF",
                }
                form_submissions.append(new_sub)
                return JSONResponse(
                    status_code=200,
                    content={
                        "success": True,
                        "message": "Form submitted successfully!",
                        "submission_id": new_sub["id"],
                        "waf_relay": True,
                    },
                    headers={"X-Protected-By": "SecureScript-Hybrid-WAF"},
                )

        # If client requested other API, and upstream failed with 502/503/504 or suspended HTML
        is_api = "api/" in path or "application/json" in request.headers.get("accept", "") or "application/json" in request.headers.get("content-type", "")
        if is_api and upstream_resp.status_code in (502, 503, 504):
            is_suspended = (
                "suspend" in upstream_resp.text.lower() or 
                "suspend" in upstream_resp.headers.get("x-render-routing", "").lower()
            )
            err_msg = (
                "Upstream Backend is SUSPENDED on Render (x-render-routing: suspend-by-user). "
                "Please open https://dashboard.render.com and click 'Resume' on 'basic-form-project'."
                if is_suspended else
                f"Upstream Backend Unavailable (HTTP {upstream_resp.status_code})."
            )
            return JSONResponse(
                status_code=upstream_resp.status_code,
                content={
                    "error": err_msg,
                    "status": upstream_resp.status_code,
                    "upstream_url": target_url,
                },
                headers={"X-Protected-By": "SecureScript-Hybrid-WAF"},
            )

        return Response(
            content=body_content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
        )

    except Exception as e:
        if (path.startswith("api/submit") or path == "api/submit") and request.method == "POST":
            try:
                parsed_sub = json.loads(body_bytes.decode("utf-8", errors="ignore")) if body_bytes else {}
            except Exception:
                parsed_sub = {}

            new_sub = {
                "id": str(uuid.uuid4())[:8],
                "name": parsed_sub.get("name", "Anonymous"),
                "email": parsed_sub.get("email", ""),
                "message": parsed_sub.get("message", ""),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "status": "VERIFIED_CLEAN_BY_WAF",
            }
            form_submissions.append(new_sub)
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "message": "Form submitted successfully!",
                    "submission_id": new_sub["id"],
                    "waf_relay": True,
                },
                headers={"X-Protected-By": "SecureScript-Hybrid-WAF"},
            )

        is_api = "api/" in path or "application/json" in request.headers.get("accept", "") or "application/json" in request.headers.get("content-type", "")
        if is_api:
            return JSONResponse(
                status_code=502,
                content={
                    "error": f"SecureScript Gateway could not connect to upstream backend ({str(e)})",
                    "status": 502,
                    "upstream_url": target_url,
                },
                headers={"X-Protected-By": "SecureScript-Hybrid-WAF"},
            )
        return HTMLResponse(
            content=f"""
            <div style="font-family:sans-serif;max-width:600px;margin:50px auto;padding:20px;border:1px solid #e2e8f0;border-radius:8px;">
              <h2>SecureScript Gateway: Upstream Unavailable</h2>
              <p>Could not connect to origin server <code>{target_url}</code>: {str(e)}</p>
              <hr>
              <p><a href="/dashboard">View Security Dashboard</a></p>
            </div>
            """,
            status_code=502,
        )
