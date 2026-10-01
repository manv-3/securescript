# AGENT.md: Autonomous Operating Manual for SecureScript

> **Note for AI Agents & Developers:**  
> This file is the primary context and operating protocol for any AI agent working on the **SecureScript** codebase. Always consult this document before initiating new features, modifying pipeline components, or refactoring existing modules.

---

## 1. Project Context & Objectives

* **Project Name:** SecureScript: Multi-Tenant SaaS Web Application Firewall Platform
* **Sponsorship / Context:** HCL Internship Program (September–October 2026)
* **Core Problem:** Traditional WAFs rely on brittle regular expressions that produce high false positives ($> 5\%$) and fail against polyglot and recursively encoded payloads. Conversely, deep learning models applied uniformly across all web traffic introduce unacceptable latency overhead ($> 50\,\text{ms}$).
* **Solution Architecture:** A **hybrid tiered pipeline**:
  1. Multi-pass **Recursive Normalization Engine** ($k=4$).
  2. Sub-millisecond **Fast-Path Lexical State Parser** ($< 2\,\text{ms}$) that instantly passes obvious benign traffic.
  3. **PyTorch Bi-LSTM Classifier** ($< 20\,\text{ms}$) evaluating only ambiguous/suspicious edge cases.
  4. Asynchronous **ASGI Middleware** (FastAPI) providing automated `PASS`, `AUDIT`, or `BLOCK (HTTP 403)` verdicts.
  5. Ingestion of client-side **W3C Content Security Policy (CSP)** telemetry to correlate DOM-based XSS attacks.

---

## 2. 48-Hour Sprint Status & Tracking

### Phase 1: Deterministic Engine & Proxy Middleware (Day 1) — **COMPLETED**
- [x] Create project structure, `README.md`, and `AGENT.md`.
- [x] Implement `securescript.core.normalizer` (recursive decoding, $k=4$, URL/HTML/Base64/Unicode).
- [x] Implement `securescript.core.lexer` (AST & Finite-State Automaton context transition detector).
- [x] Build unit test suite `tests/test_normalizer.py` and `tests/test_lexer.py`.
- [x] Benchmark Fast-Path Latency (Verify $< 2\,\text{ms}$ SLA).
- [x] Implement `securescript.middleware.asgi` (FastAPI/Starlette request interception).
- [x] Train baseline TF-IDF + Logistic Regression benchmark model.

### Phase 2: Neural Inference, CSP Telemetry & Operations Dashboard (Day 2) — **COMPLETED**
- [x] Build character/subword tokenizer in `securescript.models.tokenizer`.
- [x] Implement & train PyTorch Bi-LSTM classifier in `securescript.models.bilstm`.
- [x] Export model to TorchScript / checkpoint for low-latency CPU inference ($< 20\,\text{ms}$, achieved $0.57\,\text{ms}$).
- [x] Wire hybrid dispatch switch in `securescript.middleware.asgi`.
- [x] Implement W3C CSP violation reporting endpoint in `securescript.telemetry.csp`.
- [x] Construct real-time security dashboard in `securescript.dashboard.app`.
- [x] End-to-end integration and penetration testing against polyglots and OWASP vectors (45/45 tests passing).

### Phase 3: Explainability, Adversarial Benchmark & Containerization (Day 3) — **COMPLETED**
- [x] Implement Model Explainability & Token Attribution in `securescript.models.attribution` (Gradient Saliency).
- [x] Trace and compile PyTorch Bi-LSTM to TorchScript in `securescript.models.export` (`data/bilstm_traced.pt`).
- [x] Build Adversarial Polyglot & Evasion Benchmark Suite in `securescript.core.adversarial` (100% recall, 0% FPR).
- [x] Containerize full stack with `Dockerfile` and `docker-compose.yml`.
- [x] Expand automated regression test suite to 51/51 tests passing (`tests/test_attribution.py`, `tests/test_adversarial.py`).

### Phase 4: Full-Stack Verification, Penetration Testing, SIEM & Delivery (Day 4) — **COMPLETED**
- [x] Build automated end-to-end multi-vector penetration testing harness in `securescript.core.penetration` (100% defense efficacy).
- [x] Conduct comparative benchmark study vs. Legacy Regex / CRS WAFs in `securescript.core.benchmark_comparative`.
- [x] Implement enterprise SIEM telemetry streaming in `securescript.telemetry.siem` (ArcSight CEF & Elastic Common Schema ECS).
- [x] Build standalone full-stack launcher in `run.py`.
- [x] Expand test suite to 55/55 tests passing (`tests/test_penetration.py`, `tests/test_siem.py`).
- [x] Compile final project delivery reports and academic LaTeX thesis (`reports/DAY_4_REPORT.md`, `reports/day_4_execution_report.tex`).

### Phase 5: Multi-Tenant SaaS Platform — **COMPLETED**
- [x] Task 1: Database Models & PostgreSQL Setup — `securescript/platform/database.py`, `models.py`, async session setup
- [x] Task 2: Auth API — Register & Login with JWT — `securescript/platform/auth.py`, `routers/auth_router.py`
- [x] Task 3: Project Management API — `securescript/platform/routers/project_router.py` (CRUD, slug generation, URL verification)
- [x] Task 4: Multi-Tenant Gateway — Refactor `securescript/proxy/gateway.py` for slug-based per-project proxy routing
- [x] Task 5: Per-Project Incident Storage — `securescript/platform/incident_store.py` (PostgreSQL-backed, scoped by project_id)
- [x] Task 6: Per-Project Dashboard API — `securescript/platform/routers/analytics_router.py` (stats, incidents, report endpoints)
- [x] Task 7: Alert Engine — `securescript/platform/alerts.py` (webhook + email notifications)
- [x] Task 8: Platform UI Templates — `securescript/templates/` (index, auth, projects, new_project, dashboard HTML)
- [x] Task 9: Deployment Config — Update `requirements.txt`, `pyproject.toml`, `Dockerfile`, `render.yaml`, `docker-compose.yml`, `run.py`, `.env.example`

---

## 3. Strict Non-Negotiable Invariants

When implementing or modifying code, all agents **MUST** uphold these architectural invariants:

1. **Recursion Depth Limit ($k = 4$):**
   - The recursive unquoting engine in `normalizer.py` must never loop indefinitely. It must strictly terminate after $k=4$ passes or when fixed-point convergence ($s_{i+1} == s_i$) is achieved.
   - ReDoS protection: Do not use un-anchored catastrophic backtracking regexes.

2. **Latency SLAs:**
   - **Fast-Path Lexer:** Overhead must remain $< 2.0\,\text{ms}$ on standard CPU hardware. Do not introduce heavy disk I/O, network requests, or complex allocations in this path.
   - **Deep Learning Inference:** Overhead must not exceed $20.0\,\text{ms}$ per suspicious payload. Keep model architecture compact (128 hidden units, 1–2 LSTM layers max).

3. **Asynchronous Non-Blocking Execution:**
   - Middleware is written for ASGI (FastAPI / Starlette). Never perform blocking synchronous operations in the main event loop. If heavy CPU processing is required, route through `asyncio.to_thread` or thread pools.

4. **False Positive Margin:**
   - Technical prose, mathematical notations (`x < y and y > z`), markdown, and benign programming snippets (`for i in range(10):`) must **NOT** be falsely categorized as XSS. The Fast-Path lexer and classifier must distinguish between inert data characters and execution context transitions.

5. **No Dangerous Evaluation:**
   - Never execute, evaluate, or render untrusted payloads using `eval()`, `exec()`, or dangerous sinks anywhere in backend code or testing harnesses.

6. **Multi-Tenancy Isolation:**
   - Incidents, stats, and project configs must always be scoped by `project_id`. Never query or return incidents without a `project_id` filter on multi-tenant routes.
   - All `/platform/` API endpoints must verify `project.user_id == current_user.id` (JWT ownership) before returning data. Return HTTP 403 if ownership check fails.
   - Never leak one tenant's data to another — no global incident queries on authenticated project endpoints.

7. **Non-Blocking Alert Delivery:**
   - Webhook (`send_webhook_alert`) and email (`send_email_alert`) alerts must always run as FastAPI `BackgroundTask` and never block the proxy response path.
   - Both alert functions must internally catch all exceptions and log them — they must never propagate errors to the caller.
   - Alert delivery failure must not cause a proxy request to fail or slow down.

---

## 4. Key Module Responsibilities

| Module Path | Primary Responsibility | Critical Interfaces |
| :--- | :--- | :--- |
| `securescript.core.normalizer` | Recursively unquotes nested encodings (URL, HTML entity, Base64, Hex, Unicode). | `normalize(payload: str, max_depth: int = 4) -> NormalizationResult` |
| `securescript.core.lexer` | Parses structural syntax to check if payload forces a transition into code execution context. | `inspect_fast_path(text: str) -> LexerVerdict` |
| `securescript.middleware.asgi` | ASGI middleware intercepting query parameters, headers, and request bodies. | `XSSMiddleware(app, mode="block", threshold=0.85)` |
| `securescript.models.bilstm` | PyTorch neural network classifying semantic sequences of token embeddings. | `XSSBiLSTM(vocab_size, embed_dim, hidden_dim)` |
| `securescript.telemetry.csp` | Ingests W3C standard JSON violation reports to detect DOM-based attacks. | `router.post("/api/v1/csp-report")` |
| `securescript.dashboard.app` | Renders live incident metrics, token attribution maps, and alert feeds. | Web UI console |
| `securescript.platform.database` | Async SQLAlchemy engine + `AsyncSessionLocal` factory + `get_db()` FastAPI dependency. | `get_db() -> AsyncSession` |
| `securescript.platform.models` | SQLAlchemy ORM models for `User`, `Project`, and `Incident` tables. | `User`, `Project`, `Incident` mapped classes |
| `securescript.platform.auth` | JWT creation/verification, bcrypt password hashing, `get_current_user` dependency. | `get_current_user`, `create_access_token`, `hash_password`, `verify_password` |
| `securescript.platform.incident_store` | PostgreSQL-backed incident persistence scoped by `project_id`. | `record_incident()`, `get_incidents()`, `get_incident_count()` |
| `securescript.platform.alerts` | Async webhook POST and SMTP email alert delivery — never raises, always background. | `send_webhook_alert()`, `send_email_alert()` |
| `securescript.platform.routers.auth_router` | `POST /auth/register` and `POST /auth/login` endpoints. | FastAPI `APIRouter` |
| `securescript.platform.routers.project_router` | Full CRUD for projects + alert config (`PUT /platform/projects/{id}/alerts`). | FastAPI `APIRouter` with `get_current_user` dep |
| `securescript.platform.routers.analytics_router` | Per-project stats, paginated incident list, and full report download. | `GET /platform/projects/{id}/stats`, `/incidents`, `/report` |

---

## 5. Standard Verification & Testing Commands

Agents must run verification checks after each modification:

```bash
# 1. Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# 2. Run all unit and integration tests
pytest tests/ -v --durations=10

# 3. Test normalizer specifically
pytest tests/test_normalizer.py -v

# 4. Test fast-path lexer latency
pytest tests/test_lexer.py -v -k "test_latency"

# 5. Launch FastAPI proxy demonstration
python -m uvicorn securescript.middleware.asgi:demo_app --reload --port 8000

# 6. Run database migrations (Phase 5+)
alembic upgrade head

# 7. Launch full multi-tenant platform
python run.py
# Platform UI:   http://127.0.0.1:8000/
# Sign Up:       http://127.0.0.1:8000/signup
# API Docs:      http://127.0.0.1:8000/docs

# 8. Run only platform tests
pytest tests/test_db_models.py tests/test_auth.py tests/test_projects.py \
       tests/test_multitenant_gateway.py tests/test_incident_store.py \
       tests/test_analytics.py tests/test_alerts.py -v

# 9. Launch local stack with PostgreSQL (Docker)
docker-compose up --build
```

---

## 6. Coding Standards
- **Python Version:** $\ge 3.10$
- **Typing:** Strict type hints on all function and method signatures (`def func(param: str) -> bool:`).
- **Docstrings:** Use Google-style or standard Sphinx docstrings explaining inputs, returns, and edge cases.
- **Dependencies:** Keep external dependencies minimal. Rely on Python standard library (`urllib.parse`, `html`, `re`, `unicodedata`, `base64`) for normalizer; use `libinjection` / AST for lexer.
