# SecureScript — Platform Context

> Quick-reference document for developers, contributors, and AI agents working on this codebase.

---

## What Is SecureScript?

A **multi-tenant SaaS Web Application Firewall (WAF)** that protects any website from XSS attacks. Developers register an account, submit their deployed frontend and backend URLs, and SecureScript immediately becomes the security proxy layer between their end users and their origin servers.

- No DNS changes required
- No SDK or code changes in the protected app
- One central SecureScript deployment serves all tenants
- Per-project isolation: incidents, stats, and config never leak across tenants

---

## How Routing Works

```
User registers project:
  frontend_url = https://myapp.vercel.app
  backend_url  = https://myapp.onrender.com

SecureScript generates:
  slug       = myapp-a3f2
  proxy_path = /proxy/myapp-a3f2/

End users hit SecureScript instead of origin:
  https://securescript.app/proxy/myapp-a3f2/          → proxies to frontend_url
  https://securescript.app/proxy/myapp-a3f2/api/submit → proxies to backend_url

Every request passes through the 3-tier WAF inspection before forwarding.
```

---

## Architecture Overview

```
[End User Browser]
        │
        ▼
GET /proxy/{slug}/{path}
        │
        ▼
[Multi-Tenant Gateway: gateway.py]
        │
        ├─ LRU Cache hit? → use cached project config
        │
        ├─ DB Lookup: SELECT * FROM projects WHERE slug=? AND is_active=true
        │       └─ Not found → 404
        │
        ▼
[3-Tier XSS Inspection Pipeline]
        │
        ├─ Tier 1: RecursiveNormalizer (k=4 decode passes)
        ├─ Tier 2: FastPathLexer (FSM, < 2ms)
        └─ Tier 3: BiLSTM Neural Classifier (< 20ms, suspicious only)
               │
        ┌──────┴──────┐
        ▼             ▼
   [BLOCK 403]   [PASS → httpx proxy to upstream_url]
        │
        ▼
[BackgroundTask: record_incident() → PostgreSQL]
        │
        ▼
[BackgroundTask: send_webhook_alert() + send_email_alert()]
        │
        ▼
[User sees incident in /app/projects/{id} dashboard]
```

---

## Key URLs (Deployed)

| URL | Purpose |
|-----|---------|
| `https://securescript.app/` | Landing page |
| `https://securescript.app/signup` | Sign-up page |
| `https://securescript.app/login` | Login page |
| `https://securescript.app/app/projects` | Projects list (auth required) |
| `https://securescript.app/app/projects/new` | Connect new project |
| `https://securescript.app/app/projects/{id}` | Per-project dashboard |
| `POST /auth/register` | Create account |
| `POST /auth/login` | Get JWT token |
| `POST /platform/projects` | Create project |
| `GET /platform/projects` | List projects |
| `GET /platform/projects/{id}/stats` | Security analytics |
| `GET /platform/projects/{id}/incidents` | Incident log |
| `GET /platform/projects/{id}/report` | Full report download |
| `PUT /platform/projects/{id}/alerts` | Configure alerts |
| `ANY /proxy/{slug}/{path}` | WAF proxy endpoint |
| `GET /api/v1/siem/events` | SIEM event stream |
| `GET /docs` | Swagger API docs |
| `GET /dashboard` | Legacy single-tenant dashboard |

---

## Environment Variables Required

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./securescript.db` | PostgreSQL (or SQLite for dev) |
| `SECRET_KEY` | *(must set)* | JWT HMAC signing secret — use a long random string |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` | JWT token lifetime (24h) |
| `SMTP_HOST` | — | SMTP relay hostname (e.g., `smtp.sendgrid.net`) |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP username (SendGrid: `apikey`) |
| `SMTP_PASSWORD` | — | SMTP password or API key |
| `SMTP_FROM` | — | From address for alert emails |
| `UPSTREAM_URL` | `https://basic-form-project.vercel.app` | Legacy single-tenant fallback |
| `BACKEND_API_URL` | `https://basic-form-project.onrender.com` | Legacy single-tenant fallback |
| `DL_THRESHOLD` | `0.85` | BiLSTM confidence threshold for blocking |
| `WAF_MODE` | `block` | `block`, `audit`, or `pass` |

---

## Module Map

| Path | Purpose |
|------|---------|
| `securescript/platform/database.py` | Async SQLAlchemy engine, `AsyncSessionLocal`, `Base`, `get_db()` dependency |
| `securescript/platform/models.py` | ORM models: `User`, `Project`, `Incident` |
| `securescript/platform/auth.py` | `hash_password`, `verify_password`, `create_access_token`, `get_current_user` dependency |
| `securescript/platform/incident_store.py` | `record_incident()`, `get_incidents()`, `get_incident_count()` — scoped by `project_id` |
| `securescript/platform/alerts.py` | `send_webhook_alert()`, `send_email_alert()` — always async, never raises |
| `securescript/platform/routers/auth_router.py` | `POST /auth/register`, `POST /auth/login` |
| `securescript/platform/routers/project_router.py` | `POST/GET/DELETE /platform/projects`, `PUT /platform/projects/{id}/alerts` |
| `securescript/platform/routers/analytics_router.py` | `GET /platform/projects/{id}/stats`, `/incidents`, `/report` |
| `securescript/proxy/gateway.py` | Main FastAPI app; multi-tenant proxy route + legacy single-tenant catch-all |
| `securescript/telemetry/siem.py` | In-memory SIEM buffer + ECS/CEF export endpoints |
| `securescript/telemetry/csp.py` | W3C CSP violation ingest + DOM XSS correlation |
| `securescript/dashboard/app.py` | Legacy single-tenant dashboard router |
| `securescript/core/normalizer.py` | Recursive multi-pass URL/HTML/Base64/Unicode decoder (k=4) |
| `securescript/core/lexer.py` | FSM-based fast-path XSS context-switch detector (< 2ms) |
| `securescript/models/bilstm.py` | PyTorch Bi-LSTM XSS classifier (< 20ms inference) |

---

## Data Models (Quick Reference)

### User
```
id            UUID PK
email         String (unique, indexed)
hashed_password String
created_at    DateTime
```

### Project
```
id                UUID PK
user_id           UUID FK → users.id
name              String
slug              String (unique, indexed) — e.g. "my-app-a3f2"
frontend_url      String
backend_url       String
is_active         Boolean (default True)
frontend_reachable Boolean (nullable)
backend_reachable  Boolean (nullable)
webhook_url       String (nullable)
alert_email       String (nullable)
created_at        DateTime
```

### Incident
```
id                UUID PK
project_id        UUID FK → projects.id
event_id          String (unique) — e.g. "RAY-9A82F104BC"
timestamp         DateTime
action            String — "BLOCKED" | "AUDITED" | "PASSED"
client_ip         String
http_method       String
url_path          String
detection_stage   String — "Fast-Path Lexical Analyzer" | "PyTorch Bi-LSTM"
confidence_score  Float
trigger_tokens    JSON (list of strings)
raw_payload       Text
normalized_payload Text
latency_ms        Float
attack_category   String
severity          String — "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
created_at        DateTime
```

---

## Multi-Tenancy Invariants

1. **Isolation:** Every DB query on incidents/stats MUST include a `project_id` filter. Never query incidents globally without scoping.
2. **Ownership:** Every `/platform/` API endpoint must verify `project.user_id == current_user.id` before returning data. Return 403 otherwise.
3. **Non-Blocking Alerts:** `send_webhook_alert` and `send_email_alert` must always run as `BackgroundTask`. They must never raise exceptions or block the proxy response.
4. **LRU Cache:** Slug→Project DB lookups are cached in-process for 60 seconds. Cache is invalidated on project deactivation.
5. **Incident Recording:** Always use `incident_store.record_incident()` for multi-tenant routes. The legacy `siem_collector` is only for the single-tenant catch-all fallback.

---

## Development Notes

- **Local DB:** If `DATABASE_URL` is not set or points to SQLite, the app falls back to `sqlite+aiosqlite:///./securescript.db`. This is fine for local dev; use PostgreSQL for production.
- **Alembic:** Run `alembic upgrade head` before first launch. Dockerfile and render.yaml do this automatically.
- **JWT Auth:** All `/platform/` and `/app/` routes require a `Bearer` JWT token in the `Authorization` header. The web UI stores the token in `localStorage`.
- **Tests:** Use `pytest tests/ -v` to run the full suite. New platform tests are in `tests/test_db_models.py`, `test_auth.py`, `test_projects.py`, `test_multitenant_gateway.py`, `test_incident_store.py`, `test_analytics.py`, `test_alerts.py`.
