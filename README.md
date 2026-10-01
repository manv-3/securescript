# SecureScript: Multi-Tenant SaaS Web Application Firewall

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green.svg)](https://fastapi.tiangolo.com/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.x-orange.svg)](https://pytorch.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15%2B-blue.svg)](https://www.postgresql.org/)
[![Status](https://img.shields.io/badge/Status-Phase%205%20In%20Progress-yellow.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-55%20Passed-success.svg)](#)

SecureScript is a **multi-tenant SaaS Web Application Firewall (WAF) platform**. Protect any website from XSS attacks by connecting it in seconds — no DNS changes required. Point your traffic through SecureScript's proxy and get real-time threat detection powered by a hybrid BiLSTM neural engine.

---

## How It Works

```
1. Register    →  Create an account at securescript.app/signup
2. Connect     →  Submit your frontend URL + backend URL
3. Get a proxy →  Receive your unique proxy path: /proxy/my-app-a3f2/
4. Route       →  Point your frontend's API calls through the proxy
5. Protected   →  Every request is inspected by the 3-tier WAF before forwarding
```

Users and their end-customers never interact directly with your origin server — all traffic passes through SecureScript's detection pipeline first.

---

## Platform Features

- **Multi-Project Dashboard** — Manage multiple websites from one account, each with isolated incident logs and stats
- **Slug-Based Proxy Routing** — Unique proxy path per project (`/proxy/{slug}/`), no DNS changes or domain delegation required
- **JWT Authentication** — Secure email + password login; all management APIs are protected
- **Per-Project Incident Logs** — Every blocked attack is recorded to PostgreSQL, scoped to your project
- **Live Analytics** — Request totals, block rate, top attacked endpoints, 24-hour timeline
- **Downloadable Reports** — Full JSON security reports for any project
- **Email + Webhook Alerts** — Get notified instantly when attacks are blocked (Slack, Discord, or any webhook endpoint)
- **3-Tier Hybrid Detection Engine** — Sub-millisecond lexer + PyTorch BiLSTM neural network (≥98% accuracy, ≤1.5% FPR)
- **SIEM Integration** — ECS and CEF export for ELK, Splunk, Datadog, ArcSight

---

## Quick Start — Platform (SaaS)

### 1. Register an Account
```bash
curl -X POST https://securescript.app/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "your-password"}'
```

### 2. Login and Get a JWT Token
```bash
curl -X POST https://securescript.app/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "your-password"}'
# → {"access_token": "eyJ...", "token_type": "bearer"}
```

### 3. Connect Your Project
```bash
curl -X POST https://securescript.app/platform/projects \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "frontend_url": "https://my-app.vercel.app",
    "backend_url": "https://my-app.onrender.com"
  }'
# → {"proxy_path": "/proxy/my-app-a3f2/", "status": "active", ...}
```

### 4. Use the Proxy Path
Replace direct calls to your backend with the SecureScript proxy path:
```
Before: https://my-app.onrender.com/api/submit
After:  https://securescript.app/proxy/my-app-a3f2/api/submit
```

### 5. View Your Dashboard
```bash
curl https://securescript.app/platform/projects/{id}/stats \
  -H "Authorization: Bearer YOUR_TOKEN"
```
Or open the web dashboard at `https://securescript.app/app/projects`.

---

## Quick Start — Local Development

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/your-org/SecureScript.git
cd SecureScript
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
pip install -e .
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env — set DATABASE_URL, SECRET_KEY, SMTP_* values
```

### 3. Run Database Migrations
```bash
alembic upgrade head
```

### 4. Launch the Platform
```bash
python run.py
# Platform UI:     http://127.0.0.1:8000/
# Sign Up:         http://127.0.0.1:8000/signup
# Projects:        http://127.0.0.1:8000/app/projects
# API Docs:        http://127.0.0.1:8000/docs
```

### 5. Run Tests
```bash
pytest tests/ -v
```

---

## WAF Detection Pipeline

```
Incoming HTTP Request (via /proxy/{slug}/{path})
       │
       ▼
[0. Tenant Resolution] ─── Lookup slug → project config from PostgreSQL
       │
       ▼
[1. Recursive Normalization Engine] ─── (Decodes multi-pass URL, HTML, Base64 up to k=4)
       │
       ▼
[2. Fast-Path Lexer (State Switch?)] ── No ──► PASS (Clean, < 2ms)
       │ Suspicious
       ▼
[3. PyTorch Deep Learning Classifier]
       │
       ├─ Confidence < Threshold ──► PASS / AUDIT
       │
       └─ Confidence >= Threshold ─► BLOCK (HTTP 403)
                                           │
                                     ┌─────┴──────┐
                                     ▼            ▼
                             [Record Incident]  [Fire Alerts]
                             [to PostgreSQL]  [Webhook + Email]
                                     │
                                     ▼
                            [SIEM Dashboard & CSP]
```

---

## Project Structure

```
SecureScript/
├── AGENT.md                        # AI agent operating manual
├── README.md                       # This file
├── CONTEXT.md                      # Quick-reference platform context
├── .env.example                    # Environment variable template
├── requirements.txt                # Python dependencies
├── pyproject.toml                  # Package configuration
├── run.py                          # Platform launcher
├── waf_config.yaml                 # Legacy single-tenant config
├── Dockerfile                      # Container image definition
├── docker-compose.yml              # Local dev stack (app + PostgreSQL)
├── render.yaml                     # Render.com deployment config
├── alembic/                        # Database migration scripts
│   ├── env.py
│   └── versions/
├── securescript/
│   ├── platform/                   # ★ NEW: Multi-tenant SaaS platform
│   │   ├── database.py             # Async SQLAlchemy engine + session factory
│   │   ├── models.py               # ORM models: User, Project, Incident
│   │   ├── auth.py                 # JWT + bcrypt auth utilities
│   │   ├── incident_store.py       # PostgreSQL incident CRUD
│   │   ├── alerts.py               # Webhook + email alert delivery
│   │   └── routers/
│   │       ├── auth_router.py      # POST /auth/register, /auth/login
│   │       ├── project_router.py   # CRUD /platform/projects
│   │       └── analytics_router.py # Stats + incidents per project
│   ├── proxy/
│   │   └── gateway.py              # Multi-tenant WAF reverse proxy (extended)
│   ├── core/
│   │   ├── normalizer.py           # Recursive multi-pass decoding engine (k=4)
│   │   ├── lexer.py                # Fast-path AST & FSM token parser
│   │   ├── adversarial.py          # Adversarial evasion benchmark suite
│   │   └── penetration.py          # Automated penetration testing harness
│   ├── models/
│   │   ├── bilstm.py               # PyTorch Bi-LSTM classifier
│   │   ├── tokenizer.py            # Subword/character tokenizer
│   │   ├── attribution.py          # Gradient saliency explainability
│   │   └── export.py               # TorchScript export utilities
│   ├── middleware/
│   │   └── asgi.py                 # ASGI middleware (single-tenant mode)
│   ├── telemetry/
│   │   ├── siem.py                 # SIEM ECS/CEF streaming (extended)
│   │   └── csp.py                  # W3C CSP violation collector
│   ├── dashboard/
│   │   └── app.py                  # Legacy dashboard (still active)
│   └── templates/
│       ├── index.html              # Landing page
│       ├── auth.html               # Sign-up / Login page
│       ├── projects.html           # Projects list
│       ├── new_project.html        # Connect new project form
│       ├── dashboard.html          # Per-project dashboard
│       └── block_page.html         # WAF block page (403)
├── data/
│   ├── bilstm_model.pt             # Trained BiLSTM model weights
│   ├── bilstm_traced.pt            # TorchScript compiled model
│   ├── tokenizer.json              # Tokenizer vocabulary
│   └── baseline_model.joblib       # Baseline TF-IDF + LR model
├── tests/
│   ├── test_db_models.py           # DB schema and ORM tests
│   ├── test_auth.py                # JWT auth endpoint tests
│   ├── test_projects.py            # Project CRUD tests
│   ├── test_multitenant_gateway.py # Multi-tenant proxy routing tests
│   ├── test_incident_store.py      # PostgreSQL incident store tests
│   ├── test_analytics.py           # Stats and reporting tests
│   ├── test_alerts.py              # Webhook + email alert tests
│   ├── test_bilstm.py              # BiLSTM model tests
│   ├── test_gateway.py             # Legacy gateway tests
│   ├── test_middleware.py          # ASGI middleware tests
│   └── ...
└── reports/
    └── ...
```

---

## API Reference

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register with email + password |
| POST | `/auth/login` | Login, receive JWT access token |

### Project Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/platform/projects` | Create a new project (connect a site) |
| GET | `/platform/projects` | List all your projects |
| GET | `/platform/projects/{id}` | Get project details |
| DELETE | `/platform/projects/{id}` | Deactivate a project |
| PUT | `/platform/projects/{id}/alerts` | Configure webhook + email alerts |

### Analytics & Incidents
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/platform/projects/{id}/stats` | Aggregated security stats |
| GET | `/platform/projects/{id}/incidents` | Paginated incident log |
| GET | `/platform/projects/{id}/report` | Full downloadable security report |

### Proxy (WAF Gateway)
| Method | Endpoint | Description |
|--------|----------|-------------|
| ANY | `/proxy/{slug}/{path}` | Multi-tenant WAF proxy endpoint |

### Telemetry
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/siem/events` | Recent SIEM incident events |
| GET | `/api/v1/siem/export/ecs` | ECS (Elastic) format export |
| GET | `/api/v1/siem/export/cef` | CEF (ArcSight) format export |
| POST | `/api/v1/csp-report` | W3C CSP violation ingest |

---

## Technical Specifications & SLAs

| Metric | Target | Component |
|--------|--------|-----------|
| Fast-Path Latency | < 2 ms | `securescript.core.lexer` |
| Neural Inference Latency | < 20 ms | `securescript.models.bilstm` |
| Detection Accuracy | ≥ 98.0% | PyTorch Bi-LSTM |
| False Positive Rate | ≤ 1.5% | Hybrid Fast-Path + DL |
| Recursion Depth | Fixed k=4 | `securescript.core.normalizer` |
| DB Incident Write | < 5 ms | `securescript.platform.incident_store` |
| Alert Delivery | < 5 s | `securescript.platform.alerts` |

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `SECRET_KEY` | Yes | JWT signing secret |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | JWT expiry (default: 1440) |
| `SMTP_HOST` | For email alerts | SMTP server hostname |
| `SMTP_PORT` | For email alerts | SMTP port (usually 587) |
| `SMTP_USER` | For email alerts | SMTP username |
| `SMTP_PASSWORD` | For email alerts | SMTP password or API key |
| `SMTP_FROM` | For email alerts | From address for alert emails |
| `UPSTREAM_URL` | Legacy | Single-tenant fallback frontend URL |
| `BACKEND_API_URL` | Legacy | Single-tenant fallback backend URL |

---

## License & Attribution
Developed for the **HCL Internship Program** (September–October 2026).
Based on research specifications in *SecureScript: An Intelligent Real-Time Cross-Site Scripting (XSS) Detection Framework Using Hybrid Lexical Analysis and Deep Learning*.
