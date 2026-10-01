# SecureScript Platform - Startup Guide

## Quick Start

### Option 1: Python (Recommended for Development)
```bash
cd SecureScript
python startup.py
```

Platform will be available at: **http://127.0.0.1:8000**

### Option 2: Uvicorn (Custom Port)
If port 8000 is already in use, use a different port:
```bash
python -m uvicorn securescript.proxy.gateway:waf_app --host 127.0.0.1 --port 8888
```

### Option 3: Docker (Full Stack)
```bash
docker-compose up --build
```

---

## First Time Setup

The platform automatically:
1. Creates database tables (users, projects, incidents)
2. Initializes the WAF detection engines
3. Loads the Bi-LSTM neural model
4. Opens the browser to the landing page

**No additional setup required!**

---

## Platform URLs

| URL | Purpose |
|-----|---------|
| http://127.0.0.1:8000 | Landing page |
| http://127.0.0.1:8000/signup | User sign-up |
| http://127.0.0.1:8000/login | User login |
| http://127.0.0.1:8000/app/projects | Dashboard (auth required) |
| http://127.0.0.1:8000/docs | API documentation (Swagger) |
| http://127.0.0.1:8000/redoc | API documentation (ReDoc) |

---

## API Examples

### 1. Register a User
```bash
curl -X POST http://127.0.0.1:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "created_at": "2026-10-01T12:00:00+00:00"
}
```

### 2. Login and Get Token
```bash
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer"
}
```

### 3. Create a Project (Connect a Website)
```bash
TOKEN="eyJhbGc..."

curl -X POST http://127.0.0.1:8000/platform/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Awesome App",
    "frontend_url": "https://myapp.vercel.app",
    "backend_url": "https://api.myapp.com"
  }'
```

Response:
```json
{
  "id": "...",
  "name": "My Awesome App",
  "slug": "my-awesome-app-a3f2",
  "proxy_path": "/proxy/my-awesome-app-a3f2/",
  "frontend_url": "https://myapp.vercel.app",
  "backend_url": "https://api.myapp.com",
  "is_active": true,
  "created_at": "2026-10-01T12:00:00+00:00"
}
```

### 4. Use the WAF Proxy
Instead of calling your backend directly:
```
Before: https://api.myapp.com/api/users
After:  http://127.0.0.1:8000/proxy/my-awesome-app-a3f2/api/users
```

The request will pass through the 3-tier XSS detection pipeline:
- Tier 1: Recursive normalization (k=4 depth)
- Tier 2: Fast-path lexer (< 2ms)
- Tier 3: Bi-LSTM neural network (< 20ms)

### 5. View Security Stats
```bash
TOKEN="eyJhbGc..."
PROJECT_ID="550e8400-e29b-41d4-a716-446655440000"

curl http://127.0.0.1:8000/platform/projects/$PROJECT_ID/stats \
  -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{
  "total_inspected": 1234,
  "blocked": 23,
  "passed": 1200,
  "audited": 11,
  "block_rate_pct": 1.87,
  "avg_confidence": 0.9542,
  "top_attacked_paths": [
    {"path": "/api/submit", "count": 8},
    {"path": "/api/login", "count": 5}
  ],
  "requests_last_24h": [...]
}
```

---

## Testing an Attack

You can test the WAF by sending an XSS payload through the proxy:

```bash
curl "http://127.0.0.1:8000/proxy/my-awesome-app-a3f2/api/submit?q=<script>alert('xss')</script>" \
  -X POST
```

Expected response: **HTTP 403 Forbidden** (WAF blocked the attack)

The incident will be recorded and visible in the dashboard.

---

## Troubleshooting

### Port Already in Use
If port 8000 is already in use:
```bash
python -m uvicorn securescript.proxy.gateway:waf_app --host 127.0.0.1 --port 9000
```

### Database Errors
If you get database errors, reinitialize:
```bash
python -c "import asyncio; from securescript.platform.database import init_db; asyncio.run(init_db())"
```

### PyTorch Model Not Loading
Ensure PyTorch is installed:
```bash
pip install torch>=2.0.0
```

### Permission Denied
On Linux/macOS, you may need to use `sudo` or adjust permissions:
```bash
sudo python startup.py
# OR
chmod +x startup.py
python startup.py
```

---

## Production Deployment

For production, use a proper ASGI server like Gunicorn:

```bash
pip install gunicorn
gunicorn securescript.proxy.gateway:waf_app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

Or deploy to:
- **Render.com** - See render.yaml
- **AWS EC2** - Use Docker image
- **Heroku** - Use Procfile
- **DigitalOcean App Platform** - Use Dockerfile

---

## Next Steps

1. **Sign up** for an account
2. **Connect your app** (frontend + backend URLs)
3. **Copy the proxy path** (e.g., `/proxy/my-app-a3f2/`)
4. **Update your frontend** to route API calls through the proxy
5. **Configure alerts** (optional: webhook + email)
6. **Monitor dashboard** for attacks and analytics

---

## Features Overview

✅ **Multi-Tenant Platform** - Manage multiple websites from one account  
✅ **3-Tier Detection** - Normalizer + Lexer + Bi-LSTM  
✅ **98%+ Accuracy** - Catches XSS attacks with <1.5% false positive rate  
✅ **Real-Time Analytics** - Live dashboard with 24h timeline  
✅ **Webhook Alerts** - Integration with Slack, Discord, custom webhooks  
✅ **Email Alerts** - Instant notifications via SMTP/SendGrid  
✅ **Full API** - Programmatic access to all features  
✅ **Responsive UI** - Works on desktop, tablet, mobile  

---

## Documentation

- **README.md** - Project overview and features
- **AGENT.md** - AI agent operating manual
- **CONTEXT.md** - Platform architecture
- **PHASE_5_COMPLETION.md** - Phase 5 completion report
- **API Docs** - Available at `/docs` (Swagger UI)

---

## Support

For issues or questions:
1. Check the logs: `docker logs securescript-app` (if using Docker)
2. Review the test results: `pytest tests/ -v`
3. Check the API docs at `/docs`

---

**Status:** ✅ Ready for production  
**Last Updated:** October 1, 2026
