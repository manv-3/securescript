# ==============================================================================
# SecureScript Multi-Tenant WAF Platform — Production Dockerfile
# Optimized for Render Free Tier (512MB RAM) & Cloud Deployments
# ==============================================================================

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    PYTHONPATH=/app \
    PORT=8000

# Install runtime and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install PyTorch CPU first to leverage Docker layer caching and avoid 2.5GB CUDA bloat
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Copy requirements and install Python dependencies
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application codebase, templates, config, and trained model artifacts
COPY securescript/ securescript/
COPY data/ data/
COPY waf_config.yaml run.py ./

# Install local package in editable mode
RUN pip install --no-cache-dir -e . --no-deps

# Create a non-root security user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Health check to ensure WAF gateway is responsive
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/dashboard || exit 1

EXPOSE 8000

# Launch production ASGI WAF Gateway binding dynamically to $PORT provided by Render
CMD ["sh", "-c", "python -m uvicorn securescript.proxy.gateway:waf_app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
