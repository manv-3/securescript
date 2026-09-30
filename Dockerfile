# ==============================================================================
# SecureScript Hybrid WAF & Security Dashboard - Production Dockerfile
# Optimized for Render Free Tier (512MB RAM) & Cloud Deployments
# ==============================================================================

FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files, enable unbuffered logging,
# and optimize OpenMP/MKL thread counts to prevent RAM spikes on 512MB dynos
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    PORT=8000

WORKDIR /app

# Install system runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install PyTorch CPU first to leverage Docker layer caching
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Copy requirements and install Python dependencies
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -e . --no-deps

# Copy application codebase, templates, config, and trained model artifacts
COPY securescript/ securescript/
COPY data/ data/
COPY waf_config.yaml ./

# Create a non-root security user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Health check to ensure WAF gateway is responsive
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/dashboard || exit 1

EXPOSE 8000

# Launch production ASGI WAF Gateway binding dynamically to $PORT provided by Render
CMD ["sh", "-c", "python -m uvicorn securescript.proxy.gateway:waf_app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
