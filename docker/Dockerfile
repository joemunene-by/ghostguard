# GhostGuard — Multi-stage Docker build
# Build:   docker build -t ghostguard -f docker/Dockerfile .
# Run:     docker run -p 8000:8000 -v ./policy.yaml:/app/policy.yaml ghostguard

# ---- Builder ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN pip install --no-cache-dir hatch

# Copy project files
COPY pyproject.toml ./
COPY src/ src/

# Build the wheel
RUN pip install --no-cache-dir --prefix=/install .

# ---- Runtime ----
FROM python:3.12-slim AS runtime

# Security: non-root user
RUN groupadd --gid 1000 ghostguard && \
    useradd --uid 1000 --gid ghostguard --shell /bin/bash --create-home ghostguard

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy templates (needed at runtime)
COPY src/ghostguard/dashboard/templates/ /usr/local/lib/python3.12/site-packages/ghostguard/dashboard/templates/

# Create data directory
RUN mkdir -p /app/data && chown ghostguard:ghostguard /app/data

# Switch to non-root user
USER ghostguard

# Environment defaults
ENV GHOSTGUARD_HOST=0.0.0.0 \
    GHOSTGUARD_PORT=8000 \
    GHOSTGUARD_DB_PATH=/app/data/ghostguard.db \
    GHOSTGUARD_POLICY_PATH=/app/policy.yaml \
    GHOSTGUARD_LOG_LEVEL=info

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["ghostguard", "serve"]
