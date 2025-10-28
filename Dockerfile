# syntax=docker/dockerfile:1

# ---------- Base ----------
ARG PY_VERSION=3.12
FROM python:${PY_VERSION}-slim AS runtime

# Useful basics for debugging (curl) and certs
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---------- Python deps ----------
# If requirements.txt exists, install it; fail-soft so you can build before finalizing deps.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
 && (pip install --no-cache-dir -r /app/requirements.txt || true)

# ---------- App code ----------
# Copy your project packages/modules
COPY agents/              /app/agents/
COPY shared/              /app/shared/
COPY threat_detection/    /app/threat_detection/
# If you reference host_api.py, include it; safe to keep even if unused
COPY tee/host_api.py      /app/tee/host_api.py

# Ensure these are Python packages (safe if already present)
RUN mkdir -p /app/shared /app/threat_detection /app/threat_detection/models /app/tee \
 && [ -f /app/shared/__init__.py ] || touch /app/shared/__init__.py \
 && [ -f /app/threat_detection/__init__.py ] || touch /app/threat_detection/__init__.py \
 && [ -f /app/threat_detection/models/__init__.py ] || touch /app/threat_detection/models/__init__.py \
 && [ -f /app/tee/__init__.py ] || touch /app/tee/__init__.py

# Make /app importable for absolute imports like:
#   from threat_detection.models.url_analyzer import URLAnalyzer
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# ---------- Agent selection ----------
# Default to intake; override per build:
#   --build-arg AGENT_MODULE=agents.analyzer_agent
ARG AGENT_MODULE=agents.intake_agent
ENV AGENT_MODULE=${AGENT_MODULE}

# ECS/ALB health check port and path
ENV PORT=8080
EXPOSE 8080

# ---------- Entrypoint ----------
# Lightweight shell entry to run the chosen module
RUN printf '%s\n' \
  '#!/bin/sh' \
  'set -e' \
  'echo "[entrypoint] starting module: $AGENT_MODULE"' \
  'exec python -u -m "$AGENT_MODULE"' \
  > /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
