# syntax=docker/dockerfile:1
# IA 462 midterm - hardened multi-stage build.
# Build from the midterm/ directory:  docker build -t ia462-midterm:hardened .
#
# Base image is pinned by digest (multi-arch index for python:3.13-slim-trixie).
# Dependabot (docker ecosystem) proposes digest bumps; re-resolve manually with:
#   docker buildx imagetools inspect python:3.13-slim-trixie --format '{{json .Manifest.Digest}}'

############################
# Stage 1: builder
############################
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY requirements.lock .

# Isolated venv; --require-hashes refuses any package whose hash is not in the lock.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.lock \
 && /opt/venv/bin/pip uninstall -y pip

############################
# Stage 2: minimal runtime
############################
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS runtime

LABEL org.opencontainers.image.title="ia462-midterm" \
      org.opencontainers.image.description="Hardened Flask service for IA 462 midterm"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Unprivileged user with no login shell and no home directory contents.
# pip is also removed from the runtime image: nothing installs at runtime,
# and it removes pip's own CVEs from the scan surface.
RUN groupadd --system --gid 10001 appgroup \
 && useradd --system --uid 10001 --gid appgroup --no-create-home \
            --shell /usr/sbin/nologin appuser \
 && python -m pip uninstall -y pip

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root --chmod=0555 app/ /app/

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]

# /tmp is a tmpfs at runtime (root fs is --read-only)
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "2", \
     "--worker-tmp-dir", "/tmp", "--access-logfile", "-", "--error-logfile", "-", \
     "app:app"]
