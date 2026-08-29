# syntax=docker/dockerfile:1
#
# Build context is the Backend/ directory, not this folder, because the image
# needs common-helpers/ as well:
#   docker build -f services/administration/Dockerfile -t pingora-admin .

# ---------- Stage 1: build wheels ----------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# argon2-cffi and cryptography need a toolchain to build on slim; the compiler
# stays in this stage and never ships in the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY common-helpers/ /build/common-helpers/
COPY services/administration/requirements.txt /build/requirements.txt

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip \
    && pip install -r /build/requirements.txt \
    && pip install /build/common-helpers

# ---------- Stage 2: runtime ----------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH"

# curl is only for the container healthcheck below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1001 pingora \
    && useradd --system --uid 1001 --gid pingora --no-create-home pingora

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=pingora:pingora services/administration/ /app/

# Keys are mounted here at runtime from a secret store. Owned by the app user
# so a development key pair can be generated on first boot.
RUN mkdir -p /app/keys && chown -R pingora:pingora /app/keys

# Never run as root: a container escape starts from whatever the process is.
USER pingora

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8001/health || exit 1

CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8001", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*", \
     "--workers", "2"]
