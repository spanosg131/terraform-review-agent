# syntax=docker/dockerfile:1

# Single image used for both local `docker compose` dev and CI. It bundles the
# Python venv plus pinned scanner binaries so the reusable workflow needs no
# per-run installs.
#
# Two pinning sources, by necessity:
#   * Binary scanners below — pinned via these ARGs (not pip-installable).
#   * Python stack incl. checkov — pinned via pyproject.toml + uv.lock and
#     installed with `uv sync --frozen`, so rebuilds are deterministic.
# Bumping either is a rebuild-image PR.

# Pinned scanner binary versions (single source of truth for the binaries).
ARG TERRAFORM_VERSION=1.15.3
ARG TFSEC_VERSION=1.28.14
ARG TFLINT_VERSION=0.62.1
ARG INFRACOST_VERSION=0.10.44

# ---------------------------------------------------------------------------
# Stage 1 — fetch pinned scanner binaries (arch-aware via buildx TARGETARCH)
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS scanners

ARG TERRAFORM_VERSION
ARG TFSEC_VERSION
ARG TFLINT_VERSION
ARG INFRACOST_VERSION
# TARGETARCH is auto-populated by buildx ("amd64" / "arm64"); matches every
# upstream asset naming below.
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/dl
RUN mkdir -p /out

# terraform
RUN curl -fsSL -o terraform.zip \
      "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip" \
    && unzip -q terraform.zip terraform -d /out

# tfsec (release asset is the raw binary)
RUN curl -fsSL -o /out/tfsec \
      "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-${TARGETARCH}" \
    && chmod +x /out/tfsec

# tflint
RUN curl -fsSL -o tflint.zip \
      "https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}/tflint_linux_${TARGETARCH}.zip" \
    && unzip -q tflint.zip tflint -d /out

# infracost (tarball contains infracost-linux-<arch>)
RUN curl -fsSL -o infracost.tar.gz \
      "https://github.com/infracost/infracost/releases/download/v${INFRACOST_VERSION}/infracost-linux-${TARGETARCH}.tar.gz" \
    && tar -xzf infracost.tar.gz \
    && mv "infracost-linux-${TARGETARCH}" /out/infracost

# Fail the build immediately if any downloaded binary can't execute on the
# target arch (catches wrong-arch / truncated / corrupt downloads here, before
# they ship and silently degrade reviews).
RUN chmod +x /out/* \
    && for b in /out/*; do \
         "$b" --version >/dev/null 2>&1 || { echo "binary failed to execute: $b" >&2; exit 1; }; \
       done

# ---------------------------------------------------------------------------
# Stage 2 — build the Python venv (build tools confined to this stage)
# ---------------------------------------------------------------------------
FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_PYTHON=python3.13 \
    UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 \
    PATH="/app/.venv/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Pinned uv for a reproducible resolver/installer.
RUN pip install --no-cache-dir uv==0.11.15

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY src ./src

# Deterministic install straight from the committed lock: the app (editable, so
# compose can hot-reload ./src) plus the `container` extra (checkov). Dev tools
# are excluded; --frozen forbids any re-resolution at build time.
RUN uv sync --frozen --no-dev --extra container

# ---------------------------------------------------------------------------
# Stage 3 — final runtime image
# ---------------------------------------------------------------------------
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 app

WORKDIR /app

# Scanner binaries on PATH for every user.
COPY --from=scanners /out/ /usr/local/bin/

# Python venv (identical /app/.venv path keeps the editable install valid).
COPY --from=builder /app/.venv /app/.venv

COPY pyproject.toml ./
COPY src ./src
COPY scripts ./scripts

RUN mkdir -p /app/data && chown -R app:app /app

USER app

# Fail the build if any bundled binary fails to resolve on PATH.
RUN ./scripts/smoke_test.sh

CMD ["python", "-m", "terraform_review_agent.entrypoint"]
