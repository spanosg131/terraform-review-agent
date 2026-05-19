FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 app

WORKDIR /app

RUN python -m venv "$VIRTUAL_ENV" \
    && pip install --upgrade pip uv

COPY pyproject.toml ./
COPY src ./src

RUN uv pip install -e ".[dev]"

RUN mkdir -p /app/data && chown -R app:app /app
USER app

CMD ["python", "-m", "terraform_review_agent.entrypoint"]
