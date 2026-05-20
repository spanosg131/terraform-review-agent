.PHONY: venv install lock lock-check fmt lint type test run docker-build docker-up clean

PIP     := ./.venv/bin/pip
UV      := ./.venv/bin/uv
RUFF    := ./.venv/bin/ruff
MYPY    := ./.venv/bin/mypy
PYTEST  := ./.venv/bin/pytest

venv:
	python3.13 -m venv .venv
	$(PIP) install --upgrade pip uv

install: venv
	$(UV) sync --frozen --inexact --extra dev

lock:
	$(UV) lock

lock-check:
	$(UV) lock --check

fmt:
	$(RUFF) format src tests
	$(RUFF) check --fix src tests

lint: lock-check
	$(RUFF) check src tests
	$(RUFF) format --check src tests

type:
	$(MYPY) src

test:
	$(PYTEST) -q

# Run a review locally inside the container, which bundles every scanner
# (terraform/tfsec/tflint/infracost/checkov) — the host .venv does not. Provide
# PR coordinates + keys via .env (GITHUB_REPOSITORY, GITHUB_PR_NUMBER, *_API_KEY)
# or ad-hoc, e.g. `make run ARGS="--repository owner/repo --pr-number 1"`.
# Builds the image on first use; rerun `make docker-build` after dependency bumps
# (src is bind-mounted, so code changes need no rebuild).
run:
	docker compose run --rm agent python -m terraform_review_agent.entrypoint $(ARGS)

docker-build:
	docker compose build

docker-up:
	docker compose up

clean:
	rm -rf .venv .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
