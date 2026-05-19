.PHONY: venv install fmt lint type test run docker-build docker-up clean

PY      := ./.venv/bin/python
PIP     := ./.venv/bin/pip
UV      := ./.venv/bin/uv
RUFF    := ./.venv/bin/ruff
MYPY    := ./.venv/bin/mypy
PYTEST  := ./.venv/bin/pytest

venv:
	python3.13 -m venv .venv
	$(PIP) install --upgrade pip uv

install: venv
	$(UV) pip install -e ".[dev]"

fmt:
	$(RUFF) format src tests
	$(RUFF) check --fix src tests

lint:
	$(RUFF) check src tests
	$(RUFF) format --check src tests

type:
	$(MYPY) src

test:
	$(PYTEST) -q

run:
	$(PY) -m terraform_review_agent.entrypoint

docker-build:
	docker compose build

docker-up:
	docker compose up

clean:
	rm -rf .venv .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
