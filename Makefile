.PHONY: install dev test lint format serve clean

install:
	pip install -e .

dev:
	pip install -e ".[all]"

test:
	pytest -v --cov=ghostguard --cov-report=term-missing

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

serve:
	ghostguard serve --policy examples/policies/default.yaml

clean:
	rm -rf dist/ build/ *.egg-info .pytest_cache .ruff_cache ghostguard.db
