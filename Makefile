# AgentSec Build Pipeline
#
# Common targets:
#   make install   install package with all dependencies
#   make test      run test suite with coverage
#   make lint      run code quality checks (black, ruff, mypy)
#   make format    auto-format code with black and ruff
#   make build     run full pipeline (lint + test + wheel)
#   make hooks     install git pre-commit hooks
#   make clean     remove build artifacts
#   make demo      run demo workflow analysis

PYTHON ?= python3

.PHONY: all install test lint format build hooks clean demo help

all: build

help:
	@echo "AgentSec Development Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install    Install package with all dependencies"
	@echo "  test       Run test suite with coverage"
	@echo "  lint       Run code quality checks (black, ruff, mypy)"
	@echo "  format     Auto-format code with black and ruff"
	@echo "  build      Run full pipeline (lint + test + wheel)"
	@echo "  hooks      Install git pre-commit hooks"
	@echo "  clean      Remove build artifacts"
	@echo "  demo       Run demo workflow analysis"
	@echo "  help       Show this help message"

install:
	$(PYTHON) -m pip install --upgrade pip setuptools wheel
	$(PYTHON) -m pip install -e ".[all]"
	$(PYTHON) -m pip install pytest pytest-cov black ruff mypy pre-commit

test:
	$(PYTHON) -m pytest --cov=agentsec --cov-report=html --cov-report=term-missing tests/

lint:
	@echo "Checking code formatting..."
	$(PYTHON) -m black --check --line-length 100 .
	@echo "Linting code..."
	$(PYTHON) -m ruff check .
	@echo "Type checking..."
	$(PYTHON) -m mypy agentsec --ignore-missing-imports || true

format:
	@echo "Formatting code with black..."
	$(PYTHON) -m black --line-length 100 .
	@echo "Auto-fixing with ruff..."
	$(PYTHON) -m ruff check --fix .

build: lint test wheel
	@echo "✓ Build complete!"

wheel:
	@echo "Building wheel package..."
	rm -rf dist build *.egg-info
	$(PYTHON) -m pip wheel --no-deps -w dist .
	@echo "✓ Wheel built successfully"

hooks:
	@echo "Installing pre-commit hooks..."
	$(PYTHON) tools/install_hooks.py

clean:
	@echo "Cleaning build artifacts..."
	rm -rf dist build *.egg-info htmlcov .coverage coverage.xml
	rm -rf .pytest_cache .ruff_cache .mypy_cache
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	find . -type f -name '*~' -delete
	@echo "✓ Clean complete"

demo:
	@echo "Running demo workflow analysis..."
	$(PYTHON) -m agentsec.cli.main scan langgraph -i demo/autoops -o report-demo.html
	@echo "✓ Demo complete! Open report-demo.html to view results"

# CI/CD targets (used by GitHub Actions)
ci-lint: lint
ci-test: test
ci-build: wheel