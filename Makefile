SHELL := /bin/bash

ISORT_TARGETS := neuro_admin_client tests
BLACK_TARGETS := $(ISORT_TARGETS)
MYPY_TARGETS :=  $(ISORT_TARGETS)
FLAKE8_TARGETS:= $(ISORT_TARGETS)


setup:
	uv sync --dev
	uv run pre-commit install

format: setup
ifdef CI_LINT_RUN
	uv run pre-commit run --all-files --show-diff-on-failure
else
	uv run pre-commit run --all-files
endif


lint: format
	uv run mypy $(MYPY_TARGETS)

test:
	uv run pytest --cov=neuro_admin_client --cov-report xml:.coverage.xml tests
