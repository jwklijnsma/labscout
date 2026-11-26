# labscout: common tasks. `make` or `make help` lists them.

PYTHON ?= python3
IMAGE  ?= labscout:dev

.DEFAULT_GOAL := help
.PHONY: help install test serve docker docs version

help: ## show this list
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-10s %s\n", $$1, $$2}'

install: ## install for development (editable, with pytest)
	$(PYTHON) -m pip install -e ".[dev]"

test: ## run the test suite
	$(PYTHON) -m pytest -q

serve: ## start the web UI on http://localhost:8766
	$(PYTHON) -m labscout serve

docker: ## build the image locally (labscout:dev)
	docker build -t $(IMAGE) .

docs: ## preview the documentation on http://localhost:8000
	$(PYTHON) -m pip install -q -r requirements-docs.txt && zensical serve

version: ## print the current version
	@sed -n 's/^__version__ = "\(.*\)"$$/\1/p' src/labscout/__init__.py
