# Skróty do istniejących skryptów. Nie zmieniają kryteriów testów.
SYSTEM_PYTHON ?= /usr/bin/python3
TEST_PYTHON ?= .venv-validation/bin/python
RYU_PYTHON ?= $(HOME)/ryu-env/bin/python3
PROJECT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: help setup-tests test preflight integration

help:
	@printf '%s\n' \
	  'make setup-tests          - przygotuj osobne środowisko testowe' \
	  'make test                 - testy offline (bez sudo)' \
	  'make preflight            - sprawdź gotowość integracji (bez zmian sieci)' \
	  'make integration CONFIRM=YES - 11 testów na dedykowanym Ubuntu (sudo)'

setup-tests:
	$(SYSTEM_PYTHON) -m venv --system-site-packages .venv-validation
	.venv-validation/bin/python -m pip install -r validation/requirements-test.txt

test:
	@if [ ! -x "$(TEST_PYTHON)" ]; then \
	  printf '%s\n' 'Brak środowiska testowego. Uruchom: make setup-tests' >&2; \
	  exit 2; \
	fi
	$(TEST_PYTHON) validation/run_offline.py --source "$(PROJECT_DIR)"

preflight:
	$(SYSTEM_PYTHON) validation/run_integration.py \
	  --source "$(PROJECT_DIR)" --controller-python "$(RYU_PYTHON)"

# Wymaga jawnego potwierdzenia: uruchamia Docker/Containernet/OVS i własny Ryu.
integration:
	@if [ "$(CONFIRM)" != "YES" ]; then \
	  printf '%s\n' 'Test zmienia sieć hosta. Uruchom wyłącznie na dedykowanym Ubuntu:' \
	    'make integration CONFIRM=YES' >&2; \
	  exit 2; \
	fi
	sudo $(SYSTEM_PYTHON) validation/run_integration.py --execute \
	  --source "$(PROJECT_DIR)" --controller-python "$(RYU_PYTHON)"
