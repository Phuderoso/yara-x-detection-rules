PYTHON ?= python3
GOODWARE ?= tests/goodware
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)

.PHONY: help setup setup-dev lint fmt fmt-check test goodware report compat bundles changelog \
        coverage coverage-check health health-check fp-corpus fp-report fp-compare fp-baseline \
        anchors memscan quality pytest ci fixtures hunt clean

help:
	@echo "setup       instala dependências de runtime (yara-x)"
	@echo "setup-dev   + ruff, mypy, pytest, bandit, pip-audit, pre-commit, yara-python"
	@echo "lint        compila + policies de meta/ciclo de vida/unicidade/strings + formatação"
	@echo "fmt         formata rules/ com o formatter do YARA-X"
	@echo "test        fixtures sintéticas: positivos e negativos por regra"
	@echo "goodware    gate de FP contra GOODWARE=$(GOODWARE)"
	@echo "report      relatório (hits, tempo por regra, fixtures) em build/report.json + markdown"
	@echo "compat      matriz de compatibilidade YARA 4.x (yara-python)"
	@echo "bundles     bundles por purpose + manifest + SHA256SUMS em dist/ (VERSION=$(VERSION))"
	@echo "changelog   CHANGELOG da versão a partir de commits e diff de rules/"
	@echo "coverage    regenera docs/coverage.md a partir do meta (coverage-check: só verifica)"
	@echo "health      regenera docs/health.md (FP, idade, último match, candidatas a deprecated)"
	@echo "fp-corpus   baixa o corpus pip fixado por hash em build/fp-corpus (fp-report/fp-compare: o resto do vigia)"
	@echo "fp-baseline aceita REPORT=build/report.json como tests/goodware/baseline.json"
	@echo "anchors     extrai âncoras de SAMPLES=... (ex.: make anchors SAMPLES='a.exe b.exe' FAMILY=X)"
	@echo "memscan     escaneia IMAGE=... com as regras de escopo memory/both"
	@echo "quality     ruff + mypy + pytest + bandit"
	@echo "ci          lint + test + goodware + quality (o que a CI roda)"
	@echo "fixtures    grava as fixtures em build/fixtures/ para inspeção com yr scan -s"

setup:
	$(PYTHON) -m pip install -r requirements.txt

setup-dev: setup
	$(PYTHON) -m pip install -r requirements-dev.txt yara-python pyzipper
	pre-commit install

lint:
	$(PYTHON) scripts/lint_rules.py

fmt:
	$(PYTHON) scripts/fmt_rules.py

fmt-check:
	$(PYTHON) scripts/fmt_rules.py --check

test:
	$(PYTHON) scripts/test_rules.py --strict -v

goodware:
	@test -d "$(GOODWARE)" || { echo "crie $(GOODWARE)/ com binários limpos (ver tests/goodware/README.md)"; exit 1; }
	$(PYTHON) scripts/scan_goodware.py "$(GOODWARE)"

report:
	@test -d "$(GOODWARE)" || { echo "crie $(GOODWARE)/ com binários limpos (ver tests/goodware/README.md)"; exit 1; }
	$(PYTHON) scripts/report.py --corpus "$(GOODWARE)" --out build/report.json
	$(PYTHON) scripts/diff_report.py --head build/report.json --out build/report.md

compat:
	$(PYTHON) scripts/compat_yara4.py

bundles:
	$(PYTHON) scripts/build_bundles.py --version "$(VERSION)" --out dist/

changelog:
	$(PYTHON) scripts/changelog.py --version "$(VERSION)"

coverage:
	$(PYTHON) scripts/coverage.py

coverage-check:
	$(PYTHON) scripts/coverage.py --check

health:
	$(PYTHON) scripts/health.py

health-check:
	$(PYTHON) scripts/health.py --check

FP_CORPUS ?= /usr/bin /usr/lib/x86_64-linux-gnu
REPORT ?= build/report.json

fp-corpus:
	$(PYTHON) scripts/fp_watch.py corpus --out build/fp-corpus

fp-report: fp-corpus
	$(PYTHON) scripts/corpus_manifest.py build $(FP_CORPUS) build/fp-corpus/pip -o build/manifest.json
	$(PYTHON) scripts/report.py --status stable,test --no-fixtures --corpus $(FP_CORPUS) build/fp-corpus/pip --out $(REPORT) --label local

fp-compare: fp-report
	$(PYTHON) scripts/fp_watch.py compare --report $(REPORT) --manifest build/manifest.json --out build/diff.json --markdown build/diff.md --fail

fp-baseline:
	$(PYTHON) scripts/fp_watch.py baseline --report $(REPORT) $(if $(wildcard build/manifest.json),--manifest build/manifest.json,)
	$(PYTHON) scripts/health.py

anchors:
	@test -n "$(SAMPLES)" || { echo "use: make anchors SAMPLES='a.exe b.exe' FAMILY=FamilyX [GOODWARE=dir]"; exit 1; }
	$(PYTHON) tools/anchors/extract_anchors.py $(SAMPLES) --family "$(FAMILY)" $(if $(wildcard $(GOODWARE)),--goodware "$(GOODWARE)",) \
		--json build/anchors.json --draft build/SUSP_Win_$(FAMILY)_CodeAnchors.yar

memscan:
	@test -n "$(IMAGE)" || { echo "use: make memscan IMAGE=proc.dmp"; exit 1; }
	$(PYTHON) scripts/memscan.py "$(IMAGE)" -s --jsonl build/memscan.jsonl --format ecs

pytest:
	$(PYTHON) -m pytest -q

quality:
	ruff check .
	ruff format --check .
	mypy
	$(PYTHON) -m pytest -q
	bandit -q -r scripts tests -c pyproject.toml

ci: lint test coverage-check health-check goodware quality

fixtures:
	$(PYTHON) scripts/test_rules.py --dump build/fixtures

clean:
	rm -rf build dist .mypy_cache .pytest_cache .ruff_cache
