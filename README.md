# ASM-Texas-College-Final-year-Aasish

**Author:** Aasish Khanal  
**Institution:** Texas College

A complete **Attack Surface Management (ASM)** project for inventorying assets, ingesting findings, calculating risk, and prioritizing remediation.

## What is implemented

- ✅ Asset registry with owners, exposure level, criticality, and tags.
- ✅ Service inventory (protocol/port and internet exposure).
- ✅ Vulnerability ingestion and duplicate control.
- ✅ Risk scoring based on severity × exposure × business criticality.
- ✅ Environment dashboard summary and prioritized remediation backlog.
- ✅ JSON persistence and restore (`save` / `load`).
- ✅ CLI for real usage (`init-demo`, `dashboard`, `add-asset`, `add-vuln`, `remediate`, `list-assets`, `export-backlog`).
- ✅ Automated tests and GitHub Actions CI.
- ✅ GitHub collaboration files: PR template, issue templates, contributing guide, security policy.

## Repository structure

- `asm_system.py` — core ASM engine and domain model.
- `asm_cli.py` — command-line interface for daily operations.
- `tests/test_asm_system.py` — test suite.
- `.github/workflows/ci.yml` — CI pipeline for GitHub.
- `.github/ISSUE_TEMPLATE/*` — issue templates.
- `.github/pull_request_template.md` — PR template.
- `CONTRIBUTING.md` — contribution workflow.
- `SECURITY.md` — vulnerability reporting policy.
- `requirements.txt` — Python dependencies.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Initialize demo data:

```bash
python asm_cli.py init-demo --db data/demo.json
```

Show dashboard:

```bash
python asm_cli.py dashboard --db data/demo.json
```

List assets:

```bash
python asm_cli.py list-assets --db data/demo.json
```

Add an asset:

```bash
python asm_cli.py add-asset asset-300 api.texascollege.edu "AppSec Team" --business-criticality 5 --exposure-level public --tags api production --db data/demo.json
```

Add a vulnerability:

```bash
python asm_cli.py add-vuln asset-300 "Verbose Error Disclosure" "Stack traces exposed in production" --severity medium --service https --db data/demo.json
```

Remediate:

```bash
python asm_cli.py remediate asset-300 "Verbose Error Disclosure" --db data/demo.json
```

Export backlog JSON:

```bash
python asm_cli.py export-backlog --db data/demo.json --output data/backlog.json
```

## Run tests

```bash
python -m pytest -q
```

## GitHub setup

Push this repository to GitHub and CI will automatically run tests on push and pull requests via `.github/workflows/ci.yml`.
