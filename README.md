# ASM-Texas-College-Final-year-Aasish

A complete **Attack Surface Management (ASM)** project for inventorying assets, ingesting findings, calculating risk, and prioritizing remediation.

## What is implemented

- ✅ Asset registry with owners, exposure level, criticality, and tags.
- ✅ Service inventory (protocol/port and internet exposure).
- ✅ Vulnerability ingestion and duplicate control.
- ✅ Risk scoring based on severity × exposure × business criticality.
- ✅ Environment dashboard summary and prioritized remediation backlog.
- ✅ JSON persistence and restore (`save` / `load`).
- ✅ CLI for real usage (`init-demo`, `dashboard`, `add-asset`, `add-vuln`, `remediate`).
- ✅ Automated tests and GitHub Actions CI.

## Repository structure

- `asm_system.py` — core ASM engine and domain model.
- `asm_cli.py` — command-line interface for daily operations.
- `tests/test_asm_system.py` — test suite.
- `.github/workflows/ci.yml` — CI pipeline for GitHub.
- `requirements.txt` — Python dependencies.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Initialize demo data:

```bash
python asm_cli.py init-demo
```

Show current dashboard:

```bash
python asm_cli.py dashboard
```

Add an asset:

```bash
python asm_cli.py add-asset asset-300 api.texascollege.edu "AppSec Team" --business-criticality 5 --exposure-level public --tags api production
```

Add a vulnerability:

```bash
python asm_cli.py add-vuln asset-300 "Verbose Error Disclosure" "Stack traces exposed in production" --severity medium --service https
```

Remediate:

```bash
python asm_cli.py remediate asset-300 "Verbose Error Disclosure"
```

## Run tests

```bash
python -m pytest -q
```

## GitHub setup

Push this repository to GitHub and CI will automatically run tests on push and pull requests via `.github/workflows/ci.yml`.
