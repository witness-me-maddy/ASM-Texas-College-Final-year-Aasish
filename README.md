# ASM-Texas-College-Final-year-Aasish

Attack Surface Management (ASM) system for discovering, tracking, and prioritizing risks across digital assets.

## Features

- Asset inventory management (hostname, owner, exposure, business criticality).
- Exposed service tracking (port/protocol/internet exposure).
- Vulnerability intake from scan results.
- Risk scoring model based on severity, exposure level, and asset criticality.
- Prioritized remediation backlog generation.
- JSON persistence (`save`/`load`) for reporting and handoff.

## Project Structure

- `asm_system.py` – core ASM domain model and orchestration.
- `tests/test_asm_system.py` – automated tests for scoring, remediation, sorting, and persistence.

## Quick Start

```bash
python asm_system.py
```

Expected output includes environment risk score and a prioritized remediation backlog.

## Run Tests

```bash
python -m pytest -q
```

## Example Integration

```python
from asm_system import AttackSurfaceManagementSystem, Asset, Service, Vulnerability, ExposureLevel, Severity

asm = AttackSurfaceManagementSystem()
asm.register_asset(
    Asset(
        asset_id="asset-001",
        hostname="student-portal.texascollege.edu",
        owner="IT Security",
        business_criticality=5,
        exposure_level=ExposureLevel.PUBLIC,
    )
)

asm.ingest_scan_result(
    "asset-001",
    services=[Service(name="https", port=443, internet_exposed=True)],
    vulnerabilities=[
        Vulnerability(
            title="Outdated OpenSSL",
            severity=Severity.HIGH,
            description="Patched version required",
            cve="CVE-2023-5678",
        )
    ],
)

print(asm.environment_risk_score())
print(asm.remediation_backlog())
```
