from asm_system import (
    Asset,
    AttackSurfaceManagementSystem,
    ExposureLevel,
    Service,
    Severity,
    Vulnerability,
)


def test_register_and_score_asset():
    asm = AttackSurfaceManagementSystem()
    asset = Asset(
        asset_id="asset-01",
        hostname="app.local",
        owner="SecOps",
        business_criticality=4,
        exposure_level=ExposureLevel.PUBLIC,
    )
    asm.register_asset(asset)

    asm.ingest_scan_result(
        "asset-01",
        services=[Service(name="https", port=443, internet_exposed=True)],
        vulnerabilities=[
            Vulnerability(title="Critical RCE", severity=Severity.CRITICAL, description="remote code execution")
        ],
    )

    assert asm.environment_risk_score() > 0
    assert asm.get_asset("asset-01").risk_score() == asm.environment_risk_score()


def test_remediation_reduces_risk():
    asm = AttackSurfaceManagementSystem()
    asset = Asset(asset_id="a1", hostname="db.local", owner="DBA")
    asm.register_asset(asset)
    asm.ingest_scan_result(
        "a1",
        vulnerabilities=[
            Vulnerability(title="Weak TLS", severity=Severity.HIGH, description="legacy TLS"),
            Vulnerability(title="Open Redis", severity=Severity.MEDIUM, description="no auth"),
        ],
    )

    pre_score = asm.environment_risk_score()
    assert asm.remediate("a1", "Weak TLS") is True
    assert asm.environment_risk_score() < pre_score


def test_remediation_backlog_sorted_by_risk_points():
    asm = AttackSurfaceManagementSystem()
    asm.register_asset(
        Asset(asset_id="public", hostname="site", owner="web", exposure_level=ExposureLevel.PUBLIC)
    )
    asm.register_asset(
        Asset(asset_id="internal", hostname="intra", owner="it", exposure_level=ExposureLevel.INTERNAL)
    )

    asm.ingest_scan_result(
        "public",
        vulnerabilities=[Vulnerability(title="XSS", severity=Severity.HIGH, description="xss")],
    )
    asm.ingest_scan_result(
        "internal",
        vulnerabilities=[Vulnerability(title="Old Package", severity=Severity.CRITICAL, description="old")],
    )

    backlog = asm.remediation_backlog()
    assert backlog[0]["asset_id"] == "public"
    assert backlog[0]["risk_points"] >= backlog[1]["risk_points"]


def test_save_and_load_roundtrip(tmp_path):
    asm = AttackSurfaceManagementSystem()
    asm.register_asset(Asset(asset_id="a", hostname="a.local", owner="team"))

    output = tmp_path / "asm.json"
    asm.save(output)

    loaded = AttackSurfaceManagementSystem.load(output)
    assert loaded.get_asset("a").hostname == "a.local"
