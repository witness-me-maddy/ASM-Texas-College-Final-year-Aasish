from asm_system import (
    Asset,
    AttackSurfaceManagementSystem,
    ExposureLevel,
    Service,
    Severity,
    Vulnerability,
    seed_demo_environment,
)


def test_register_and_score_asset():
    asm = AttackSurfaceManagementSystem()
    asm.register_asset(
        Asset(
            asset_id="asset-01",
            hostname="app.local",
            owner="SecOps",
            business_criticality=4,
            exposure_level=ExposureLevel.PUBLIC,
        )
    )

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
    asm.register_asset(Asset(asset_id="a1", hostname="db.local", owner="DBA"))
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
    asm.register_asset(Asset(asset_id="public", hostname="site", owner="web", exposure_level=ExposureLevel.PUBLIC))
    asm.register_asset(Asset(asset_id="internal", hostname="intra", owner="it", exposure_level=ExposureLevel.INTERNAL))

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
    asm.register_asset(Asset(asset_id="a", hostname="a.local", owner="team", tags=["core"]))

    output = tmp_path / "asm.json"
    asm.save(output)

    loaded = AttackSurfaceManagementSystem.load(output)
    assert loaded.get_asset("a").hostname == "a.local"
    assert loaded.get_asset("a").tags == ["core"]


def test_dashboard_contains_expected_keys():
    asm = seed_demo_environment()
    dashboard = asm.dashboard()

    assert dashboard["asset_count"] == 2
    assert "severity_summary" in dashboard
    assert "top_risks" in dashboard


def test_duplicate_service_is_ignored_during_ingest():
    asm = AttackSurfaceManagementSystem()
    asm.register_asset(Asset(asset_id="dup", hostname="dup.local", owner="Ops"))

    asm.ingest_scan_result("dup", services=[Service(name="https", port=443)])
    asm.ingest_scan_result("dup", services=[Service(name="https", port=443)])

    assert len(asm.get_asset("dup").services) == 1


def test_duplicate_open_vulnerability_not_added_twice():
    asm = AttackSurfaceManagementSystem()
    asm.register_asset(Asset(asset_id="vdup", hostname="vdup.local", owner="Ops"))

    vuln = Vulnerability(title="TLS Weak", severity=Severity.MEDIUM, description="desc", affected_service="https")
    asm.ingest_scan_result("vdup", vulnerabilities=[vuln])
    asm.ingest_scan_result("vdup", vulnerabilities=[vuln])

    assert len(asm.get_asset("vdup").open_vulnerabilities()) == 1
