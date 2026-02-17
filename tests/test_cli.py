import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "asm_cli.py"), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )


def test_cli_demo_and_export(tmp_path):
    db = tmp_path / "asm.json"
    backlog = tmp_path / "backlog.json"

    run_cli("init-demo", "--db", str(db))
    dashboard = run_cli("dashboard", "--db", str(db))
    payload = json.loads(dashboard.stdout)
    assert payload["asset_count"] == 2

    run_cli("export-backlog", "--db", str(db), "--output", str(backlog))
    assert backlog.exists()
    backlog_payload = json.loads(backlog.read_text())
    assert isinstance(backlog_payload, list)
    assert len(backlog_payload) >= 1


def test_cli_add_asset_and_list(tmp_path):
    db = tmp_path / "state.json"
    run_cli(
        "add-asset",
        "asset-x",
        "x.example.edu",
        "Security",
        "--business-criticality",
        "5",
        "--exposure-level",
        "public",
        "--db",
        str(db),
    )

    listed = run_cli("list-assets", "--db", str(db))
    assert "asset-x" in listed.stdout
