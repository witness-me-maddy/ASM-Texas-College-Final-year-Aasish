from __future__ import annotations

import argparse
import json
from pathlib import Path

from asm_system import (
    Asset,
    AttackSurfaceManagementSystem,
    ExposureLevel,
    Severity,
    Vulnerability,
    seed_demo_environment,
)


def load_or_new(path: Path) -> AttackSurfaceManagementSystem:
    if path.exists():
        return AttackSurfaceManagementSystem.load(path)
    return AttackSurfaceManagementSystem()


def cmd_init_demo(args: argparse.Namespace) -> None:
    asm = seed_demo_environment()
    asm.save(args.db)
    print(f"Demo environment written to {args.db}")


def cmd_dashboard(args: argparse.Namespace) -> None:
    asm = load_or_new(args.db)
    print(json.dumps(asm.dashboard(), indent=2))


def cmd_add_asset(args: argparse.Namespace) -> None:
    asm = load_or_new(args.db)
    asm.register_asset(
        Asset(
            asset_id=args.asset_id,
            hostname=args.hostname,
            owner=args.owner,
            business_criticality=args.business_criticality,
            exposure_level=ExposureLevel(args.exposure_level),
            tags=args.tags,
        )
    )
    asm.save(args.db)
    print(f"Asset {args.asset_id} added")


def cmd_add_vuln(args: argparse.Namespace) -> None:
    asm = load_or_new(args.db)
    asm.ingest_scan_result(
        args.asset_id,
        vulnerabilities=[
            Vulnerability(
                title=args.title,
                severity=Severity(args.severity),
                description=args.description,
                cve=args.cve,
                affected_service=args.service,
            )
        ],
    )
    asm.save(args.db)
    print(f"Vulnerability '{args.title}' added to {args.asset_id}")


def cmd_remediate(args: argparse.Namespace) -> None:
    asm = load_or_new(args.db)
    changed = asm.remediate(args.asset_id, args.title)
    asm.save(args.db)
    if changed:
        print(f"Remediated '{args.title}' on {args.asset_id}")
    else:
        print(f"No open vulnerability named '{args.title}' found on {args.asset_id}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Attack Surface Management CLI")
    parser.add_argument("--db", type=Path, default=Path("data/asm_state.json"), help="Path to ASM JSON state file")

    subparsers = parser.add_subparsers(dest="command", required=True)

    init_demo = subparsers.add_parser("init-demo", help="Create demo ASM dataset")
    init_demo.set_defaults(func=cmd_init_demo)

    dashboard = subparsers.add_parser("dashboard", help="Print dashboard summary")
    dashboard.set_defaults(func=cmd_dashboard)

    add_asset = subparsers.add_parser("add-asset", help="Register a new asset")
    add_asset.add_argument("asset_id")
    add_asset.add_argument("hostname")
    add_asset.add_argument("owner")
    add_asset.add_argument("--business-criticality", type=int, default=3)
    add_asset.add_argument("--exposure-level", choices=[e.value for e in ExposureLevel], default="internal")
    add_asset.add_argument("--tags", nargs="*", default=[])
    add_asset.set_defaults(func=cmd_add_asset)

    add_vuln = subparsers.add_parser("add-vuln", help="Attach vulnerability to an asset")
    add_vuln.add_argument("asset_id")
    add_vuln.add_argument("title")
    add_vuln.add_argument("description")
    add_vuln.add_argument("--severity", choices=[s.value for s in Severity], default="medium")
    add_vuln.add_argument("--cve")
    add_vuln.add_argument("--service")
    add_vuln.set_defaults(func=cmd_add_vuln)

    remediate = subparsers.add_parser("remediate", help="Mark vulnerability as remediated")
    remediate.add_argument("asset_id")
    remediate.add_argument("title")
    remediate.set_defaults(func=cmd_remediate)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
