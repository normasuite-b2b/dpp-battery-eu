"""Command-line interface for dpp-battery-eu."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from . import __version__
from .rules_annex_xiii import RULES, TIER_ORDER
from .validator import ValidationReport, repair_passport, validate_passport_file


def _render_text_report(report: ValidationReport) -> str:
    status = "COMPLIANT" if report.compliant else "NON-COMPLIANT"
    lines = [
        f"EU Battery Passport Audit (Reg. (EU) 2023/1542 Annex XIII + EN 18219/18222)",
        f"Status         : {status}",
        f"Readiness Score: {report.readiness_score:.0f}% ({report.earned_weight}/{report.total_weight} pts, {report.passed_count}/{report.total_rules} rules)",
        f"Battery @id    : {report.battery_id}",
        f"Category       : {report.battery_category}",
        "",
        "Access Tier Breakdown:",
    ]
    for tier_name in TIER_ORDER:
        summary = report.tiers[tier_name]
        lines.append(
            f"  - {tier_name:<20} {summary.score_pct:6.2f}% ({summary.passed_count}/{summary.total_count} passed)"
        )

    failed = [f for f in report.findings if not f.passed]
    if failed:
        lines.append("")
        lines.append(f"Detected Gaps ({len(failed)}):")
        for item in failed:
            lines.append(
                f"  [{item.severity.upper()}] {item.rule_id} ({item.tier} | {item.legal_ref}): {item.message}"
            )
            lines.append(f"      Fix: {item.remediation}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="dpp-battery-eu",
        description="Validate EU Battery Passport JSON-LD against Regulation (EU) 2023/1542 Annex XIII, CIRPASS-2, EN 18219, and EN 18222.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_cmd = subparsers.add_parser(
        "validate", help="Validate a JSON-LD battery passport file."
    )
    validate_cmd.add_argument("file", help="Path to the .jsonld or .json file.")
    validate_cmd.add_argument(
        "--json", action="store_true", help="Emit full machine-readable JSON report."
    )
    validate_cmd.add_argument(
        "--repair-out",
        metavar="OUT_PATH",
        help="Write a 3-tier auto-repaired JSON-LD template to OUT_PATH.",
    )

    rules_cmd = subparsers.add_parser(
        "rules", help="List all Annex XIII / EN 18219 / EN 18222 validation rules."
    )
    rules_cmd.add_argument(
        "--json", action="store_true", help="Emit rule catalog as JSON."
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning 0 on compliance, 1 on gaps, 2 on input errors."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        if args.json:
            payload = [
                {
                    "rule_id": r.rule_id,
                    "tier": r.tier,
                    "legal_ref": r.legal_ref,
                    "title": r.title,
                    "severity": r.severity,
                    "weight": r.weight,
                    "field_path": r.field_path,
                }
                for r in RULES
            ]
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(f"Total Rules: {len(RULES)}")
            for rule in RULES:
                print(
                    f"{rule.rule_id} | {rule.tier:<19} | w={rule.weight} | {rule.legal_ref} | {rule.title}"
                )
        return 0

    if args.command == "validate":
        target = Path(args.file)
        try:
            report = validate_passport_file(target)
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            print(f"Error reading '{target}': {exc}", file=sys.stderr)
            return 2

        if args.repair_out:
            raw_data = json.loads(target.read_text(encoding="utf-8"))
            repaired = repair_passport(raw_data)
            out_path = Path(args.repair_out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps(repaired, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

        if args.json:
            print(report.to_json())
        else:
            print(_render_text_report(report))

        return 0 if report.compliant else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
