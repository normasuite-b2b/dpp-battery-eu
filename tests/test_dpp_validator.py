"""Unit and CLI integration tests for dpp_battery_eu."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from dpp_battery_eu import (  # noqa: E402
    RULE_COUNT,
    RULES,
    TOTAL_WEIGHT,
    repair_passport,
    validate_passport,
    validate_passport_file,
)
from dpp_battery_eu.rules_annex_xiii import (  # noqa: E402
    TIER_ORDER,
    is_valid_en18219_identifier,
)


SAMPLES_DIR = PROJECT_ROOT / "samples"
COMPLIANT_SAMPLE = SAMPLES_DIR / "compliant_ev_battery_2027.jsonld"
NON_COMPLIANT_SAMPLE = SAMPLES_DIR / "non_compliant_industrial.jsonld"


class TestDppValidator(unittest.TestCase):
    """Verify rule coverage, tier-level gap detection, repair, and CLI exits."""

    def test_rule_catalog_completeness(self) -> None:
        self.assertGreaterEqual(RULE_COUNT, 22)
        self.assertEqual(RULE_COUNT, 26)
        self.assertEqual(TOTAL_WEIGHT, 100)
        rule_ids = [rule.rule_id for rule in RULES]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        for rule in RULES:
            self.assertIn(rule.tier, TIER_ORDER)
            self.assertIn(rule.severity, ("critical", "major"))

    def test_compliant_ev_battery_scores_100_percent(self) -> None:
        report = validate_passport_file(COMPLIANT_SAMPLE)
        self.assertTrue(report.compliant)
        self.assertEqual(report.readiness_score, 100.0)
        self.assertEqual(report.passed_count, RULE_COUNT)
        self.assertEqual(report.earned_weight, 100)
        self.assertEqual(report.battery_category, "EV")
        for tier_name in TIER_ORDER:
            tier = report.tiers[tier_name]
            self.assertEqual(tier.score_pct, 100.0)
            self.assertEqual(tier.failed_rule_ids, ())

    def test_non_compliant_industrial_exact_tier_gaps(self) -> None:
        report = validate_passport_file(NON_COMPLIANT_SAMPLE)
        self.assertFalse(report.compliant)
        self.assertLess(report.readiness_score, 100.0)
        self.assertEqual(report.battery_category, "Industrial_gt_2kWh")

        expected_failures = {
            "structural": ("DPP-STR-002", "DPP-STR-003", "DPP-STR-004"),
            "public": (
                "DPP-PUB-005",
                "DPP-PUB-007",
                "DPP-PUB-008",
                "DPP-PUB-010",
                "DPP-PUB-011",
                "DPP-PUB-012",
            ),
            "legitimate_interest": ("DPP-LEG-001", "DPP-LEG-002", "DPP-LEG-005"),
            "authorities": ("DPP-AUT-001", "DPP-AUT-002", "DPP-AUT-003"),
        }
        for tier_name, expected_ids in expected_failures.items():
            self.assertEqual(
                report.tiers[tier_name].failed_rule_ids,
                expected_ids,
                msg=f"Unexpected gaps in tier '{tier_name}'",
            )

    def test_en18219_identifier_variants(self) -> None:
        ok_urn, _ = is_valid_en18219_identifier(
            "urn:uuid:550e8400-e29b-41d4-a716-446655440000"
        )
        self.assertTrue(ok_urn)

        ok_gs1, _ = is_valid_en18219_identifier(
            "https://id.example.eu/01/04260999881011/21/SERIAL-01"
        )
        self.assertTrue(ok_gs1)

        bad_check, msg = is_valid_en18219_identifier(
            "https://id.example.eu/01/04260999881019/21/SERIAL-01"
        )
        self.assertFalse(bad_check)
        self.assertIn("check digit", msg)

    def test_repair_passport_preserves_valid_data_and_reaches_100(self) -> None:
        raw = json.loads(NON_COMPLIANT_SAMPLE.read_text(encoding="utf-8"))
        repaired = repair_passport(raw)
        report = validate_passport(repaired)

        self.assertTrue(report.compliant)
        self.assertEqual(report.readiness_score, 100.0)
        self.assertEqual(
            repaired["public"]["economicOperator"]["name"],
            "IndustriStorage Solutions S.L.",
        )
        self.assertEqual(repaired["public"]["batteryModel"], "IND-LFP-RACK-1800")
        self.assertNotIn("dismantlingManualUrl", repaired["public"])
        self.assertGreater(repaired["public"]["technicalSpecs"]["ratedEnergyKwh"], 2.0)

        # Ensure untouched compliant sample remains identical in outcome
        compliant_raw = json.loads(COMPLIANT_SAMPLE.read_text(encoding="utf-8"))
        compliant_copy = copy.deepcopy(compliant_raw)
        self.assertEqual(validate_passport(repair_passport(compliant_copy)).readiness_score, 100.0)

    def test_cli_exit_codes_and_json_output(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SRC_DIR)

        pass_proc = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                "-m",
                "dpp_battery_eu.cli",
                "validate",
                str(COMPLIANT_SAMPLE),
                "--json",
            ],
            cwd=str(PROJECT_ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        self.assertEqual(pass_proc.returncode, 0, msg=pass_proc.stderr)
        pass_json = json.loads(pass_proc.stdout)
        self.assertTrue(pass_json["compliant"])
        self.assertEqual(pass_json["readiness_score"], 100.0)

        fail_proc = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                "-m",
                "dpp_battery_eu.cli",
                "validate",
                str(NON_COMPLIANT_SAMPLE),
                "--json",
            ],
            cwd=str(PROJECT_ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        self.assertEqual(fail_proc.returncode, 1, msg=fail_proc.stderr)
        fail_json = json.loads(fail_proc.stdout)
        self.assertFalse(fail_json["compliant"])
        self.assertEqual(
            fail_json["tiers"]["authorities"]["failed_rule_ids"],
            ["DPP-AUT-001", "DPP-AUT-002", "DPP-AUT-003"],
        )

        rules_proc = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                "-m",
                "dpp_battery_eu.cli",
                "rules",
                "--json",
            ],
            cwd=str(PROJECT_ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        self.assertEqual(rules_proc.returncode, 0, msg=rules_proc.stderr)
        rules_json = json.loads(rules_proc.stdout)
        self.assertEqual(len(rules_json), 26)

        with tempfile.TemporaryDirectory() as tmpdir:
            repaired_path = Path(tmpdir) / "repaired.jsonld"
            repair_proc = subprocess.run(
                [
                    sys.executable,
                    "-X",
                    "utf8",
                    "-m",
                    "dpp_battery_eu.cli",
                    "validate",
                    str(NON_COMPLIANT_SAMPLE),
                    "--repair-out",
                    str(repaired_path),
                ],
                cwd=str(PROJECT_ROOT),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertEqual(repair_proc.returncode, 1)
            self.assertTrue(repaired_path.exists())

            recheck_proc = subprocess.run(
                [
                    sys.executable,
                    "-X",
                    "utf8",
                    "-m",
                    "dpp_battery_eu.cli",
                    "validate",
                    str(repaired_path),
                ],
                cwd=str(PROJECT_ROOT),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertEqual(recheck_proc.returncode, 0, msg=recheck_proc.stdout)

        missing_proc = subprocess.run(
            [
                sys.executable,
                "-X",
                "utf8",
                "-m",
                "dpp_battery_eu.cli",
                "validate",
                str(SAMPLES_DIR / "does_not_exist.jsonld"),
            ],
            cwd=str(PROJECT_ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        self.assertEqual(missing_proc.returncode, 2)

    def test_web_studio_parity_and_markdown_size_limits(self) -> None:
        web_dir = PROJECT_ROOT / "web"
        html = (web_dir / "index.html").read_text(encoding="utf-8")
        js = (web_dir / "dpp_studio.js").read_text(encoding="utf-8")
        css = (web_dir / "styles.css").read_text(encoding="utf-8")
        self.assertGreater(len(css), 200)

        html_ids = set(re.findall(r'id="([^"]+)"', html))
        for js_id in re.findall(r'document\.getElementById\("([^"]+)"\)', js):
            self.assertIn(js_id, html_ids, msg=f"Missing DOM id '{js_id}' in index.html")
        for tab_id in re.findall(r'data-tab="([^"]+)"', html):
            self.assertIn(tab_id, html_ids, msg=f"Missing tab panel '{tab_id}' in index.html")

        js_rules = re.findall(r'ruleId:\s*"([^"]+)"[\s\S]*?weight:\s*(\d+)', js)
        py_rules = [(rule.rule_id, str(rule.weight)) for rule in RULES]
        self.assertEqual(js_rules, py_rules)

        for md_file in PROJECT_ROOT.glob("*.md"):
            size_bytes = md_file.stat().st_size
            self.assertLess(size_bytes, 10240, msg=f"{md_file.name} exceeds 10 KB ({size_bytes} B)")
            self.assertLess(size_bytes, 16384, msg=f"{md_file.name} exceeds 16 KB ({size_bytes} B)")


if __name__ == "__main__":
    unittest.main()
