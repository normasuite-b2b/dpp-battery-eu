"""Zero-dependency EU Battery Passport JSON-LD validator (Regulation (EU) 2023/1542 Annex XIII)."""

from __future__ import annotations

from .rules_annex_xiii import RULE_COUNT, RULES, TOTAL_WEIGHT, RuleDefinition
from .validator import (
    RuleFinding,
    TierSummary,
    ValidationReport,
    repair_passport,
    validate_passport,
    validate_passport_file,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "RULES",
    "RULE_COUNT",
    "TOTAL_WEIGHT",
    "RuleDefinition",
    "RuleFinding",
    "TierSummary",
    "ValidationReport",
    "validate_passport",
    "validate_passport_file",
    "repair_passport",
]
