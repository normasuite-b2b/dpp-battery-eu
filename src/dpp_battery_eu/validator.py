"""Core EU Battery Passport validation and auto-repair engine.

Evaluates JSON-LD documents against Regulation (EU) 2023/1542 Annex XIII,
CIRPASS-2, EN 18219:2026 identifiers, and EN 18222:2026 lifecycle schemas.
"""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any

from .rules_annex_xiii import (
    ALLOWED_CARBON_CLASSES,
    ALLOWED_CATEGORIES,
    ALLOWED_LIFECYCLE_STATUSES,
    REQUIRED_LEGITIMATE_ROLES,
    RESTRICTED_KEYS_FORBIDDEN_IN_PUBLIC,
    RULES,
    TIER_ORDER,
    TOTAL_WEIGHT,
    _is_https_url,
    _is_iso_date_or_datetime,
    _is_non_empty_str,
    _is_non_neg_int,
    _is_number_in_range,
    is_valid_en18219_identifier,
)


@dataclass(frozen=True, slots=True)
class RuleFinding:
    """Outcome of evaluating a single compliance rule."""

    rule_id: str
    tier: str
    legal_ref: str
    title: str
    severity: str
    weight: int
    passed: bool
    message: str
    field_path: str
    remediation: str


@dataclass(frozen=True, slots=True)
class TierSummary:
    """Aggregated compliance score and failures for one access tier."""

    tier: str
    passed_count: int
    total_count: int
    earned_weight: int
    total_weight: int
    score_pct: float
    failed_rule_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """Complete EU Battery Passport pre-audit report."""

    compliant: bool
    readiness_score: float
    passed_count: int
    total_rules: int
    earned_weight: int
    total_weight: int
    battery_id: str
    battery_category: str
    tiers: dict[str, TierSummary]
    findings: tuple[RuleFinding, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to a JSON-compatible dictionary."""
        return {
            "compliant": self.compliant,
            "readiness_score": self.readiness_score,
            "passed_count": self.passed_count,
            "total_rules": self.total_rules,
            "earned_weight": self.earned_weight,
            "total_weight": self.total_weight,
            "battery_id": self.battery_id,
            "battery_category": self.battery_category,
            "tiers": {
                tier_name: {
                    **asdict(summary),
                    "failed_rule_ids": list(summary.failed_rule_ids),
                }
                for tier_name, summary in self.tiers.items()
            },
            "findings": [asdict(finding) for finding in self.findings],
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Render the report as formatted UTF-8 JSON."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def validate_passport(data: dict[str, Any]) -> ValidationReport:
    """Validate an in-memory Battery Passport JSON-LD dictionary."""
    if not isinstance(data, dict):
        raise TypeError("Battery passport root document must be a JSON object.")

    findings: list[RuleFinding] = []
    tier_buckets: dict[str, list[RuleFinding]] = {tier: [] for tier in TIER_ORDER}

    for rule in RULES:
        passed, message = rule.check(data)
        finding = RuleFinding(
            rule_id=rule.rule_id,
            tier=rule.tier,
            legal_ref=rule.legal_ref,
            title=rule.title,
            severity=rule.severity,
            weight=rule.weight,
            passed=passed,
            message=message,
            field_path=rule.field_path,
            remediation=rule.remediation,
        )
        findings.append(finding)
        tier_buckets[rule.tier].append(finding)

    tiers: dict[str, TierSummary] = {}
    for tier_name in TIER_ORDER:
        bucket = tier_buckets[tier_name]
        t_weight = sum(item.weight for item in bucket)
        e_weight = sum(item.weight for item in bucket if item.passed)
        p_count = sum(1 for item in bucket if item.passed)
        failed_ids = tuple(item.rule_id for item in bucket if not item.passed)
        score_pct = round((e_weight / t_weight) * 100.0, 2) if t_weight else 100.0
        tiers[tier_name] = TierSummary(
            tier=tier_name,
            passed_count=p_count,
            total_count=len(bucket),
            earned_weight=e_weight,
            total_weight=t_weight,
            score_pct=score_pct,
            failed_rule_ids=failed_ids,
        )

    earned_weight = sum(item.weight for item in findings if item.passed)
    passed_count = sum(1 for item in findings if item.passed)
    readiness_score = (
        round((earned_weight / TOTAL_WEIGHT) * 100.0, 2) if TOTAL_WEIGHT else 100.0
    )

    pub = data.get("public") if isinstance(data.get("public"), dict) else {}
    battery_id = str(data.get("@id") or "UNSPECIFIED")
    battery_category = str(pub.get("batteryCategory") or "UNSPECIFIED")

    return ValidationReport(
        compliant=(passed_count == len(RULES)),
        readiness_score=readiness_score,
        passed_count=passed_count,
        total_rules=len(RULES),
        earned_weight=earned_weight,
        total_weight=TOTAL_WEIGHT,
        battery_id=battery_id,
        battery_category=battery_category,
        tiers=tiers,
        findings=tuple(findings),
    )


def validate_passport_file(path: str | Path) -> ValidationReport:
    """Load and validate a Battery Passport JSON-LD file from disk."""
    file_path = Path(path)
    raw_text = file_path.read_text(encoding="utf-8")
    data = json.loads(raw_text)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in '{file_path}', got {type(data).__name__}.")
    return validate_passport(data)


def _ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    val = parent.get(key)
    if not isinstance(val, dict):
        val = {}
        parent[key] = val
    return val


def _fill_defaults(
    target: dict[str, Any],
    defaults: dict[str, Any],
    validators: dict[str, Any] | None = None,
) -> None:
    """Populate missing or invalid keys in `target` from `defaults`."""
    validators = validators or {}
    for key, default_val in defaults.items():
        current = target.get(key)
        check_fn = validators.get(key)
        if check_fn is not None:
            if not check_fn(current):
                target[key] = copy.deepcopy(default_val)
        elif current is None or (isinstance(default_val, str) and not _is_non_empty_str(current)):
            target[key] = copy.deepcopy(default_val)


def repair_passport(data: dict[str, Any]) -> dict[str, Any]:
    """Return a repaired copy of `data` satisfying all 26 Annex XIII / EN 18222 rules.

    Valid existing manufacturer values are preserved wherever present.
    """
    doc = copy.deepcopy(data) if isinstance(data, dict) else {}

    # Structural & EN 18219 / EN 18222
    ctx = doc.get("@context")
    if not (
        _is_non_empty_str(ctx)
        or (isinstance(ctx, dict) and len(ctx) > 0)
        or (isinstance(ctx, list) and len(ctx) > 0)
    ):
        doc["@context"] = [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/cirpass2/battery-passport/v1",
            "https://gs1.org/voc/",
        ]
    doc.setdefault("@type", "BatteryPassport")

    ok_id, _ = is_valid_en18219_identifier(doc.get("@id"))
    if not ok_id:
        doc["@id"] = "https://id.example-battery-oem.eu/01/04260999881011/21/REPAIRED-2027-001"

    lifecycle = _ensure_dict(doc, "lifecycleMetadata")
    _fill_defaults(
        lifecycle,
        {
            "dppSchemaVersion": "CIRPASS-2/EN18222:2026-v1.0",
            "passportStatus": "active",
            "apiEndpoint": "https://dpp.example-battery-oem.eu/api/v1/passports",
            "issuedAt": "2026-11-20T09:00:00Z",
            "lastUpdatedAt": "2026-11-20T09:00:00Z",
        },
        {
            "passportStatus": lambda v: v in ALLOWED_LIFECYCLE_STATUSES,
            "apiEndpoint": _is_https_url,
            "issuedAt": _is_iso_date_or_datetime,
            "lastUpdatedAt": _is_iso_date_or_datetime,
        },
    )

    # Three access tiers + leak scrub
    pub = _ensure_dict(doc, "public")
    for leaked_key in list(pub.keys()):
        if leaked_key in RESTRICTED_KEYS_FORBIDDEN_IN_PUBLIC:
            pub.pop(leaked_key, None)

    leg = _ensure_dict(doc, "legitimateInterest")
    aut = _ensure_dict(doc, "authorities")

    # Public Tier
    op = _ensure_dict(pub, "economicOperator")
    _fill_defaults(
        op,
        {
            "name": "Example European Battery Manufacturing GmbH",
            "identifier": "DE-EORI-9988776655",
            "contactAddress": "Industriestrasse 14, 80331 Munich, Germany",
            "contactEmail": "dpp-compliance@example-battery-oem.eu",
        },
    )

    if pub.get("batteryCategory") not in ALLOWED_CATEGORIES:
        pub["batteryCategory"] = "Industrial_gt_2kWh"
    if not _is_non_empty_str(pub.get("batteryModel")):
        pub["batteryModel"] = "BATT-EU-2027-SERIES"
    if not _is_non_empty_str(pub.get("serialOrBatchNumber")):
        pub["serialOrBatchNumber"] = "SN-2027-0001"

    mfg = _ensure_dict(pub, "manufacturing")
    _fill_defaults(
        mfg,
        {
            "plantName": "Gigafactory Plant 1",
            "countryCode": "DE",
            "manufacturingDate": "2026-10-15",
        },
        {
            "countryCode": lambda v: _is_non_empty_str(v) and len(v.strip()) == 2 and v.strip().isupper(),
            "manufacturingDate": _is_iso_date_or_datetime,
        },
    )

    specs = _ensure_dict(pub, "technicalSpecs")
    is_ind = pub.get("batteryCategory") == "Industrial_gt_2kWh"
    _fill_defaults(
        specs,
        {
            "weightKg": 240.0,
            "nominalVoltageV": 400.0,
            "ratedCapacityAh": 150.0,
            "ratedEnergyKwh": 60.0 if is_ind else 45.0,
        },
        {
            "weightKg": lambda v: _is_number_in_range(v, 0.0, strict_min=True),
            "nominalVoltageV": lambda v: _is_number_in_range(v, 0.0, strict_min=True),
            "ratedCapacityAh": lambda v: _is_number_in_range(v, 0.0, strict_min=True),
            "ratedEnergyKwh": lambda v: _is_number_in_range(
                v, 2.0 if is_ind else 0.0, strict_min=True
            ),
        },
    )

    chem = _ensure_dict(pub, "chemistry")
    _fill_defaults(
        chem,
        {
            "chemistryType": "LFP",
            "cathodeMaterial": "LiFePO4",
            "anodeMaterial": "Natural & synthetic graphite",
            "electrolyte": "LiPF6 in organic carbonate blend",
        },
    )

    haz = _ensure_dict(pub, "hazardousSubstances")
    if not isinstance(haz.get("present"), bool):
        haz["present"] = False
    if haz["present"] is False and not _is_non_empty_str(haz.get("declarationStatement")):
        haz["declarationStatement"] = (
            "No mercury, cadmium, or lead above Regulation (EU) 2023/1542 Annex I thresholds."
        )
    elif haz["present"] is True and (
        not isinstance(haz.get("substances"), list) or len(haz["substances"]) == 0
    ):
        haz["substances"] = [
            {
                "name": "Lithium hexafluorophosphate",
                "casNumber": "21324-40-3",
                "location": "Electrolyte",
            }
        ]

    crm = _ensure_dict(pub, "criticalRawMaterials")
    for mat in ("cobalt", "lithium", "nickel"):
        val = crm.get(mat)
        valid_num = _is_number_in_range(val, 0.0)
        valid_obj = isinstance(val, dict) and (
            _is_number_in_range(val.get("massKg"), 0.0)
            or _is_number_in_range(val.get("sharePct"), 0.0, 100.0)
        )
        if not (valid_num or valid_obj):
            crm[mat] = {"massKg": 0.0 if mat in ("cobalt", "nickel") else 4.2, "sharePct": 0.0 if mat in ("cobalt", "nickel") else 1.75}

    cf = _ensure_dict(pub, "carbonFootprint")
    _fill_defaults(
        cf,
        {
            "totalKgCo2ePerKwh": 62.4,
            "calculationMethodology": "Regulation (EU) 2023/1542 Annex II / PEFCR",
            "performanceClass": "B",
            "publicStudyUrl": "https://dpp.example-battery-oem.eu/studies/cf-2027.pdf",
        },
        {
            "totalKgCo2ePerKwh": lambda v: _is_number_in_range(v, 0.0, strict_min=True),
            "performanceClass": lambda v: v in ALLOWED_CARBON_CLASSES,
            "publicStudyUrl": _is_https_url,
        },
    )
    stages = _ensure_dict(cf, "lifecycleStages")
    _fill_defaults(
        stages,
        {
            "rawMaterialAcquisition": 38.5,
            "manufacturing": 18.2,
            "distribution": 2.4,
            "endOfLife": 3.3,
        },
        {
            s: (lambda v: _is_number_in_range(v, 0.0))
            for s in (
                "rawMaterialAcquisition",
                "manufacturing",
                "distribution",
                "endOfLife",
            )
        },
    )

    rc = _ensure_dict(pub, "recycledContent")
    _fill_defaults(
        rc,
        {
            "cobaltPct": 16.0,
            "leadPct": 85.0,
            "lithiumPct": 6.0,
            "nickelPct": 6.0,
        },
        {
            k: (lambda v: _is_number_in_range(v, 0.0, 100.0))
            for k in ("cobaltPct", "leadPct", "lithiumPct", "nickelPct")
        },
    )

    doc_eu = _ensure_dict(pub, "euDeclarationOfConformity")
    _fill_defaults(
        doc_eu,
        {
            "declarationId": "EU-DOC-2027-001",
            "issueDate": "2026-10-20",
            "ceMarkingConfirmed": True,
            "documentUrl": "https://dpp.example-battery-oem.eu/conformity/eu-doc-2027.pdf",
        },
        {
            "issueDate": _is_iso_date_or_datetime,
            "ceMarkingConfirmed": lambda v: v is True,
            "documentUrl": _is_https_url,
        },
    )

    eol = _ensure_dict(pub, "endOfLifeAndSafety")
    _fill_defaults(
        eol,
        {
            "separateCollectionSymbol": True,
            "extinguishingAgent": "CO2, dry powder, or high-volume water mist per EN 50604",
            "safetyInstructionsUrl": "https://dpp.example-battery-oem.eu/safety/handling-guide.pdf",
        },
        {
            "separateCollectionSymbol": lambda v: v is True,
            "safetyInstructionsUrl": _is_https_url,
        },
    )

    perf = _ensure_dict(pub, "performanceIndicators")
    _fill_defaults(
        perf,
        {
            "expectedLifetimeCycles": 3000,
            "expectedLifetimeYears": 10,
            "roundTripEfficiencyPct": 93.5,
        },
        {
            "expectedLifetimeCycles": lambda v: _is_number_in_range(v, 0.0, strict_min=True),
            "expectedLifetimeYears": lambda v: _is_number_in_range(v, 0.0, strict_min=True),
            "roundTripEfficiencyPct": lambda v: _is_number_in_range(v, 0.0, 100.0, strict_min=True),
        },
    )

    # Tier 2: Legitimate Interest
    leg_policy = _ensure_dict(leg, "accessPolicy")
    _fill_defaults(
        leg_policy,
        {
            "accessScope": "restricted_legitimate_interest",
            "authMethod": "eIDAS_OIDC_VC",
            "authorizedRoles": sorted(REQUIRED_LEGITIMATE_ROLES),
        },
        {
            "accessScope": lambda v: v == "restricted_legitimate_interest",
            "authorizedRoles": lambda v: isinstance(v, list)
            and REQUIRED_LEGITIMATE_ROLES.issubset({str(r).strip() for r in v}),
        },
    )

    dismantling = _ensure_dict(leg, "dismantlingInfo")
    _fill_defaults(
        dismantling,
        {
            "manualUrl": "https://dpp.example-battery-oem.eu/restricted/dismantling-manual.pdf",
            "explodedDiagramsUrl": "https://dpp.example-battery-oem.eu/restricted/exploded-diagrams.svg",
            "requiredTools": ["Insulated 1000V torque wrench", "HV PPE Class 0 gloves"],
            "highVoltageSafetyProtocol": "Isolate service disconnect, wait 10 min, verify <60V DC before opening pack.",
        },
        {
            "manualUrl": _is_https_url,
            "explodedDiagramsUrl": _is_https_url,
            "requiredTools": lambda v: isinstance(v, list) and any(_is_non_empty_str(t) for t in v),
        },
    )

    if not isinstance(leg.get("spareParts"), list) or len(leg["spareParts"]) == 0:
        leg["spareParts"] = [
            {
                "partNumber": "SP-BMS-400V-01",
                "componentName": "Battery Management System Master Board",
                "supplierContact": "spares@example-battery-oem.eu",
                "availabilityYears": 10,
            }
        ]

    det_comp = _ensure_dict(leg, "detailedComposition")
    _fill_defaults(
        det_comp,
        {
            "cathodeActiveMaterial": "LiFePO4 (94 wt%) + conductive carbon + PVDF binder",
            "anodeActiveMaterial": "Graphite (96 wt%) + CMC/SBR binder on Cu foil",
            "electrolyteComposition": "1.0M LiPF6 in EC:EMC (3:7) with 2% VC additive",
            "hazardousComponentLocations": [
                {"component": "Electrolyte cells", "location": "Modules M1-M8"}
            ],
        },
        {
            "hazardousComponentLocations": lambda v: (
                (isinstance(v, list) and len(v) > 0)
                or (isinstance(v, dict) and len(v) > 0)
            )
        },
    )

    dyn = _ensure_dict(leg, "dynamicHealthSchema")
    _fill_defaults(
        dyn,
        {
            "stateOfHealthPct": 100.0,
            "remainingCapacityAh": specs["ratedCapacityAh"],
            "fullChargeCycles": 0,
            "deepDischargeEvents": 0,
            "extremeTempExposureEvents": 0,
            "lastTelemetryTimestamp": "2026-11-20T09:00:00Z",
            "updateFrequency": "on_event",
        },
        {
            "stateOfHealthPct": lambda v: _is_number_in_range(v, 0.0, 100.0),
            "remainingCapacityAh": lambda v: _is_number_in_range(v, 0.0),
            "fullChargeCycles": _is_non_neg_int,
            "deepDischargeEvents": _is_non_neg_int,
            "extremeTempExposureEvents": _is_non_neg_int,
            "lastTelemetryTimestamp": _is_iso_date_or_datetime,
        },
    )

    # Tier 3: Authorities
    aut_policy = _ensure_dict(aut, "accessPolicy")
    _fill_defaults(
        aut_policy,
        {
            "accessScope": "market_surveillance_and_notified_bodies",
            "notifiedBodyId": "NB-0123",
            "competentAuthorityEndpoint": "https://dpp.example-battery-oem.eu/authorities/v1/dossier",
        },
        {
            "accessScope": lambda v: v == "market_surveillance_and_notified_bodies",
            "competentAuthorityEndpoint": _is_https_url,
        },
    )

    reports = aut.get("testReports")
    if not isinstance(reports, list):
        reports = []
    valid_reports = [
        rep
        for rep in reports
        if isinstance(rep, dict)
        and _is_non_empty_str(rep.get("reportId"))
        and _is_non_empty_str(rep.get("annexRef"))
        and _is_non_empty_str(rep.get("standardRef"))
        and _is_non_empty_str(rep.get("accreditedLab"))
        and _is_iso_date_or_datetime(rep.get("testDate"))
        and rep.get("result") == "PASS"
    ]
    existing_annex_text = " ".join(rep["annexRef"].upper() for rep in valid_reports)
    required_templates = [
        (
            "ANNEX III",
            {
                "reportId": "TR-ANNEX-III-2027",
                "annexRef": "Annex III",
                "standardRef": "Regulation (EU) 2023/1542 Annex III Sustainability & Safety",
                "accreditedLab": "DEKRA Testing & Certification GmbH",
                "testDate": "2026-10-01",
                "result": "PASS",
            },
        ),
        (
            "ANNEX IV",
            {
                "reportId": "TR-ANNEX-IV-2027",
                "annexRef": "Annex IV",
                "standardRef": "IEC 62660-1 / Annex IV Performance & Durability",
                "accreditedLab": "TUV Rheinland Kraftfahrt GmbH",
                "testDate": "2026-10-05",
                "result": "PASS",
            },
        ),
        (
            "ANNEX V",
            {
                "reportId": "TR-ANNEX-V-2027",
                "annexRef": "Annex V",
                "standardRef": "UN 38.3 / EN 50604-1 / Annex V Safety Parameters",
                "accreditedLab": "TUV SUD Battery Testing",
                "testDate": "2026-10-08",
                "result": "PASS",
            },
        ),
    ]
    for marker, template in required_templates:
        if marker not in existing_annex_text:
            valid_reports.append(template)
    aut["testReports"] = valid_reports

    ver = _ensure_dict(aut, "conformityVerification")
    _fill_defaults(
        ver,
        {
            "assessmentModule": "Module D1",
            "technicalDocumentationRef": "TECH-DOC-EU-2023-1542-2027",
            "carbonFootprintVerificationRef": "CF-VER-NB0123-2027",
        },
    )

    return doc
