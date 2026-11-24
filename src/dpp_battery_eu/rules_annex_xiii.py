"""Concrete validation rules for Regulation (EU) 2023/1542 Annex XIII,
CIRPASS-2, EN 18219:2026 (identifiers), and EN 18222:2026 (DPP lifecycle APIs).

Zero external dependencies: pure Python 3.11 standard library.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
import re
from typing import Any, Callable
from urllib.parse import urlparse


ALLOWED_CATEGORIES = frozenset({"EV", "LMT", "Industrial_gt_2kWh"})
ALLOWED_CARBON_CLASSES = frozenset({"A", "B", "C", "D", "E"})
ALLOWED_LIFECYCLE_STATUSES = frozenset(
    {"active", "inactive", "end_of_life", "repurposed"}
)
REQUIRED_LEGITIMATE_ROLES = frozenset(
    {"repairer", "remanufacturer", "second_life_operator", "recycler"}
)
RESTRICTED_KEYS_FORBIDDEN_IN_PUBLIC = frozenset(
    {
        "dismantlingInfo",
        "dismantlingManualUrl",
        "spareParts",
        "detailedComposition",
        "dynamicHealthSchema",
        "testReports",
        "conformityVerification",
        "notifiedBodyId",
    }
)
TIER_ORDER = ("structural", "public", "legitimate_interest", "authorities")

_ISO_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_URN_RE = re.compile(
    r"^urn:(uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|"
    r"(epc|iec61406|gs1):[A-Za-z0-9._:/-]+)$"
)
_GS1_GTIN_PATH_RE = re.compile(r"/01/(\d{14})(?:/|$)")
_GS1_SERIAL_OR_BATCH_RE = re.compile(r"/(21|10)/([^/?#]+)")


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Declarative specification of a single EU Battery Passport rule."""

    rule_id: str
    tier: str
    legal_ref: str
    title: str
    severity: str
    weight: int
    field_path: str
    remediation: str
    check: Callable[[dict[str, Any]], tuple[bool, str]]


def _is_non_empty_str(value: Any) -> bool:
    return isinstance(value, str) and len(value.strip()) > 0


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_non_neg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_number_in_range(
    value: Any,
    minimum: float | None = None,
    maximum: float | None = None,
    *,
    strict_min: bool = False,
) -> bool:
    if not _is_number(value):
        return False
    num = float(value)
    if minimum is not None:
        if strict_min and not (num > minimum):
            return False
        if not strict_min and not (num >= minimum):
            return False
    if maximum is not None and not (num <= maximum):
        return False
    return True


def _is_https_url(value: Any) -> bool:
    if not _is_non_empty_str(value):
        return False
    parsed = urlparse(value.strip())
    return parsed.scheme == "https" and bool(parsed.netloc)


def _is_iso_date_or_datetime(value: Any) -> bool:
    if not _is_non_empty_str(value):
        return False
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        if "T" in text or " " in text:
            datetime.fromisoformat(text)
        else:
            date.fromisoformat(text)
        return True
    except ValueError:
        return False


def is_valid_gtin14(gtin: str) -> bool:
    """Validate a 14-digit GS1 GTIN using the standard Mod-10 check digit."""
    if not isinstance(gtin, str) or not re.fullmatch(r"\d{14}", gtin):
        return False
    weighted_sum = sum(
        int(digit) * (3 if idx % 2 == 0 else 1)
        for idx, digit in enumerate(gtin[:13])
    )
    expected_check = (10 - (weighted_sum % 10)) % 10
    return int(gtin[13]) == expected_check


def is_valid_en18219_identifier(value: Any) -> tuple[bool, str]:
    """Validate @id against EN 18219:2026 URN or GS1 Digital Link rules."""
    if not _is_non_empty_str(value):
        return False, "Missing or empty '@id' identifier."
    identifier = value.strip()
    if identifier.startswith("urn:"):
        if _URN_RE.match(identifier):
            return True, "Valid EN 18219 URN identifier."
        return (
            False,
            "Invalid URN syntax; expected urn:uuid:..., urn:epc:..., urn:iec61406:..., or urn:gs1:....",
        )
    if _is_https_url(identifier):
        parsed = urlparse(identifier)
        gtin_match = _GS1_GTIN_PATH_RE.search(parsed.path)
        if not gtin_match:
            return False, "GS1 Digital Link must contain '/01/<14-digit-GTIN>'."
        gtin = gtin_match.group(1)
        if not is_valid_gtin14(gtin):
            return False, f"Invalid GS1 GTIN-14 check digit in '{gtin}'."
        if not _GS1_SERIAL_OR_BATCH_RE.search(parsed.path):
            return (
                False,
                "GS1 Digital Link must include serial ('/21/<serial>') or batch ('/10/<batch>') qualifier.",
            )
        return True, f"Valid GS1 Digital Link (GTIN-14 {gtin})."
    return (
        False,
        "Identifier '@id' must be a valid URN or HTTPS GS1 Digital Link URI (EN 18219:2026).",
    )


def _get_dict(parent: dict[str, Any], key: str) -> dict[str, Any] | None:
    val = parent.get(key)
    return val if isinstance(val, dict) else None


def _check_str_001(doc: dict[str, Any]) -> tuple[bool, str]:
    ctx = doc.get("@context")
    if _is_non_empty_str(ctx):
        return True, "JSON-LD @context string declared."
    if isinstance(ctx, dict) and len(ctx) > 0:
        return True, "JSON-LD @context object declared."
    if isinstance(ctx, list) and len(ctx) > 0 and all(
        _is_non_empty_str(item) or (isinstance(item, dict) and len(item) > 0)
        for item in ctx
    ):
        return True, "JSON-LD @context array declared."
    return False, "Missing or invalid JSON-LD '@context' declaration."


def _check_str_002(doc: dict[str, Any]) -> tuple[bool, str]:
    return is_valid_en18219_identifier(doc.get("@id"))


def _check_str_003(doc: dict[str, Any]) -> tuple[bool, str]:
    meta = _get_dict(doc, "lifecycleMetadata")
    if meta is None:
        return False, "Missing 'lifecycleMetadata' object (EN 18222:2026)."
    missing: list[str] = []
    if not _is_non_empty_str(meta.get("dppSchemaVersion")):
        missing.append("dppSchemaVersion")
    if meta.get("passportStatus") not in ALLOWED_LIFECYCLE_STATUSES:
        missing.append(
            f"passportStatus ({'|'.join(sorted(ALLOWED_LIFECYCLE_STATUSES))})"
        )
    if not _is_https_url(meta.get("apiEndpoint")):
        missing.append("apiEndpoint (https://)")
    if not _is_iso_date_or_datetime(meta.get("issuedAt")):
        missing.append("issuedAt (ISO-8601)")
    if not _is_iso_date_or_datetime(meta.get("lastUpdatedAt")):
        missing.append("lastUpdatedAt (ISO-8601)")
    if missing:
        return False, "Incomplete EN 18222 lifecycleMetadata: " + ", ".join(missing)
    return True, "EN 18222 lifecycle metadata valid."


def _check_str_004(doc: dict[str, Any]) -> tuple[bool, str]:
    missing_tiers = [
        tier
        for tier in ("public", "legitimateInterest", "authorities")
        if not isinstance(doc.get(tier), dict)
    ]
    if missing_tiers:
        return (
            False,
            "Missing top-level access tier object(s): " + ", ".join(missing_tiers),
        )
    pub = doc["public"]
    leaked = sorted(k for k in pub if k in RESTRICTED_KEYS_FORBIDDEN_IN_PUBLIC)
    if leaked:
        return (
            False,
            "Restricted fields leaked into 'public' tier: " + ", ".join(leaked),
        )
    return True, "Three-tier access partitioning cleanly enforced."


def _check_pub_001(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    op = _get_dict(pub, "economicOperator")
    if op is None:
        return False, "Missing 'public.economicOperator' object."
    missing = [
        key
        for key in ("name", "identifier")
        if not _is_non_empty_str(op.get(key))
    ]
    if not (
        _is_non_empty_str(op.get("contactAddress"))
        or _is_non_empty_str(op.get("contactEmail"))
    ):
        missing.append("contactAddress/contactEmail")
    if missing:
        return False, "Incomplete economicOperator fields: " + ", ".join(missing)
    return True, "Economic operator identity complete."


def _check_pub_002(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    cat = pub.get("batteryCategory")
    if cat not in ALLOWED_CATEGORIES:
        return (
            False,
            f"Invalid 'batteryCategory' ({cat!r}); expected one of EV, LMT, Industrial_gt_2kWh.",
        )
    missing = [
        key
        for key in ("batteryModel", "serialOrBatchNumber")
        if not _is_non_empty_str(pub.get(key))
    ]
    if missing:
        return False, "Missing battery identification fields: " + ", ".join(missing)
    return True, f"Category '{cat}', model, and serial/batch declared."


def _check_pub_003(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    mfg = _get_dict(pub, "manufacturing")
    if mfg is None:
        return False, "Missing 'public.manufacturing' object."
    issues: list[str] = []
    if not (
        _is_non_empty_str(mfg.get("plantName"))
        or _is_non_empty_str(mfg.get("facilityId"))
    ):
        issues.append("plantName/facilityId")
    country = mfg.get("countryCode")
    if not (_is_non_empty_str(country) and _ISO_COUNTRY_RE.match(country.strip())):
        issues.append("countryCode (ISO 3166-1 alpha-2)")
    if not _is_iso_date_or_datetime(mfg.get("manufacturingDate")):
        issues.append("manufacturingDate (ISO-8601)")
    if issues:
        return False, "Invalid manufacturing details: " + ", ".join(issues)
    return True, "Manufacturing plant and date valid."


def _check_pub_004(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    specs = _get_dict(pub, "technicalSpecs") or {}
    weight = specs.get("weightKg")
    if not _is_number_in_range(weight, 0.0, strict_min=True):
        return False, "Missing or non-positive 'public.technicalSpecs.weightKg'."
    return True, f"Battery weight declared ({weight} kg)."


def _check_pub_005(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    specs = _get_dict(pub, "technicalSpecs")
    if specs is None:
        return False, "Missing 'public.technicalSpecs' object."
    invalid = [
        key
        for key in ("nominalVoltageV", "ratedCapacityAh", "ratedEnergyKwh")
        if not _is_number_in_range(specs.get(key), 0.0, strict_min=True)
    ]
    if invalid:
        return False, "Invalid or non-positive technicalSpecs: " + ", ".join(invalid)
    if (
        pub.get("batteryCategory") == "Industrial_gt_2kWh"
        and float(specs["ratedEnergyKwh"]) <= 2.0
    ):
        return (
            False,
            "Category 'Industrial_gt_2kWh' requires 'ratedEnergyKwh' > 2.0 kWh.",
        )
    return True, "Nominal voltage, rated capacity, and energy valid."


def _check_pub_006(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    chem = _get_dict(pub, "chemistry")
    if chem is None:
        return False, "Missing 'public.chemistry' object."
    missing = [
        key
        for key in ("chemistryType", "cathodeMaterial", "anodeMaterial", "electrolyte")
        if not _is_non_empty_str(chem.get(key))
    ]
    if missing:
        return False, "Incomplete battery chemistry fields: " + ", ".join(missing)
    return True, "Battery chemistry composition declared."


def _check_pub_007(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    haz = _get_dict(pub, "hazardousSubstances")
    if haz is None:
        return False, "Missing 'public.hazardousSubstances' declaration."
    present = haz.get("present")
    if not isinstance(present, bool):
        return False, "'public.hazardousSubstances.present' must be a boolean."
    if not present:
        if not _is_non_empty_str(haz.get("declarationStatement")):
            return (
                False,
                "When hazardousSubstances.present is false, 'declarationStatement' is required.",
            )
        return True, "Absence of reportable hazardous substances explicitly declared."
    substances = haz.get("substances")
    if not isinstance(substances, list) or len(substances) == 0:
        return (
            False,
            "When hazardousSubstances.present is true, non-empty 'substances' list is required.",
        )
    for idx, item in enumerate(substances):
        if not isinstance(item, dict) or not (
            _is_non_empty_str(item.get("name"))
            and _is_non_empty_str(item.get("casNumber"))
            and (
                _is_non_empty_str(item.get("location"))
                or _is_number_in_range(item.get("concentrationPct"), 0.0, 100.0)
            )
        ):
            return (
                False,
                f"Hazardous substance entry [{idx}] requires name, casNumber, and location/concentrationPct.",
            )
    return True, f"{len(substances)} hazardous substance(s) disclosed with CAS identifiers."


def _check_pub_008(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    crm = _get_dict(pub, "criticalRawMaterials")
    if crm is None:
        return False, "Missing 'public.criticalRawMaterials' object."
    missing_or_bad: list[str] = []
    for material in ("cobalt", "lithium", "nickel"):
        entry = crm.get(material)
        if _is_number_in_range(entry, 0.0):
            continue
        if isinstance(entry, dict) and (
            _is_number_in_range(entry.get("massKg"), 0.0)
            or _is_number_in_range(entry.get("sharePct"), 0.0, 100.0)
        ):
            continue
        missing_or_bad.append(material)
    if missing_or_bad:
        return (
            False,
            "Missing or non-numeric critical raw material disclosure for: "
            + ", ".join(missing_or_bad),
        )
    return True, "Critical raw materials (Co, Li, Ni) declared."


def _check_pub_009(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    cf = _get_dict(pub, "carbonFootprint")
    if cf is None:
        return False, "Missing 'public.carbonFootprint' object (Art. 7)."
    if not _is_number_in_range(cf.get("totalKgCo2ePerKwh"), 0.0, strict_min=True):
        return False, "'carbonFootprint.totalKgCo2ePerKwh' must be > 0."
    if not _is_non_empty_str(cf.get("calculationMethodology")):
        return False, "Missing 'carbonFootprint.calculationMethodology'."
    stages = _get_dict(cf, "lifecycleStages")
    if stages is None:
        return False, "Missing 'carbonFootprint.lifecycleStages' breakdown."
    bad_stages = [
        stage
        for stage in (
            "rawMaterialAcquisition",
            "manufacturing",
            "distribution",
            "endOfLife",
        )
        if not _is_number_in_range(stages.get(stage), 0.0)
    ]
    if bad_stages:
        return False, "Invalid carbon footprint stage(s): " + ", ".join(bad_stages)
    return True, "Article 7 carbon footprint value and lifecycle stages valid."


def _check_pub_010(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    cf = _get_dict(pub, "carbonFootprint") or {}
    perf_class = cf.get("performanceClass")
    if perf_class not in ALLOWED_CARBON_CLASSES:
        return False, "Invalid 'carbonFootprint.performanceClass' (expected A-E)."
    if not _is_https_url(cf.get("publicStudyUrl")):
        return False, "Missing valid HTTPS 'carbonFootprint.publicStudyUrl'."
    return True, f"Carbon footprint performance class '{perf_class}' and study URL valid."


def _check_pub_011(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    rc = _get_dict(pub, "recycledContent")
    if rc is None:
        return False, "Missing 'public.recycledContent' object (Art. 8)."
    bad_fields = [
        field
        for field in ("cobaltPct", "leadPct", "lithiumPct", "nickelPct")
        if not _is_number_in_range(rc.get(field), 0.0, 100.0)
    ]
    if bad_fields:
        return (
            False,
            "Invalid or missing Art. 8 recycled content percentage (0-100) for: "
            + ", ".join(bad_fields),
        )
    return True, "Article 8 recycled content shares (Co, Pb, Li, Ni) declared."


def _check_pub_012(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    doc_eu = _get_dict(pub, "euDeclarationOfConformity")
    if doc_eu is None:
        return False, "Missing 'public.euDeclarationOfConformity' object."
    issues: list[str] = []
    if not _is_non_empty_str(doc_eu.get("declarationId")):
        issues.append("declarationId")
    if not _is_iso_date_or_datetime(doc_eu.get("issueDate")):
        issues.append("issueDate")
    if doc_eu.get("ceMarkingConfirmed") is not True:
        issues.append("ceMarkingConfirmed (true)")
    if not _is_https_url(doc_eu.get("documentUrl")):
        issues.append("documentUrl (https://)")
    if issues:
        return False, "Incomplete EU Declaration of Conformity: " + ", ".join(issues)
    return True, "EU Declaration of Conformity and CE marking verified."


def _check_pub_013(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    eol = _get_dict(pub, "endOfLifeAndSafety")
    if eol is None:
        return False, "Missing 'public.endOfLifeAndSafety' object."
    issues: list[str] = []
    if eol.get("separateCollectionSymbol") is not True:
        issues.append("separateCollectionSymbol (true)")
    if not _is_non_empty_str(eol.get("extinguishingAgent")):
        issues.append("extinguishingAgent")
    if not _is_https_url(eol.get("safetyInstructionsUrl")):
        issues.append("safetyInstructionsUrl (https://)")
    if issues:
        return False, "Incomplete end-of-life/safety info: " + ", ".join(issues)
    return True, "Separate collection symbol and safety guidance present."


def _check_pub_014(doc: dict[str, Any]) -> tuple[bool, str]:
    pub = _get_dict(doc, "public") or {}
    perf = _get_dict(pub, "performanceIndicators")
    if perf is None:
        return False, "Missing 'public.performanceIndicators' object."
    issues: list[str] = []
    if not _is_number_in_range(perf.get("expectedLifetimeCycles"), 0.0, strict_min=True):
        issues.append("expectedLifetimeCycles (>0)")
    if not _is_number_in_range(perf.get("expectedLifetimeYears"), 0.0, strict_min=True):
        issues.append("expectedLifetimeYears (>0)")
    if not _is_number_in_range(
        perf.get("roundTripEfficiencyPct"), 0.0, 100.0, strict_min=True
    ):
        issues.append("roundTripEfficiencyPct (0-100]")
    if issues:
        return False, "Invalid performance indicators: " + ", ".join(issues)
    return True, "Expected lifetime and efficiency indicators valid."


def _check_leg_001(doc: dict[str, Any]) -> tuple[bool, str]:
    leg = _get_dict(doc, "legitimateInterest") or {}
    policy = _get_dict(leg, "accessPolicy")
    if policy is None:
        return False, "Missing 'legitimateInterest.accessPolicy' object."
    if policy.get("accessScope") != "restricted_legitimate_interest":
        return (
            False,
            "'legitimateInterest.accessPolicy.accessScope' must equal 'restricted_legitimate_interest'.",
        )
    if not _is_non_empty_str(policy.get("authMethod")):
        return False, "Missing 'legitimateInterest.accessPolicy.authMethod'."
    roles = policy.get("authorizedRoles")
    if not isinstance(roles, list):
        return False, "'authorizedRoles' must be a list."
    present_roles = {str(r).strip() for r in roles}
    missing_roles = sorted(REQUIRED_LEGITIMATE_ROLES - present_roles)
    if missing_roles:
        return (
            False,
            "authorizedRoles missing mandatory circular-economy actors: "
            + ", ".join(missing_roles),
        )
    return True, "Legitimate interest RBAC policy valid."


def _check_leg_002(doc: dict[str, Any]) -> tuple[bool, str]:
    leg = _get_dict(doc, "legitimateInterest") or {}
    dismantling = _get_dict(leg, "dismantlingInfo")
    if dismantling is None:
        return False, "Missing 'legitimateInterest.dismantlingInfo' object."
    issues: list[str] = []
    if not _is_https_url(dismantling.get("manualUrl")):
        issues.append("manualUrl (https://)")
    if not _is_https_url(dismantling.get("explodedDiagramsUrl")):
        issues.append("explodedDiagramsUrl (https://)")
    tools = dismantling.get("requiredTools")
    if not isinstance(tools, list) or not any(_is_non_empty_str(t) for t in tools):
        issues.append("requiredTools (non-empty list)")
    if not _is_non_empty_str(dismantling.get("highVoltageSafetyProtocol")):
        issues.append("highVoltageSafetyProtocol")
    if issues:
        return False, "Incomplete dismantling information: " + ", ".join(issues)
    return True, "Dismantling manual, diagrams, tools, and safety protocol present."


def _check_leg_003(doc: dict[str, Any]) -> tuple[bool, str]:
    leg = _get_dict(doc, "legitimateInterest") or {}
    parts = leg.get("spareParts")
    if not isinstance(parts, list) or len(parts) == 0:
        return False, "Missing or empty 'legitimateInterest.spareParts' list."
    for idx, part in enumerate(parts):
        if not isinstance(part, dict):
            return False, f"spareParts[{idx}] must be an object."
        if not (
            _is_non_empty_str(part.get("partNumber"))
            and _is_non_empty_str(part.get("componentName"))
            and _is_non_empty_str(part.get("supplierContact"))
            and _is_number_in_range(part.get("availabilityYears"), 0.0)
        ):
            return (
                False,
                f"spareParts[{idx}] requires partNumber, componentName, supplierContact, availabilityYears.",
            )
    return True, f"{len(parts)} spare part reference(s) declared."


def _check_leg_004(doc: dict[str, Any]) -> tuple[bool, str]:
    leg = _get_dict(doc, "legitimateInterest") or {}
    comp = _get_dict(leg, "detailedComposition")
    if comp is None:
        return False, "Missing 'legitimateInterest.detailedComposition' object."
    missing = [
        key
        for key in ("cathodeActiveMaterial", "anodeActiveMaterial", "electrolyteComposition")
        if not _is_non_empty_str(comp.get(key))
    ]
    locs = comp.get("hazardousComponentLocations")
    if not ((isinstance(locs, list) and len(locs) > 0) or (isinstance(locs, dict) and len(locs) > 0)):
        missing.append("hazardousComponentLocations")
    if missing:
        return False, "Incomplete detailed composition for recyclers: " + ", ".join(missing)
    return True, "Detailed cell/material composition for recyclers present."


def _check_leg_005(doc: dict[str, Any]) -> tuple[bool, str]:
    leg = _get_dict(doc, "legitimateInterest") or {}
    dyn = _get_dict(leg, "dynamicHealthSchema")
    if dyn is None:
        return False, "Missing 'legitimateInterest.dynamicHealthSchema' object."
    issues: list[str] = []
    if not _is_number_in_range(dyn.get("stateOfHealthPct"), 0.0, 100.0):
        issues.append("stateOfHealthPct (0-100)")
    if not _is_number_in_range(dyn.get("remainingCapacityAh"), 0.0):
        issues.append("remainingCapacityAh (>=0)")
    for counter in (
        "fullChargeCycles",
        "deepDischargeEvents",
        "extremeTempExposureEvents",
    ):
        if not _is_non_neg_int(dyn.get(counter)):
            issues.append(f"{counter} (int >=0)")
    if not _is_iso_date_or_datetime(dyn.get("lastTelemetryTimestamp")):
        issues.append("lastTelemetryTimestamp (ISO-8601)")
    if not _is_non_empty_str(dyn.get("updateFrequency")):
        issues.append("updateFrequency")
    if issues:
        return False, "Invalid dynamic SoH/cycle schema: " + ", ".join(issues)
    return True, "Dynamic SoH and operational cycle telemetry schema valid."


def _check_aut_001(doc: dict[str, Any]) -> tuple[bool, str]:
    aut = _get_dict(doc, "authorities") or {}
    policy = _get_dict(aut, "accessPolicy")
    if policy is None:
        return False, "Missing 'authorities.accessPolicy' object."
    issues: list[str] = []
    if policy.get("accessScope") != "market_surveillance_and_notified_bodies":
        issues.append("accessScope=='market_surveillance_and_notified_bodies'")
    if not _is_non_empty_str(policy.get("notifiedBodyId")):
        issues.append("notifiedBodyId")
    if not _is_https_url(policy.get("competentAuthorityEndpoint")):
        issues.append("competentAuthorityEndpoint (https://)")
    if issues:
        return False, "Invalid authorities accessPolicy: " + ", ".join(issues)
    return True, "Authorities access governance and Notified Body ID valid."


def _check_aut_002(doc: dict[str, Any]) -> tuple[bool, str]:
    aut = _get_dict(doc, "authorities") or {}
    reports = aut.get("testReports")
    if not isinstance(reports, list) or len(reports) == 0:
        return False, "Missing or empty 'authorities.testReports' list (Annex III-V)."
    covered_annexes: set[str] = set()
    for idx, rep in enumerate(reports):
        if not isinstance(rep, dict):
            return False, f"testReports[{idx}] must be an object."
        if not (
            _is_non_empty_str(rep.get("reportId"))
            and _is_non_empty_str(rep.get("annexRef"))
            and _is_non_empty_str(rep.get("standardRef"))
            and _is_non_empty_str(rep.get("accreditedLab"))
            and _is_iso_date_or_datetime(rep.get("testDate"))
            and rep.get("result") == "PASS"
        ):
            return (
                False,
                f"testReports[{idx}] must include reportId, annexRef, standardRef, accreditedLab, testDate, and result=='PASS'.",
            )
        ref_upper = rep["annexRef"].upper()
        for required in ("ANNEX III", "ANNEX IV", "ANNEX V"):
            if required in ref_upper:
                covered_annexes.add(required)
    missing_annexes = [
        annex
        for annex in ("ANNEX III", "ANNEX IV", "ANNEX V")
        if annex not in covered_annexes
    ]
    if missing_annexes:
        return (
            False,
            "Test reports missing coverage for mandatory regulatory annexes: "
            + ", ".join(missing_annexes),
        )
    return True, f"{len(reports)} accredited PASS test report(s) covering Annexes III, IV, and V."


def _check_aut_003(doc: dict[str, Any]) -> tuple[bool, str]:
    aut = _get_dict(doc, "authorities") or {}
    ver = _get_dict(aut, "conformityVerification")
    if ver is None:
        return False, "Missing 'authorities.conformityVerification' object."
    missing = [
        key
        for key in (
            "assessmentModule",
            "technicalDocumentationRef",
            "carbonFootprintVerificationRef",
        )
        if not _is_non_empty_str(ver.get(key))
    ]
    if missing:
        return False, "Incomplete conformity verification dossier: " + ", ".join(missing)
    return True, "Conformity assessment module and verification dossier linked."


RULES: tuple[RuleDefinition, ...] = (
    # --- Structural & EN 18219 / EN 18222 (17 pts) ---
    RuleDefinition(
        rule_id="DPP-STR-001",
        tier="structural",
        legal_ref="CIRPASS-2 / W3C JSON-LD 1.1",
        title="JSON-LD @context Declaration",
        severity="critical",
        weight=4,
        field_path="@context",
        remediation="Include a valid '@context' string, object, or array referencing CIRPASS-2 / W3C JSON-LD contexts.",
        check=_check_str_001,
    ),
    RuleDefinition(
        rule_id="DPP-STR-002",
        tier="structural",
        legal_ref="EN 18219:2026 / Art. 77(3)",
        title="Unique Persistent @id (URN or GS1 Digital Link)",
        severity="critical",
        weight=5,
        field_path="@id",
        remediation="Set '@id' to a valid URN (urn:uuid:..., urn:iec61406:...) or HTTPS GS1 Digital Link (/01/<GTIN-14>/21/<serial>).",
        check=_check_str_002,
    ),
    RuleDefinition(
        rule_id="DPP-STR-003",
        tier="structural",
        legal_ref="EN 18222:2026",
        title="Passport Lifecycle & API Metadata",
        severity="critical",
        weight=4,
        field_path="lifecycleMetadata",
        remediation="Provide 'lifecycleMetadata' with dppSchemaVersion, passportStatus, https apiEndpoint, issuedAt, and lastUpdatedAt.",
        check=_check_str_003,
    ),
    RuleDefinition(
        rule_id="DPP-STR-004",
        tier="structural",
        legal_ref="Reg. (EU) 2023/1542 Art. 77(2) & Annex XIII",
        title="Three-Tier Access Control Partitioning",
        severity="critical",
        weight=4,
        field_path="public | legitimateInterest | authorities",
        remediation="Partition passport data into 'public', 'legitimateInterest', and 'authorities' without leaking restricted fields into 'public'.",
        check=_check_str_004,
    ),
    # --- Tier 1: Publicly Accessible Information (54 pts) ---
    RuleDefinition(
        rule_id="DPP-PUB-001",
        tier="public",
        legal_ref="Annex XIII Pt. 1(a) / Annex VI Pt. A(1)",
        title="Economic Operator / Manufacturer Identity",
        severity="critical",
        weight=4,
        field_path="public.economicOperator",
        remediation="Provide 'public.economicOperator' with name, legal identifier (EORI/VAT/GLN), and contactAddress or contactEmail.",
        check=_check_pub_001,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-002",
        tier="public",
        legal_ref="Annex XIII Pt. 1(b) & Art. 77(1)",
        title="Battery Category (EV | LMT | Industrial_gt_2kWh) & Model",
        severity="critical",
        weight=5,
        field_path="public.batteryCategory",
        remediation="Set 'public.batteryCategory' to EV, LMT, or Industrial_gt_2kWh along with batteryModel and serialOrBatchNumber.",
        check=_check_pub_002,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-003",
        tier="public",
        legal_ref="Annex XIII Pt. 1(c-d)",
        title="Manufacturing Plant & Date",
        severity="major",
        weight=3,
        field_path="public.manufacturing",
        remediation="Specify plantName/facilityId, ISO-3166-1 alpha-2 countryCode, and ISO-8601 manufacturingDate.",
        check=_check_pub_003,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-004",
        tier="public",
        legal_ref="Annex XIII Pt. 1(e)",
        title="Battery Weight (kg)",
        severity="major",
        weight=3,
        field_path="public.technicalSpecs.weightKg",
        remediation="Set positive numeric 'public.technicalSpecs.weightKg'.",
        check=_check_pub_004,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-005",
        tier="public",
        legal_ref="Annex XIII Pt. 1(f-g)",
        title="Nominal Voltage, Rated Capacity & Energy (>2 kWh Check)",
        severity="critical",
        weight=4,
        field_path="public.technicalSpecs",
        remediation="Declare positive nominalVoltageV, ratedCapacityAh, and ratedEnergyKwh (>2.0 kWh for Industrial_gt_2kWh).",
        check=_check_pub_005,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-006",
        tier="public",
        legal_ref="Annex XIII Pt. 1(h)",
        title="Battery Chemistry Composition",
        severity="critical",
        weight=4,
        field_path="public.chemistry",
        remediation="Provide chemistryType, cathodeMaterial, anodeMaterial, and electrolyte in 'public.chemistry'.",
        check=_check_pub_006,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-007",
        tier="public",
        legal_ref="Annex XIII Pt. 1(i)",
        title="Hazardous Substances Disclosure",
        severity="critical",
        weight=4,
        field_path="public.hazardousSubstances",
        remediation="Declare 'hazardousSubstances.present' boolean with either declarationStatement or CAS-identified substances list.",
        check=_check_pub_007,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-008",
        tier="public",
        legal_ref="Annex XIII Pt. 1(j)",
        title="Critical Raw Materials (Co, Li, Ni)",
        severity="critical",
        weight=4,
        field_path="public.criticalRawMaterials",
        remediation="Disclose cobalt, lithium, and nickel values (>=0 massKg or sharePct) under 'public.criticalRawMaterials'.",
        check=_check_pub_008,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-009",
        tier="public",
        legal_ref="Reg. (EU) 2023/1542 Art. 7 & Annex XIII Pt. 1(k)",
        title="Carbon Footprint Intensity & Lifecycle Stages",
        severity="critical",
        weight=5,
        field_path="public.carbonFootprint",
        remediation="Provide totalKgCo2ePerKwh (>0), calculationMethodology, and 4 lifecycleStages (rawMaterialAcquisition, manufacturing, distribution, endOfLife).",
        check=_check_pub_009,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-010",
        tier="public",
        legal_ref="Art. 7(2) & Annex XIII Pt. 1(k)",
        title="Carbon Footprint Performance Class (A-E) & Study URL",
        severity="major",
        weight=3,
        field_path="public.carbonFootprint.performanceClass",
        remediation="Set 'performanceClass' (A-E) and valid HTTPS 'publicStudyUrl' in 'public.carbonFootprint'.",
        check=_check_pub_010,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-011",
        tier="public",
        legal_ref="Reg. (EU) 2023/1542 Art. 8 & Annex XIII Pt. 1(l)",
        title="Recycled Content Shares (Co, Pb, Li, Ni)",
        severity="critical",
        weight=5,
        field_path="public.recycledContent",
        remediation="Declare numeric percentages (0-100) for cobaltPct, leadPct, lithiumPct, and nickelPct.",
        check=_check_pub_011,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-012",
        tier="public",
        legal_ref="Art. 18 & Annex XIII Pt. 1(m)",
        title="EU Declaration of Conformity & CE Marking",
        severity="critical",
        weight=4,
        field_path="public.euDeclarationOfConformity",
        remediation="Provide declarationId, issueDate, ceMarkingConfirmed: true, and HTTPS documentUrl.",
        check=_check_pub_012,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-013",
        tier="public",
        legal_ref="Art. 74 & Annex XIII Pt. 1(n-o)",
        title="Separate Collection Symbol & Safety Guidance",
        severity="major",
        weight=3,
        field_path="public.endOfLifeAndSafety",
        remediation="Confirm separateCollectionSymbol: true, extinguishingAgent, and HTTPS safetyInstructionsUrl.",
        check=_check_pub_013,
    ),
    RuleDefinition(
        rule_id="DPP-PUB-014",
        tier="public",
        legal_ref="Annex IV & Annex XIII Pt. 1",
        title="Expected Lifetime & Efficiency Indicators",
        severity="major",
        weight=3,
        field_path="public.performanceIndicators",
        remediation="Include positive expectedLifetimeCycles, expectedLifetimeYears, and roundTripEfficiencyPct (0-100].",
        check=_check_pub_014,
    ),
    # --- Tier 2: Legitimate Interest (17 pts) ---
    RuleDefinition(
        rule_id="DPP-LEG-001",
        tier="legitimate_interest",
        legal_ref="Art. 77(2)(c) & Annex XIII Pt. 2",
        title="Legitimate Interest RBAC & Auth Policy",
        severity="major",
        weight=3,
        field_path="legitimateInterest.accessPolicy",
        remediation="Set accessScope='restricted_legitimate_interest', authMethod, and authorizedRoles including repairer, remanufacturer, second_life_operator, and recycler.",
        check=_check_leg_001,
    ),
    RuleDefinition(
        rule_id="DPP-LEG-002",
        tier="legitimate_interest",
        legal_ref="Annex XIII Pt. 2(a-b)",
        title="Dismantling Manual, Diagrams & HV Safety Measures",
        severity="critical",
        weight=4,
        field_path="legitimateInterest.dismantlingInfo",
        remediation="Provide HTTPS manualUrl, explodedDiagramsUrl, non-empty requiredTools list, and highVoltageSafetyProtocol.",
        check=_check_leg_002,
    ),
    RuleDefinition(
        rule_id="DPP-LEG-003",
        tier="legitimate_interest",
        legal_ref="Annex XIII Pt. 2(c-d)",
        title="Spare Parts References & Availability",
        severity="major",
        weight=3,
        field_path="legitimateInterest.spareParts",
        remediation="Populate non-empty 'spareParts' list with partNumber, componentName, supplierContact, and availabilityYears.",
        check=_check_leg_003,
    ),
    RuleDefinition(
        rule_id="DPP-LEG-004",
        tier="legitimate_interest",
        legal_ref="Annex XIII Pt. 2(e)",
        title="Detailed Cell & Material Composition for Recyclers",
        severity="major",
        weight=3,
        field_path="legitimateInterest.detailedComposition",
        remediation="Provide cathodeActiveMaterial, anodeActiveMaterial, electrolyteComposition, and hazardousComponentLocations.",
        check=_check_leg_004,
    ),
    RuleDefinition(
        rule_id="DPP-LEG-005",
        tier="legitimate_interest",
        legal_ref="Annex XIII Pt. 4 & Annex VII",
        title="Dynamic State of Health (SoH) & Cycle Schema",
        severity="critical",
        weight=4,
        field_path="legitimateInterest.dynamicHealthSchema",
        remediation="Include stateOfHealthPct (0-100), remainingCapacityAh, fullChargeCycles, deepDischargeEvents, extremeTempExposureEvents, lastTelemetryTimestamp, and updateFrequency.",
        check=_check_leg_005,
    ),
    # --- Tier 3: Authorities & Notified Bodies (12 pts) ---
    RuleDefinition(
        rule_id="DPP-AUT-001",
        tier="authorities",
        legal_ref="Art. 77(2)(b) & Annex XIII Pt. 3",
        title="Market Surveillance Access Policy & Notified Body ID",
        severity="major",
        weight=3,
        field_path="authorities.accessPolicy",
        remediation="Set accessScope='market_surveillance_and_notified_bodies', notifiedBodyId, and HTTPS competentAuthorityEndpoint.",
        check=_check_aut_001,
    ),
    RuleDefinition(
        rule_id="DPP-AUT-002",
        tier="authorities",
        legal_ref="Annex XIII Pt. 3(a) & Annexes III-V",
        title="Accredited Test Reports Covering Annexes III, IV & V",
        severity="critical",
        weight=5,
        field_path="authorities.testReports",
        remediation="Include accredited PASS testReports covering Annex III, Annex IV, and Annex V with reportId, standardRef, accreditedLab, and testDate.",
        check=_check_aut_002,
    ),
    RuleDefinition(
        rule_id="DPP-AUT-003",
        tier="authorities",
        legal_ref="Annex VIII & Annex XIII Pt. 3(b)",
        title="Conformity Assessment & Carbon Verification Dossier",
        severity="critical",
        weight=4,
        field_path="authorities.conformityVerification",
        remediation="Specify assessmentModule, technicalDocumentationRef, and carbonFootprintVerificationRef under 'authorities.conformityVerification'.",
        check=_check_aut_003,
    ),
)

RULE_COUNT: int = len(RULES)
TOTAL_WEIGHT: int = sum(rule.weight for rule in RULES)
