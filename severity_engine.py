# severity_engine.py
# Scores comparator Findings against rules/windows_rules.yaml.
#
# First-match semantics: rules are evaluated in YAML order; the first rule
# whose artefact, change_type, key_equals, and conditions all match is applied.
# Unmatched findings get severity="UNMATCHED" — they still appear in the report
# but are separated from the scored section for analyst review.
#
# Suppressed findings are scored in the same pass so that Section 4 of the PDF
# (Suppression Audit Summary) can show suppression_rule alongside severity.

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

import config as cfg
from comparator import Finding

logger = logging.getLogger(__name__)

_RULES_PATH = Path(cfg.DIRS["rules"]) / "windows_rules.yaml"

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNMATCHED"]


# ── DATA TYPE ─────────────────────────────────────────────────────────────────

@dataclass
class ScoredFinding:
    """A Finding enriched with severity and MITRE ATT&CK attribution."""
    # Copied from Finding
    artefact: str
    change_type: str
    key: str
    baseline_value: Any = None
    current_value: Any = None
    suppressed: bool = False
    suppression_rule: Optional[str] = None
    suppression_reason: Optional[str] = None
    # Added by severity engine
    severity: str = "UNMATCHED"
    rule_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_name: Optional[str] = None
    description: Optional[str] = None
    investigator_note: Optional[str] = None


# ── RULE LOADING ──────────────────────────────────────────────────────────────

def load_rules(rules_path=None) -> list:
    """Load and return the rules list from windows_rules.yaml.

    Raises FileNotFoundError if the YAML is absent.
    Raises yaml.YAMLError if the YAML is malformed.
    Called at module import time (cached in _RULES); call explicitly in tests.
    """
    path = Path(rules_path) if rules_path else _RULES_PATH
    with open(path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    if not isinstance(rules, list):
        raise ValueError(f"Expected a YAML list at top level in {path}")
    logger.info(f"Loaded {len(rules)} severity rules from {path.name}")
    return rules


# Load rules once at import — fail fast if YAML is missing or broken.
try:
    _RULES: list = load_rules()
except Exception as _e:
    logger.error(f"Failed to load severity rules: {_e}")
    _RULES = []


# ── CONDITION EVALUATION ──────────────────────────────────────────────────────

def _eval_condition(condition: dict, finding: Finding) -> bool:
    """Evaluate one condition dict against a Finding.

    condition keys (all optional — an empty dict always passes):
      current_value_field   : dict key to extract from finding.current_value.
                              Omit when current_value is a scalar.
      current_value_equals  : val must equal this (strict ==)
      current_value_not     : val must NOT equal this
      current_value_truthy  : bool — bool(val) must equal this
    """
    field = condition.get("current_value_field")

    cv = finding.current_value
    if field is not None:
        val = cv.get(field) if isinstance(cv, dict) else None
    else:
        val = cv

    if "current_value_equals" in condition:
        if val != condition["current_value_equals"]:
            return False

    if "current_value_not" in condition:
        if val == condition["current_value_not"]:
            return False

    if "current_value_truthy" in condition:
        if bool(val) != condition["current_value_truthy"]:
            return False

    return True


# ── RULE MATCHING ─────────────────────────────────────────────────────────────

def _rule_matches(rule: dict, finding: Finding) -> bool:
    """Return True if a rule matches a Finding.

    Match order (all must pass):
      1. artefact — exact match
      2. change_type — exact match OR pipe-separated OR list ("added|modified")
      3. key_equals — if present, finding.key must equal this value exactly
      4. conditions — all must pass (see _eval_condition)
    """
    if rule.get("artefact") != finding.artefact:
        return False

    change_type_val = rule.get("change_type", "")
    if change_type_val:
        # Pipe-separated list: "added|modified" means either type matches.
        # An absent change_type means "match any" — no filter applied.
        if finding.change_type not in set(change_type_val.split("|")):
            return False

    if "key_equals" in rule:
        if rule["key_equals"] != finding.key:
            return False

    for condition in rule.get("conditions", []):
        if not _eval_condition(condition, finding):
            return False

    return True


# ── SCORING ───────────────────────────────────────────────────────────────────

def score_finding(finding: Finding, rules: list = None) -> ScoredFinding:
    """Score a single Finding against the rule list (first match wins).

    Returns a ScoredFinding with severity="UNMATCHED" when no rule matches.
    """
    rule_list = rules if rules is not None else _RULES

    sf = ScoredFinding(
        artefact=finding.artefact,
        change_type=finding.change_type,
        key=finding.key,
        baseline_value=finding.baseline_value,
        current_value=finding.current_value,
        suppressed=finding.suppressed,
        suppression_rule=finding.suppression_rule,
        suppression_reason=finding.suppression_reason,
    )

    for rule in rule_list:
        if _rule_matches(rule, finding):
            sf.severity          = rule.get("severity", "UNMATCHED")
            sf.rule_id           = rule.get("rule_id")
            sf.mitre_technique   = rule.get("mitre_technique")
            sf.mitre_name        = rule.get("mitre_name")
            sf.description       = (rule.get("description") or "").strip()
            sf.investigator_note = (rule.get("investigator_note") or "").strip()
            return sf

    logger.debug(
        f"No rule matched: {finding.artefact}/{finding.change_type}/{finding.key}"
    )
    return sf


def score_findings(findings: list, rules: list = None) -> dict:
    """Score all Findings from comparator.run_comparison().

    Args:
        findings : list[Finding] — the "findings" key from run_comparison()
        rules    : optional rule list override (uses module-level _RULES if None)

    Returns:
        {
            "scored_alerts":     [ScoredFinding, ...],  # non-suppressed, scored
            "scored_suppressed": [ScoredFinding, ...],  # suppressed, scored
            "severity_counts":   {                       # alerts only
                "CRITICAL": int,
                "HIGH":     int,
                "MEDIUM":   int,
                "LOW":      int,
                "UNMATCHED": int,
            },
            "top_severity": str,  # highest severity level present in alerts, or "NONE"
        }
    """
    rule_list = rules if rules is not None else _RULES
    scored_alerts: list[ScoredFinding] = []
    scored_suppressed: list[ScoredFinding] = []

    for finding in findings:
        sf = score_finding(finding, rules=rule_list)
        if sf.suppressed:
            scored_suppressed.append(sf)
        else:
            scored_alerts.append(sf)

    severity_counts = {s: 0 for s in _SEVERITY_ORDER}
    for sf in scored_alerts:
        severity_counts[sf.severity] = severity_counts.get(sf.severity, 0) + 1

    top_severity = "NONE"
    for level in _SEVERITY_ORDER:
        if severity_counts.get(level, 0) > 0:
            top_severity = level
            break

    logger.info(
        f"Severity scoring complete — "
        f"CRITICAL={severity_counts['CRITICAL']}, "
        f"HIGH={severity_counts['HIGH']}, "
        f"MEDIUM={severity_counts['MEDIUM']}, "
        f"LOW={severity_counts['LOW']}, "
        f"UNMATCHED={severity_counts['UNMATCHED']} | "
        f"top_severity={top_severity}"
    )

    return {
        "scored_alerts":     scored_alerts,
        "scored_suppressed": scored_suppressed,
        "severity_counts":   severity_counts,
        "top_severity":      top_severity,
    }
