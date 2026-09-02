# golden_baseline_manager.py
# Golden baseline creation, verification, and deep audit for WFRIDD.
#
# Three public functions:
#   create_golden_baseline() — first-run baseline; raises FileExistsError if
#                              golden_snapshot.json already exists
#   verify_golden_baseline() — re-hash + compare against golden_baseline_created
#                              CoC entry; writes VERIFIED or TAMPERED CoC entry
#   run_deep_audit()         — full 11-step cumulative drift analysis comparing
#                              the golden baseline against the current system state

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import config as cfg
import coc_manager
import collection_agent
import comparator
import mongodb_store
import reporter
import severity_engine

logger = logging.getLogger(__name__)

_GOLDEN_SNAPSHOT = cfg.GOLDEN_BASELINE_DIR / "golden_snapshot.json"


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _read_coc_entries_by_event(event: str) -> list:
    """Return all CoC log entries matching the given event name, in file order."""
    log_path = cfg.COC_LOG_FILE
    if not log_path.exists():
        return []
    entries = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                if e.get("event") == event:
                    entries.append(e)
            except json.JSONDecodeError:
                pass
    return entries


# ── PUBLIC FUNCTIONS ──────────────────────────────────────────────────────────

def create_golden_baseline() -> str:
    """Collect all 25 artefacts and write the ACL-locked, signed golden snapshot.

    Raises FileExistsError if golden_snapshot.json already exists — the
    golden baseline is created exactly once and is never overwritten.

    Returns the SHA-256 hex digest of the written file.
    """
    if _GOLDEN_SNAPSHOT.exists():
        raise FileExistsError(
            f"Golden baseline already exists at {_GOLDEN_SNAPSHOT}. "
            "Delete it manually if a fresh baseline is required."
        )
    cfg.GOLDEN_BASELINE_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("Collecting all artefacts for golden baseline...")
    snapshot = collection_agent.collect_all()
    _GOLDEN_SNAPSHOT.write_text(
        json.dumps(snapshot, indent=2, default=str), encoding="utf-8"
    )
    logger.info(f"Golden snapshot written: {_GOLDEN_SNAPSHOT}")

    sha256 = coc_manager.sign_and_lock(_GOLDEN_SNAPSHOT, event="golden_baseline_created")
    logger.info(f"Golden baseline created and ACL-locked — SHA-256: {sha256[:16]}...")
    return sha256


def verify_golden_baseline() -> bool:
    """Re-hash golden_snapshot.json and compare against the CoC log.

    Finds the golden_baseline_created entry in chain_of_custody.json and
    compares its recorded sha256 against the current file hash.

    Writes:
      event="golden_baseline_verified"  (result=VERIFIED)  on match
      event="golden_baseline_tampered"  (result=TAMPERED, action=halt)  on mismatch

    Returns True if verified, False if tampered or no CoC entry found.
    """
    entries = _read_coc_entries_by_event("golden_baseline_created")
    if not entries:
        logger.critical("verify_golden_baseline: no golden_baseline_created entry in CoC log")
        coc_manager._append_coc_entry({
            "timestamp":    datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
            "event":        "golden_baseline_tampered",
            "result":       "TAMPERED",
            "detail":       "no golden_baseline_created entry found in CoC log",
            "action":       "halt",
            "agent_id":     cfg.AGENT_ID,
            "tool_version": cfg.AGENT_VERSION,
        })
        return False

    recorded_sha256 = entries[0].get("sha256", "")
    actual_sha256   = coc_manager.hash_file(_GOLDEN_SNAPSHOT)

    if actual_sha256 == recorded_sha256:
        logger.info(f"Golden baseline verified — SHA-256 matches [{actual_sha256[:16]}...]")
        coc_manager._append_coc_entry({
            "timestamp":    datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
            "event":        "golden_baseline_verified",
            "result":       "VERIFIED",
            "sha256":       actual_sha256,
            "agent_id":     cfg.AGENT_ID,
            "tool_version": cfg.AGENT_VERSION,
        })
        return True

    logger.critical(
        f"Golden baseline TAMPERED — recorded: {recorded_sha256[:16]}..., "
        f"actual: {actual_sha256[:16]}..."
    )
    coc_manager._append_coc_entry({
        "timestamp":       datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
        "event":           "golden_baseline_tampered",
        "result":          "TAMPERED",
        "recorded_sha256": recorded_sha256,
        "actual_sha256":   actual_sha256,
        "action":          "halt",
        "agent_id":        cfg.AGENT_ID,
        "tool_version":    cfg.AGENT_VERSION,
    })
    return False


def run_deep_audit() -> dict:
    """Full cumulative drift analysis: golden baseline vs current system state.

    Steps
    -----
    1  verify_golden_baseline() — halt if tampered
    2  CoC event="deep_audit_initiated"
    3  Collect current snapshot into a temp file (not stored in snapshots/)
    4  Load golden_baseline/golden_snapshot.json as baseline
    5  comparator.run_comparison() with SR-001 only (relaxed suppression)
    6  severity_engine.score_findings()
    7  Categorise findings: legitimate / unresolved / unknown
    8  reporter.generate_deep_audit_pdf()
    9  coc_manager.sign_and_lock(pdf)
    10 CoC event="deep_audit_completed" with summary fields
    11 mongodb_store.store_deep_audit()

    Returns the audit_result dict.
    Raises RuntimeError if the golden baseline is tampered.
    """
    import suppression as supp

    # Step 1 — verify golden baseline integrity
    if not verify_golden_baseline():
        raise RuntimeError(
            "Golden baseline verification failed — deep audit halted. "
            "The baseline file has been tampered. Investigate before proceeding."
        )

    # Step 2 — CoC: deep audit initiated
    audit_start_ts = datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT)
    coc_manager._append_coc_entry({
        "timestamp":    audit_start_ts,
        "event":        "deep_audit_initiated",
        "agent_id":     cfg.AGENT_ID,
        "tool_version": cfg.AGENT_VERSION,
    })

    # Step 3 — collect current snapshot (temp file, never stored in snapshots/)
    logger.info("Deep audit: collecting current snapshot...")
    current_snapshot = collection_agent.collect_all()
    tmp_path = cfg.GOLDEN_BASELINE_DIR / "_deep_audit_temp_snapshot.json"
    tmp_path.write_text(
        json.dumps(current_snapshot, indent=2, default=str), encoding="utf-8"
    )
    current_sha256 = coc_manager.hash_file(tmp_path)

    # Step 4 — resolve golden baseline SHA-256 from CoC log
    golden_entries = _read_coc_entries_by_event("golden_baseline_created")
    golden_sha256 = (
        golden_entries[0]["sha256"] if golden_entries
        else coc_manager.hash_file(_GOLDEN_SNAPSHOT)
    )

    # Step 5 — compare golden baseline → current (SR-001 only, relaxed suppression)
    logger.info("Deep audit: comparing against golden baseline...")
    try:
        comparison_result = comparator.run_comparison(
            _GOLDEN_SNAPSHOT,
            tmp_path,
            suppress_fns={"services": supp.SUPPRESS_FNS["services"]},
            skip_coc_verify=True,
        )
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass

    # Step 6 — score findings
    logger.info("Deep audit: scoring findings...")
    scored_result = severity_engine.score_findings(comparison_result["findings"])

    # Step 7 — categorise findings: legitimate / unresolved / unknown
    # Prior daily cycle alerts from MongoDB (up to 5000 most recent).
    # The alerts collection stores only non-suppressed findings (see store_alerts).
    prior_alerts = mongodb_store.get_recent_alerts(n=5000)
    prior_alert_keys = {
        (a.get("artefact", ""), a.get("key", ""))
        for a in prior_alerts
    }

    # Build (artefact, key) -> earliest stored_at for first-detected lookup
    first_detected_map: dict = {}
    for a in prior_alerts:
        kt = (a.get("artefact", ""), a.get("key", ""))
        sa = a.get("stored_at", "") or a.get("cycle_id", "")
        if kt not in first_detected_map or sa < first_detected_map[kt]:
            first_detected_map[kt] = sa

    legitimate: list = []  # suppressed by SR-001 in this deep audit run
    unresolved: list = []  # non-suppressed + appeared in a prior daily cycle alert
    unknown:    list = []  # non-suppressed + never seen in any prior daily cycle

    for sf in scored_result.get("scored_suppressed", []):
        legitimate.append(sf)

    for sf in scored_result.get("scored_alerts", []):
        key = (getattr(sf, "artefact", ""), getattr(sf, "key", ""))
        if key in prior_alert_keys:
            unresolved.append(sf)
        else:
            unknown.append(sf)

    # Days since installation (delta from golden_baseline_created CoC timestamp)
    installation_ts = golden_entries[0]["timestamp"] if golden_entries else audit_start_ts
    try:
        install_dt  = datetime.strptime(installation_ts, cfg.TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
        days_since  = (datetime.now(timezone.utc) - install_dt).days
    except Exception:
        days_since = 0

    total_changes = len(legitimate) + len(unresolved) + len(unknown)

    # Collect CoC entries for the PDF Chain-of-Custody page
    coc_initiated = _read_coc_entries_by_event("deep_audit_initiated")
    coc_verified  = _read_coc_entries_by_event("golden_baseline_verified")
    coc_golden    = _read_coc_entries_by_event("golden_baseline_created")

    # Assemble audit_result (used by reporter + mongodb_store)
    audit_date_ts = datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT)
    ts_clean      = audit_date_ts.replace(":", "").replace("-", "")
    pdf_path      = cfg.DIRS["reports"] / f"deep_audit_{ts_clean}.pdf"

    audit_result = {
        "generated_at":                 audit_date_ts,
        "installation_date":            installation_ts,
        "audit_date":                   audit_date_ts,
        "days_since_installation":      days_since,
        "golden_baseline_sha256":       golden_sha256,
        "current_snapshot_sha256":      current_sha256,
        "total_changes":                total_changes,
        "legitimate_changes":           len(legitimate),
        "unresolved_security_findings": len(unresolved),
        "unknown_changes":              len(unknown),
        "legitimate":                   legitimate,
        "unresolved":                   unresolved,
        "unknown":                      unknown,
        "unresolved_first_detected":    {
            f"{getattr(sf,'artefact','')}::{getattr(sf,'key','')}":
            first_detected_map.get(
                (getattr(sf, "artefact", ""), getattr(sf, "key", "")), "N/A"
            )
            for sf in unresolved
        },
        "severity_counts":              scored_result.get("severity_counts", {}),
        "top_severity":                 scored_result.get("top_severity", "NONE"),
        "golden_baseline_integrity":    "VERIFIED",
        "coc_golden_created":           coc_golden[-1]    if coc_golden    else {},
        "coc_audit_initiated":          coc_initiated[-1] if coc_initiated else {},
        "coc_golden_verified":          coc_verified[-1]  if coc_verified  else {},
        "coc_audit_completed":          {},  # filled after step 10
        "report_path":                  str(pdf_path),
    }

    # Step 8 — CoC entry: deep audit completed (written before PDF so the row
    #           is present when _da_coc() builds the Chain of Custody table)
    coc_manager._append_coc_entry({
        "timestamp":                    datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
        "event":                        "deep_audit_completed",
        "golden_baseline_sha256":       golden_sha256,
        "current_snapshot_sha256":      current_sha256,
        "days_since_installation":      days_since,
        "total_changes":                total_changes,
        "legitimate_changes":           len(legitimate),
        "unresolved_security_findings": len(unresolved),
        "unknown_changes":              len(unknown),
        "agent_id":                     cfg.AGENT_ID,
        "tool_version":                 cfg.AGENT_VERSION,
    })

    coc_completed = _read_coc_entries_by_event("deep_audit_completed")
    audit_result["coc_audit_completed"] = coc_completed[-1] if coc_completed else {}

    # Step 9 — generate deep audit PDF (coc_audit_completed now populated)
    logger.info("Deep audit: generating PDF report...")
    reporter.generate_deep_audit_pdf(audit_result, pdf_path)

    # Step 10 — sign and lock the PDF
    coc_manager.sign_and_lock(pdf_path, event="deep_audit_report_created")

    # Step 11 — persist in MongoDB
    logger.info("Deep audit: storing result in MongoDB...")
    mongodb_store.store_deep_audit(audit_result)

    logger.info(
        f"Deep audit complete — {total_changes} total changes "
        f"({len(legitimate)} legitimate, {len(unresolved)} unresolved, "
        f"{len(unknown)} unknown)"
    )
    return audit_result
