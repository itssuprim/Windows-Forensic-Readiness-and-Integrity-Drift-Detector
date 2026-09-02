# mongodb_store.py
# MongoDB persistence layer — secondary store.
# Connection failure never interrupts the detection cycle.
#
# Collections:
#   snapshots     — raw snapshot JSON with per-artefact type annotation
#   drift_reports — comparator + severity engine output per cycle
#   alerts        — one document per non-suppressed ScoredFinding

import dataclasses
import logging
import os
from datetime import datetime, timezone

import config as cfg
from coc_manager import hash_file  # noqa: F401 — canonical hash impl, don't reimplement

logger = logging.getLogger(__name__)

_DB_NAME   = "wfridd"
_client    = None
_db        = None
_SEV_RANK  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNMATCHED": 4}


def _get_db():
    global _client, _db
    if _db is not None:
        return _db
    try:
        from pymongo import MongoClient
        uri = os.environ.get("WFRIDD_MONGO_URI", "mongodb://localhost:27017/")
        _client = MongoClient(uri, serverSelectionTimeoutMS=3000, connectTimeoutMS=3000)
        _client.admin.command("ping")
        _db = _client[_DB_NAME]
        logger.info(f"mongodb_store: connected {uri}{_DB_NAME}")
        return _db
    except Exception as e:
        logger.error(f"mongodb_store: connection failed — {e}")
        _client = _db = None
        return None


def store_snapshot(snapshot: dict) -> str:
    """Insert full raw snapshot into snapshots collection.

    Each artefact entry is annotated with artefact_type from cfg.ARTEFACTS
    so the dashboard can filter by STATIC/SEMI-STATIC/DYNAMIC without
    re-reading the config.

    Returns inserted_id as str, or "" on failure.
    """
    db = _get_db()
    if db is None:
        return ""
    try:
        artefacts = {
            name: {**entry, "artefact_type": cfg.ARTEFACTS.get(name, {}).get("type", "UNKNOWN")}
            for name, entry in snapshot.get("artefacts", {}).items()
        }
        doc = {**snapshot, "artefacts": artefacts, "stored_at": datetime.now(timezone.utc).isoformat()}
        result = db.snapshots.insert_one(doc)
        logger.info(f"mongodb_store: snapshot stored {result.inserted_id}")
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"mongodb_store: store_snapshot failed — {e}")
        return ""


def store_report(comparison_result: dict, scored_result: dict, report_path: str) -> str:
    """Build and insert a drift_report document.

    Args:
        comparison_result: return value of comparator.run_comparison()
        scored_result:     return value of severity_engine.score_findings()
        report_path:       path to the generated PDF report

    Returns inserted_id as str, or "" on failure.
    """
    db = _get_db()
    if db is None:
        return ""
    try:
        suppressed = scored_result.get("scored_suppressed", [])
        by_rule: dict = {}
        for sf in suppressed:
            rule = (sf.suppression_rule if hasattr(sf, "suppression_rule")
                    else sf.get("suppression_rule")) or "unknown"
            by_rule[rule] = by_rule.get(rule, 0) + 1

        doc = {
            "generated_at":            datetime.now(timezone.utc).isoformat(),
            "baseline_timestamp":      comparison_result.get("baseline_timestamp"),
            "current_timestamp":       comparison_result.get("current_timestamp"),
            "agent_id":                cfg.AGENT_ID,
            "windows_update_detected": comparison_result.get("windows_update_detected", False),
            "severity_counts":         scored_result.get("severity_counts", {}),
            "top_severity":            scored_result.get("top_severity", "NONE"),
            "total_alerts":            len(scored_result.get("scored_alerts", [])),
            "suppression_summary":     {"total_suppressed": len(suppressed), "by_rule": by_rule},
            "report_path":             report_path,
        }
        result = db.drift_reports.insert_one(doc)
        logger.info(f"mongodb_store: drift report stored {result.inserted_id}")
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"mongodb_store: store_report failed — {e}")
        return ""


def store_alerts(scored_findings: list, cycle_id: str) -> int:
    """Insert one alert document per non-suppressed ScoredFinding.

    Args:
        scored_findings: list of ScoredFinding (mixed suppressed/non-suppressed)
        cycle_id:        snapshot timestamp string — ties alerts to their cycle

    Returns count of documents inserted, or 0 on failure.
    """
    db = _get_db()
    if db is None:
        return 0
    alerts = [sf for sf in scored_findings
              if not (sf.suppressed if hasattr(sf, "suppressed") else sf.get("suppressed", False))]
    if not alerts:
        return 0
    try:
        ts   = datetime.now(timezone.utc).isoformat()
        docs = []
        for sf in alerts:
            d = dataclasses.asdict(sf) if dataclasses.is_dataclass(sf) else dict(sf)
            d["cycle_id"]     = cycle_id
            d["stored_at"]    = ts
            d["severity_rank"] = _SEV_RANK.get(d.get("severity", ""), 5)
            docs.append(d)
        result = db.alerts.insert_many(docs)
        count  = len(result.inserted_ids)
        logger.info(f"mongodb_store: {count} alert(s) stored")
        return count
    except Exception as e:
        logger.error(f"mongodb_store: store_alerts failed — {e}")
        return 0


def get_recent_snapshots(n: int = 10) -> list:
    """Return last n snapshots sorted by timestamp descending.

    Returns list of dicts (_id serialised as str), or [] on failure.
    """
    db = _get_db()
    if db is None:
        return []
    try:
        docs = list(db.snapshots.find().sort("timestamp", -1).limit(n))
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs
    except Exception as e:
        logger.error(f"mongodb_store: get_recent_snapshots failed — {e}")
        return []


def get_recent_alerts(n: int = 50) -> list:
    """Return last n non-suppressed alerts sorted by stored_at descending.

    The alerts collection contains only non-suppressed findings (store_alerts
    filters at write time), so no additional filter is needed here.

    Returns list of dicts (_id serialised as str), or [] on failure.
    """
    db = _get_db()
    if db is None:
        return []
    try:
        docs = list(db.alerts.find().sort("stored_at", -1).limit(n))
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs
    except Exception as e:
        logger.error(f"mongodb_store: get_recent_alerts failed — {e}")
        return []


def get_alerts_for_cycle(cycle_ts: str) -> list:
    """Return all alerts whose cycle_id matches cycle_ts.

    cycle_ts is the current_timestamp from the drift_report (set as cycle_id
    on each alert at store time in store_alerts()).
    Returns list of dicts (_id serialised as str), or [] on failure.
    """
    db = _get_db()
    if db is None:
        return []
    try:
        docs = list(db.alerts.find({"cycle_id": cycle_ts}).sort("severity_rank", 1))
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs
    except Exception as e:
        logger.error(f"mongodb_store: get_alerts_for_cycle failed — {e}")
        return []


def count_collection(collection_name: str) -> int:
    """Return total document count for a collection, or 0 on failure."""
    db = _get_db()
    if db is None:
        return 0
    try:
        return db[collection_name].count_documents({})
    except Exception as e:
        logger.error(f"mongodb_store: count_collection({collection_name}) failed — {e}")
        return 0


def get_recent_reports(n: int = 20) -> list:
    """Return last n drift reports sorted by generated_at descending.

    Returns list of dicts (_id serialised as str), or [] on failure.
    """
    db = _get_db()
    if db is None:
        return []
    try:
        docs = list(db.drift_reports.find().sort("generated_at", -1).limit(n))
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs
    except Exception as e:
        logger.error(f"mongodb_store: get_recent_reports failed — {e}")
        return []


def store_deep_audit(audit_result: dict) -> str:
    """Insert a deep audit result into the deep_audit_reports collection.

    Fields stored: generated_at, golden_baseline_sha256, current_snapshot_sha256,
    days_since_installation, total_changes, legitimate_changes,
    unresolved_security_findings, unknown_changes, severity_counts,
    top_severity, report_path.

    Returns inserted_id as str, or "" on failure.
    """
    db = _get_db()
    if db is None:
        return ""
    try:
        doc = {
            "generated_at":                 datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
            "golden_baseline_sha256":       audit_result.get("golden_baseline_sha256",       ""),
            "current_snapshot_sha256":      audit_result.get("current_snapshot_sha256",      ""),
            "days_since_installation":      audit_result.get("days_since_installation",       0),
            "total_changes":                audit_result.get("total_changes",                 0),
            "legitimate_changes":           audit_result.get("legitimate_changes",            0),
            "unresolved_security_findings": audit_result.get("unresolved_security_findings",  0),
            "unknown_changes":              audit_result.get("unknown_changes",               0),
            "severity_counts":              audit_result.get("severity_counts",              {}),
            "top_severity":                 audit_result.get("top_severity",             "NONE"),
            "report_path":                  audit_result.get("report_path",                  ""),
        }
        result = db.deep_audit_reports.insert_one(doc)
        logger.info(f"mongodb_store: deep audit report stored {result.inserted_id}")
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"mongodb_store: store_deep_audit failed — {e}")
        return ""


def get_deep_audit_history(n: int = 10) -> list:
    """Return last n deep_audit_reports sorted by generated_at descending.

    Returns list of dicts (_id serialised as str), or [] on failure.
    """
    db = _get_db()
    if db is None:
        return []
    try:
        docs = list(db.deep_audit_reports.find().sort("generated_at", -1).limit(n))
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs
    except Exception as e:
        logger.error(f"mongodb_store: get_deep_audit_history failed — {e}")
        return []
