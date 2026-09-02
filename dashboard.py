# dashboard.py — Flask monitoring dashboard for WFRIDD.
# Entry point: python dashboard.py  →  http://localhost:5001

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

import yaml
from flask import Flask, abort, jsonify, render_template, request, send_file

import config as cfg
import golden_baseline_manager
import mongodb_store

# Module-level flag: True while a deep audit background thread is running.
_deep_audit_running = threading.Event()


def _utc_to_local(ts: str) -> str:
    """Convert a UTC timestamp to local system time.

    Accepts cfg.TIMESTAMP_FORMAT ('%Y-%m-%dT%H:%M:%SZ') and isoformat strings
    (e.g. '2026-08-28T17:40:41.123456+00:00') so that records written by either
    convention display correctly.
    """
    if not ts:
        return ts
    try:
        try:
            dt_utc = datetime.strptime(ts, cfg.TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
        except ValueError:
            dt_utc = datetime.fromisoformat(ts)
            if dt_utc.tzinfo is None:
                dt_utc = dt_utc.replace(tzinfo=timezone.utc)
        return dt_utc.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True
logging.basicConfig(level=logging.INFO)

_RULES_PATH = cfg.DIRS["rules"] / "windows_rules.yaml"
_SEV_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNMATCHED": 5}

_CAT_NAMES = {
    "A": "Identity",       "B": "Access Control", "C": "Persistence",
    "D": "Software",       "E": "Network",         "F": "Filesystem",
    "G": "Kernel / Boot",  "H": "Audit",
}


def _cat(artefact_name: str) -> tuple:
    letter = cfg.ARTEFACTS.get(artefact_name, {}).get("category", "?")
    return letter, _CAT_NAMES.get(letter, "Unknown")


def _cycle_id(rank: int) -> str:
    """rank=1 is oldest (CYC-001). rank=total is newest."""
    return f"CYC-{str(rank).zfill(3)}"

def _snapshot_id(rank: int) -> str:
    """rank=1 is oldest (SNP-001). rank=total is newest."""
    return f"SNP-{str(rank).zfill(3)}"


def _load_rules():
    try:
        with open(_RULES_PATH, encoding="utf-8") as f:
            return yaml.safe_load(f) or []
    except Exception:
        return []


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def overview():
    snapshots      = mongodb_store.get_recent_snapshots(1)
    latest_reports = mongodb_store.get_recent_reports(1)
    history_desc   = mongodb_store.get_recent_reports(20)   # newest-first
    alert_preview  = mongodb_store.get_recent_alerts(8)

    snapshot = snapshots[0]      if snapshots      else None
    report   = latest_reports[0] if latest_reports else None

    # Oldest-first for the scan timeline chart
    history_asc = list(reversed(history_desc))

    artefact_statuses: dict = {}
    if snapshot:
        for name in cfg.ARTEFACTS:
            entry = snapshot.get("artefacts", {}).get(name, {})
            artefact_statuses[name] = entry.get("collection_status", "unknown")

    # Annotate alert preview with category
    for a in alert_preview:
        letter, cname = _cat(a.get("artefact", ""))
        a["category_letter"] = letter
        a["category_name"]   = cname

    # Group artefacts by category for the grouped grid
    _cat_order = ["A", "B", "C", "D", "E", "F", "G", "H"]
    _groups: dict = {}
    for name in cfg.ARTEFACTS:
        letter, cname = _cat(name)
        if letter not in _groups:
            _groups[letter] = {"name": cname, "artefacts": []}
        _groups[letter]["artefacts"].append(name)
    artefact_groups = [(k, _groups[k]) for k in _cat_order if k in _groups]

    return render_template(
        "overview.html",
        snapshot=snapshot,
        report=report,
        history=history_asc,
        alert_preview=alert_preview,
        artefact_statuses=artefact_statuses,
        artefact_names=list(cfg.ARTEFACTS.keys()),
        artefact_groups=artefact_groups,
    )


@app.route("/api/status")
def api_status():
    reports  = mongodb_store.get_recent_reports(1)
    snaps    = mongodb_store.get_recent_snapshots(1)
    report   = reports[0]  if reports else None
    snapshot = snaps[0]    if snaps   else None
    top      = report.get("top_severity", "NONE") if report else "NONE"
    return jsonify({
        "status":       "CLEAN" if top in ("NONE", "") else "DRIFT",
        "top_severity": top,
        "last_run":     report.get("generated_at", "") if report else "",
        "agent_id":     snapshot.get("agent_id", cfg.AGENT_ID) if snapshot else cfg.AGENT_ID,
    })


@app.route("/alerts")
def alerts():
    rows = mongodb_store.get_recent_alerts(50)
    for a in rows:
        letter, cname = _cat(a.get("artefact", ""))
        a["category_letter"] = letter
        a["category_name"]   = cname
    return render_template("alerts.html", alerts=rows)


@app.route("/reports")
def reports():
    rows  = mongodb_store.get_recent_reports(20)
    total = mongodb_store.count_collection("drift_reports")
    for i, r in enumerate(rows):
        r["cycle_id"] = _cycle_id(total - i)
    return render_template("reports.html", reports=rows)


@app.route("/rules")
def rules():
    all_rules = _load_rules()
    for r in all_rules:
        letter, cname = _cat(r.get("artefact", ""))
        r["category_letter"] = letter
        r["category_name"]   = cname
    all_rules.sort(
        key=lambda r: (_SEV_ORDER.get(r.get("severity", "UNMATCHED"), 5), r.get("rule_id", ""))
    )
    return render_template("rules.html", rules=all_rules)


@app.route("/snapshots")
def snapshots():
    rows  = mongodb_store.get_recent_snapshots(20)
    total = mongodb_store.count_collection("snapshots")
    for i, s in enumerate(rows):
        s["cycle_id"] = _snapshot_id(total - i)
    return render_template("snapshots.html", snapshots=rows)


@app.route("/downloads")
def downloads():
    reports_dir = cfg.DIRS["reports"]

    # Group PDF + JSON by shared stem (e.g. report_20260821T051121Z)
    stem_map: dict = {}
    for ext in ("*.pdf", "*.json"):
        for f in reports_dir.glob(ext):
            stem_map.setdefault(f.stem, {})[f.suffix.lstrip(".")] = f

    # Sort newest-first by whichever file exists
    file_groups = sorted(
        stem_map.values(),
        key=lambda g: (g.get("pdf") or g.get("json")).stat().st_mtime,
        reverse=True,
    )

    rows  = mongodb_store.get_recent_reports(50)
    total = mongodb_store.count_collection("drift_reports")
    for i, r in enumerate(rows):
        r["cycle_id"] = _cycle_id(total - i)

    # stem → report lookup for cycle_id / severity annotation
    report_by_stem: dict = {}
    for r in rows:
        rp = r.get("report_path", "")
        if rp:
            fname = rp.replace("\\", "/").split("/")[-1]
            report_by_stem[fname.rsplit(".", 1)[0]] = r

    return render_template(
        "downloads.html",
        file_groups=file_groups,
        report_by_stem=report_by_stem,
        reports=rows,
    )


@app.route("/download/<path:filename>")
def download_file(filename):
    reports_dir = cfg.DIRS["reports"]
    filepath    = (reports_dir / filename).resolve()
    try:
        filepath.relative_to(reports_dir.resolve())
    except ValueError:
        abort(403)
    if not filepath.is_file():
        abort(404)
    return send_file(str(filepath), as_attachment=True)


@app.route("/api/cycle/<path:cycle_ts>/alerts")
def api_cycle_alerts(cycle_ts: str):
    rows = mongodb_store.get_alerts_for_cycle(cycle_ts)
    for a in rows:
        letter, cname = _cat(a.get("artefact", ""))
        a["category_letter"] = letter
        a["category_name"]   = cname
    return jsonify(rows)


@app.route("/suppression")
def suppression():
    rows  = mongodb_store.get_recent_reports(20)
    total = mongodb_store.count_collection("drift_reports")
    for i, r in enumerate(rows):
        r["cycle_id"] = _cycle_id(total - i)
    return render_template("suppression.html", reports=rows)


@app.route("/golden-baseline")
def golden_baseline():
    golden_path = cfg.GOLDEN_BASELINE_DIR / "golden_snapshot.json"
    golden_exists = golden_path.exists()

    golden_info = {}
    if golden_exists:
        try:
            from golden_baseline_manager import _read_coc_entries_by_event
            created_entries  = _read_coc_entries_by_event("golden_baseline_created")
            verified_entries = _read_coc_entries_by_event("golden_baseline_verified")
            tampered_entries = _read_coc_entries_by_event("golden_baseline_tampered")

            created_entry  = created_entries[0]  if created_entries  else {}
            last_verified  = verified_entries[-1] if verified_entries else None
            last_tampered  = tampered_entries[-1] if tampered_entries else None

            # Determine last verification result
            if last_verified and last_tampered:
                lv_ts = last_verified.get("timestamp", "")
                lt_ts = last_tampered.get("timestamp", "")
                last_ver_result = "VERIFIED" if lv_ts >= lt_ts else "TAMPERED"
                last_ver_at     = lv_ts      if lv_ts >= lt_ts else lt_ts
            elif last_verified:
                last_ver_result = "VERIFIED"
                last_ver_at     = last_verified.get("timestamp")
            elif last_tampered:
                last_ver_result = "TAMPERED"
                last_ver_at     = last_tampered.get("timestamp")
            else:
                last_ver_result = None
                last_ver_at     = None

            created_ts = created_entry.get("timestamp", "")
            days_since = 0
            if created_ts:
                try:
                    install_dt = datetime.strptime(created_ts, cfg.TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
                    days_since = (datetime.now(timezone.utc) - install_dt).days
                except Exception:
                    pass

            golden_info = {
                "created_at":           _utc_to_local(created_ts),
                "sha256":               created_entry.get("sha256", ""),
                "days_since_creation":  days_since,
                "last_verified_at":     _utc_to_local(last_ver_at) if last_ver_at else None,
                "last_verified_result": last_ver_result,
            }
        except Exception as e:
            logging.error(f"golden_baseline route: error reading CoC — {e}")

    deep_audit_history = mongodb_store.get_deep_audit_history(10)
    for rec in deep_audit_history:
        rec["generated_at_local"] = _utc_to_local(rec.get("generated_at", "")) or "—"

    return render_template(
        "golden_baseline.html",
        golden_exists=golden_exists,
        golden_info=golden_info,
        deep_audit_history=deep_audit_history,
        deep_audit_running=_deep_audit_running.is_set(),
    )


@app.route("/api/deep-audit/status")
def api_deep_audit_status():
    history = mongodb_store.get_deep_audit_history(1)
    last_completed = history[0].get("generated_at") if history else None
    return jsonify({
        "running":        _deep_audit_running.is_set(),
        "last_completed": last_completed,
    })


@app.route("/deep-audit/run", methods=["POST"])
def deep_audit_run():
    golden_path = cfg.GOLDEN_BASELINE_DIR / "golden_snapshot.json"
    if not golden_path.exists():
        return jsonify({"error": "No golden baseline exists"}), 400

    if _deep_audit_running.is_set():
        return jsonify({"error": "Deep audit already in progress"}), 409

    def _run():
        _deep_audit_running.set()
        try:
            golden_baseline_manager.run_deep_audit()
        except Exception as e:
            logging.error(f"Background deep audit failed: {e}")
        finally:
            _deep_audit_running.clear()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({"status": "started"}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
