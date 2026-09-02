#!/usr/bin/env python
# run.py
# Main entry point — two modes:
#   python run.py        → daemon (hourly by default, --interval MINUTES to override)
#   python run.py --now  → single cycle and exit

import argparse
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import schedule

import json

import coc_manager
import collection_agent
import comparator
import config as cfg
import golden_baseline_manager
import mongodb_store
import reporter
import severity_engine
from suppression import SUPPRESS_FNS

cfg.ensure_dirs()  # create project directories before log file paths are used below

_run_ts  = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
_run_log = cfg.DIRS["logs"] / f"run_{_run_ts}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(_run_log),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def _select_baseline(exclude: Path) -> Path | None:
    """Most recent snapshot in the snapshots dir that isn't the current one.

    Filename sort == chronological sort because filenames are
    snapshot_YYYYMMDDTHHMMSSZ.json.
    """
    candidates = [
        p for p in sorted(cfg.DIRS["snapshots"].glob("snapshot_*.json"))
        if p.resolve() != exclude.resolve()
    ]
    return candidates[-1] if candidates else None


def run_full_cycle() -> None:
    ts_start = datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT)
    logger.info("=" * 60)
    logger.info(f"CYCLE STARTED — {ts_start}")
    logger.info("=" * 60)

    # First-run golden baseline guard.
    # One collection serves two purposes: the data is ACL-locked as the immutable
    # golden baseline AND written to snapshots/ as the first daily snapshot so the
    # very next run can immediately compare against it rather than requiring a
    # third invocation before drift detection starts.
    golden_path = cfg.GOLDEN_BASELINE_DIR / "golden_snapshot.json"
    if not golden_path.exists():
        logger.info("First run — creating golden baseline and first daily snapshot...")
        golden_baseline_manager.create_golden_baseline()
        snapshot = json.loads(golden_path.read_text(encoding="utf-8"))
        collection_agent.write_snapshot(snapshot)
        mongodb_store.store_snapshot(snapshot)
        logger.info(
            "Golden baseline ACL-locked. First daily snapshot stored. "
            "Run again to start drift detection."
        )
        sys.exit(0)

    # Step 1: collect
    snapshot = collection_agent.collect_all()

    # Step 2: write snapshot (signs + locks + CoC entry)
    current_path = Path(collection_agent.write_snapshot(snapshot))

    # Baseline selection — first-run guard
    baseline_path = _select_baseline(current_path)
    if baseline_path is None:
        mongodb_store.store_snapshot(snapshot)
        logger.info("First run — baseline established. Run again to detect drift.")
        return

    # Step 3: CoC verification — attempt backup recovery on baseline failure.
    # Current snapshot was just collected and signed; if it fails, halt immediately
    # (no recovery makes sense for a file written seconds ago).
    # Baseline failure → try backups/ recovery before halting.
    current_ok  = coc_manager.verify_snapshot(current_path)
    baseline_ok = coc_manager.verify_snapshot(baseline_path)

    if not current_ok:
        logger.critical("CoC HALT: current snapshot failed verification — halting.")
        coc_manager.write_halt_entry(
            detail="current snapshot CoC verification failed — cycle halted",
            baseline=str(baseline_path),
            current=str(current_path),
        )
        sys.exit(1)

    if not baseline_ok:
        logger.warning(
            f"Baseline CoC violation — attempting backup recovery for {baseline_path.name} ..."
        )
        recovered = coc_manager.get_verified_backup(baseline_path)
        if recovered is None:
            logger.critical(
                "CoC HALT: backup recovery failed — both primary and backup compromised."
            )
            coc_manager.write_halt_entry(
                detail="baseline CoC violation, backup recovery failed — cycle halted",
                baseline=str(baseline_path),
                current=str(current_path),
            )
            sys.exit(1)
        logger.info(
            f"Baseline recovered from backup: {recovered.name} — continuing cycle."
        )
        baseline_path = recovered

    # Step 4: compare (skip_coc_verify=True — step 3 already verified)
    comparison_result = comparator.run_comparison(
        baseline_path, current_path,
        suppress_fns=SUPPRESS_FNS,
        skip_coc_verify=True,
    )

    # Step 5: score findings
    scored_result = severity_engine.score_findings(comparison_result["findings"])

    # Steps 6-7: JSON then PDF report
    ts_clean   = comparison_result.get("current_timestamp", ts_start).replace(":", "").replace("-", "")
    report_base = cfg.DIRS["reports"] / f"report_{ts_clean}"
    reporter.generate_json_report(comparison_result, scored_result, report_base.with_suffix(".json"))
    pdf_path = report_base.with_suffix(".pdf")
    reporter.generate_pdf_report(comparison_result, scored_result, pdf_path)

    # Step 8: store snapshot
    mongodb_store.store_snapshot(snapshot)

    # Step 9: store report
    mongodb_store.store_report(comparison_result, scored_result, str(pdf_path))

    # Step 10: store alerts (non-suppressed filtered inside store_alerts)
    current_ts = comparison_result.get("current_timestamp", ts_start)
    mongodb_store.store_alerts(
        scored_result["scored_alerts"] + scored_result["scored_suppressed"],
        current_ts,
    )

    top      = scored_result.get("top_severity", "NONE")
    n_alerts = len(scored_result.get("scored_alerts", []))
    logger.info("-" * 60)
    logger.info(f"CYCLE COMPLETE — top_severity={top}, alerts={n_alerts}, report={pdf_path.name}")
    logger.info("-" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Windows Forensic Readiness and Integrity Drift Detector",
    )
    parser.add_argument("--now", action="store_true",
                        help="Run one cycle and exit.")
    parser.add_argument("--interval", type=int, default=60, metavar="MINUTES",
                        help="Daemon cycle interval in minutes (default: 60).")
    parser.add_argument("--deep-audit", action="store_true",
                        help="Run a deep audit comparing current state against the golden baseline.")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info(f"{cfg.TOOL_NAME} v{cfg.AGENT_VERSION}")
    logger.info(f"Agent    : {cfg.AGENT_ID}")
    logger.info(f"Mode     : {'single (--now)' if args.now else f'daemon ({args.interval}m interval)'}")
    logger.info("=" * 60)

    if args.deep_audit:
        golden_baseline_manager.run_deep_audit()
        sys.exit(0)

    if args.now:
        run_full_cycle()
        sys.exit(0)

    # Daemon mode — run once immediately on startup, then on schedule
    logger.info(f"Daemon mode — every {args.interval} minute(s). Ctrl+C to stop.")
    run_full_cycle()
    schedule.every(args.interval).minutes.do(run_full_cycle)
    try:
        while True:
            schedule.run_pending()
            time.sleep(30)
    except KeyboardInterrupt:
        logger.info("Stopped by user — exiting cleanly")
        sys.exit(0)
