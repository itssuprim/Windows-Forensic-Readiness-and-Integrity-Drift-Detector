# collection_agent.py
# Orchestrates all collectors registered in config.ARTEFACTS.
#
# Deliberately reads the artefact list from config.py rather than
# importing each collector module by name. Adding artefact #6 through
# #25 later means adding a row to config.ARTEFACTS — this file does
# not change. That is the fix for the pattern the Capstone 1 audit
# flagged: logic that has to be hand-duplicated per artefact.

import importlib
import json
import logging
from datetime import datetime, timezone

import config as cfg
import coc_manager
from collectors._shared import require_admin

cfg.ensure_dirs()  # create snapshots/, reports/, logs/, etc. before first use

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(cfg.APP_LOG),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def run_collector(artefact_name: str, spec: dict) -> dict:
    """Dynamically import and run the collector function for one artefact.

    A single collector raising or timing out must not take down the
    other 24. Failure is captured as a status field on that artefact's
    entry, not as an unhandled exception that kills the cycle.
    """
    try:
        module = importlib.import_module(spec["module"])
        func = getattr(module, spec["func"])
        result = func()
    except Exception as e:
        logger.error(f"{artefact_name} — collector crashed: {e}")
        result = {"status": "collector_error", "data": {}, "error": str(e)}

    return {
        "type": spec["type"],
        "comparator_mode": spec["comparator_mode"],
        "collection_status": result.get("status", "unknown"),
        "data": result.get("data", {}),
    }


def collect_all() -> dict:
    """Run every artefact registered in config.ARTEFACTS, build one snapshot."""
    require_admin()

    logger.info(f"Starting collection cycle — {len(cfg.ARTEFACTS)} artefacts registered")

    artefacts_out = {}
    for name, spec in cfg.ARTEFACTS.items():
        logger.info(f"Collecting: {name}")
        artefacts_out[name] = run_collector(name, spec)

    failed = [n for n, a in artefacts_out.items() if a["collection_status"] not in ("ok",)]
    if failed:
        logger.warning(f"{len(failed)} artefact(s) did not collect cleanly: {failed}")

    snapshot = {
        "timestamp": datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
        "agent_id": cfg.AGENT_ID,
        "os": "Windows",
        "tool_version": cfg.AGENT_VERSION,
        "artefacts": artefacts_out,
    }

    logger.info(f"Collection cycle complete — {len(failed)} failure(s)")
    return snapshot


def write_snapshot(snapshot: dict) -> str:
    """Write snapshot JSON, sign it, ACL-lock it, record a CoC entry, and write a backup.

    These steps make the output evidence-grade:
      1. Write JSON to snapshots/
      2. Copy identical bytes to backups/ BEFORE signing, so backup == original
      3. sign_and_lock(primary) — records the canonical SHA-256 in the CoC log
      4. ACL-lock the backup separately — backup is verified via the primary's
         CoC entry, not its own (Capstone 1 design from DEVLOG Session 1 cont.3)
    """
    ts = snapshot["timestamp"].replace(":", "").replace("-", "")
    path = cfg.DIRS["snapshots"] / f"snapshot_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, default=str)
    logger.info(f"Snapshot written: {path.name}")

    # Write backup from the same bytes before locking the primary.
    raw_bytes = path.read_bytes()
    backup_path = cfg.DIRS["backups"] / f"backup_snapshot_{ts}.json"
    backup_path.write_bytes(raw_bytes)

    sha256 = coc_manager.sign_and_lock(path)
    logger.info(f"Snapshot signed and locked: {path.name} [{sha256[:16]}...]")

    # Lock the backup — no separate CoC entry; verified via primary's recorded hash.
    coc_manager.lock_file_immutable(backup_path)
    logger.info(f"Backup written and locked: {backup_path.name}")

    return str(path)


if __name__ == "__main__":
    snap = collect_all()
    write_snapshot(snap)
