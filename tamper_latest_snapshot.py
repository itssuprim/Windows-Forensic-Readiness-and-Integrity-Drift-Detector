# tamper_latest_snapshot.py
# CoC live tamper scenario — Session 15
#
# Simulates an attacker modifying the latest snapshot after it was signed.
# After running this script, run:
#
#   python run.py --now
#
# The CoC verification step will detect the hash mismatch, log a coc_violation
# entry, write a coc_halt entry, and exit with code 1.
#
# To restore: run python run.py --now again (it will collect a fresh snapshot
# and the tampered file is no longer the most recent, so it won't be selected
# as baseline again).

import json
import sys
from pathlib import Path

sys.path.insert(0, r"C:\Users\supri\OneDrive\Desktop\WFRIDD")

import config as cfg
import coc_manager

cfg.ensure_dirs()


# ── Find the latest snapshot ───────────────────────────────────────────────────
snapshots = sorted(cfg.DIRS["snapshots"].glob("snapshot_*.json"))
if not snapshots:
    print("ERROR: No snapshots found. Run python run.py --now first to create one.")
    sys.exit(1)

target = snapshots[-1]
print(f"Target snapshot : {target.name}")

# ── Confirm it has a CoC entry (otherwise we get 'no entry' not 'hash mismatch')
coc_entries = []
if cfg.COC_LOG_FILE.exists():
    for line in cfg.COC_LOG_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                e = json.loads(line)
                if (
                    e.get("event") in ("snapshot_created",)
                    and Path(e.get("filepath", "")).resolve() == target.resolve()
                ):
                    coc_entries.append(e)
            except json.JSONDecodeError:
                pass

if not coc_entries:
    print(
        "WARNING: No CoC entry found for this snapshot.\n"
        "         verify_snapshot() will report 'no CoC entry' instead of 'hash mismatch'.\n"
        "         Run python run.py --now once to establish a signed baseline, then re-run this script."
    )
    sys.exit(1)

recorded_hash = coc_entries[-1]["sha256"]
print(f"Recorded SHA-256: {recorded_hash}")

# ── Read and modify the snapshot content ──────────────────────────────────────
coc_manager.unlock_file(target)

data = json.loads(target.read_text(encoding="utf-8"))

# Inject a fake admin account into local_users.
# This simulates the attacker back-dating a privileged account into the baseline
# so the comparator would not flag it as 'added' in the next cycle.
FAKE_USER = "BackdoorAdmin_CoC"
if "local_users" in data.get("data", {}):
    data["data"]["local_users"][FAKE_USER] = {
        "sid": "S-1-5-21-9999999999-9999999999-9999999999-9999",
        "account_type": "Administrator",
        "status": "Active",
        "comment": "[INJECTED by attacker]",
    }
    print(f"Injected fake user '{FAKE_USER}' into local_users artefact.")
else:
    # Fallback: append a marker field to the top-level snapshot dict.
    data["__tampered__"] = True
    print("local_users artefact not found — added '__tampered__' marker to snapshot root.")

target.write_text(json.dumps(data, indent=2), encoding="utf-8")

actual_hash = coc_manager.hash_file(target)
print(f"Tampered SHA-256: {actual_hash}")
print(f"Hash changed    : {recorded_hash != actual_hash}")

# Leave the file unlocked so Python can write it — do NOT relock.
# An attacker who relocks would need a different recorded hash, which they
# cannot produce without also tampering the CoC log (itself protected).
# Either way, verify_snapshot() catches it: hash mismatch if tampered,
# 'no entry' if the CoC log was wiped.

print()
print("=" * 60)
print("Snapshot tampered. Now run:")
print()
print("  python run.py --now")
print()
print("Expected output: CoC VIOLATION: hash mismatch, cycle HALT, exit code 1.")
print("=" * 60)
