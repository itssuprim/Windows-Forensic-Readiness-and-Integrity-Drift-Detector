# test_coc_tamper.py
# CoC Tamper Evidence Scenario (Session 15)
#
# One end-to-end scenario covering three tamper vectors in sequence:
#   Vector 1 — Hash mismatch:   sign a snapshot, overwrite it, verify → coc_violation
#   Vector 2 — Injected file:   file dropped without signing → no CoC entry → violation
#   Vector 3 — ACL write-block: DACL deny-ACE physically prevents write on locked file
#
# Vectors 1-2 run without admin (lock/unlock patched to no-ops for isolation).
# Vector 3 requires admin + win32security — pass --acl to enable.
#
# Usage:
#   python test_coc_tamper.py           # Vectors 1-2
#   python test_coc_tamper.py --acl     # Vectors 1-3 (must be elevated)

import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, r"C:\Users\supri\OneDrive\Desktop\WFRIDD")

import config as cfg
import coc_manager

# ── Save real ACL functions before patching ───────────────────────────────────
_real_lock   = coc_manager.lock_file_immutable
_real_unlock = coc_manager.unlock_file

# Patch to no-ops for Vectors 1-2 so they run without admin.
coc_manager.lock_file_immutable = lambda fp: None
coc_manager.unlock_file         = lambda fp: None

# ── Temp workspace and isolated CoC log ───────────────────────────────────────
TMPDIR = Path(tempfile.mkdtemp(prefix="wfridd_coc_tamper_"))
_orig_coc_log    = cfg.COC_LOG_FILE
cfg.COC_LOG_FILE = TMPDIR / "test_chain_of_custody.json"

def _tmp(name: str, content: bytes) -> Path:
    p = TMPDIR / name
    p.write_bytes(content)
    return p

def _violations() -> list:
    lp = cfg.COC_LOG_FILE
    if not lp.exists():
        return []
    out = []
    for line in lp.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                e = json.loads(line)
                if e.get("event") == "coc_violation":
                    out.append(e)
            except json.JSONDecodeError:
                pass
    return out

passed = failed = 0

def ok(label):
    global passed
    passed += 1
    print(f"OK   {label}")

def fail(label, detail=""):
    global failed
    failed += 1
    print(f"FAIL {label}" + (f": {detail}" if detail else ""))

def assert_true(label, cond, detail=""):
    ok(label) if cond else fail(label, detail)

def assert_false(label, cond, detail=""):
    ok(label) if not cond else fail(label, "expected False, got True")

def assert_eq(label, got, expected):
    ok(label) if got == expected else fail(label, f"got={got!r}  expected={expected!r}")


print("=" * 60)
print("CoC Tamper Evidence Scenario")
print("=" * 60)


# ─────────────────────────────────────────────────────────────────
# Vector 1 — Hash mismatch
# Sign a snapshot, tamper its contents, verify → coc_violation
# ─────────────────────────────────────────────────────────────────
print("\n[Vector 1] Hash mismatch after tamper")

cfg.COC_LOG_FILE.unlink(missing_ok=True)

snapshot = _tmp("v1_snapshot.json", b'{"artefact": "run_keys_hklm", "data": {"S1Backdoor": "cmd.exe"}}')
recorded_hash = coc_manager.sign_and_lock(snapshot)
print(f"  Signed snapshot: {recorded_hash[:16]}...")

# Tamper: overwrite after signing.
snapshot.write_bytes(b'{"artefact": "run_keys_hklm", "data": {}}')
actual_hash = hashlib.sha256(snapshot.read_bytes()).hexdigest()
print(f"  Tampered hash:   {actual_hash[:16]}...")

result = coc_manager.verify_snapshot(snapshot)
assert_false("V1 verify_snapshot returns False on tampered file", result)

viols = _violations()
assert_true("V1 coc_violation entry written to log", len(viols) == 1)
assert_eq("V1 violation detail — hash mismatch",
          viols[0].get("detail"),
          "hash mismatch — file has been modified after signing")
assert_true("V1 recorded_sha256 in violation entry", "recorded_sha256" in viols[0])
assert_true("V1 actual_sha256 in violation entry",   "actual_sha256"   in viols[0])
assert_true("V1 hashes differ in entry",
            viols[0]["recorded_sha256"] != viols[0]["actual_sha256"])


# ─────────────────────────────────────────────────────────────────
# Vector 2 — Injected file (no CoC entry)
# File present on disk but never signed → no chain-of-custody record
# ─────────────────────────────────────────────────────────────────
print("\n[Vector 2] Injected file — no CoC entry")

cfg.COC_LOG_FILE.unlink(missing_ok=True)

injected = _tmp("v2_injected.json", b'{"injected": true, "data": {"EvilKey": "malware.exe"}}')
print(f"  File present:    {injected.name}")
print( "  Not signed — no sign_and_lock called")

result = coc_manager.verify_snapshot(injected)
assert_false("V2 verify_snapshot returns False for unsigned file", result)

viols = _violations()
assert_true("V2 coc_violation entry written to log", len(viols) == 1)
assert_eq("V2 violation detail — no entry",
          viols[0].get("detail"),
          "no CoC entry found — file may be injected or CoC log tampered")


# ─────────────────────────────────────────────────────────────────
# Vector 3 — ACL write-block (admin required)
# lock_file_immutable() DACL deny-ACE must physically block writes
# ─────────────────────────────────────────────────────────────────
RUN_ACL = "--acl" in sys.argv
print(f"\n[Vector 3] ACL write-block {'(RUNNING)' if RUN_ACL else '(SKIPPED — pass --acl, requires admin)'}")

if RUN_ACL:
    coc_manager.lock_file_immutable = _real_lock
    coc_manager.unlock_file         = _real_unlock

    target = _tmp("v3_acl.json", b"acl test content - deny write")
    _real_lock(target)
    print(f"  Locked: {target.name}")

    try:
        target.write_bytes(b"overwrite attempt")
        write_blocked = False
    except (PermissionError, OSError):
        write_blocked = True
    assert_true("V3 locked file — write attempt blocked by DACL", write_blocked)

    _real_unlock(target)
    try:
        target.write_bytes(b"write after unlock")
        write_allowed = True
    except (PermissionError, OSError):
        write_allowed = False
    assert_true("V3 unlocked file — write now succeeds", write_allowed)
else:
    print("  SKIP")


# ─────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────
cfg.COC_LOG_FILE = _orig_coc_log
for fp in TMPDIR.iterdir():
    try:
        _real_unlock(fp)
    except Exception:
        pass
shutil.rmtree(TMPDIR, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────
total = passed + failed
print(f"\n{'=' * 60}")
print(f"{passed}/{total} passed", "— all good" if not failed else "— FAILURES above")
