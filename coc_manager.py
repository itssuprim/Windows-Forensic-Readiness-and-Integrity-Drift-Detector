# coc_manager.py
# Chain of Custody: SHA-256 signing, ACL immutability lock, CoC log.
#
# Every evidence-grade file passes through three steps:
#   1. hash_file()            — SHA-256 of file contents
#   2. lock_file_immutable()  — deny write/delete to Everyone incl. Administrators
#   3. write_coc_entry()      — append a signed entry to chain_of_custody.json
#
# The CoC log itself follows the same lock/unlock cycle on every append:
#   unlock_file() → append → lock_file_immutable()
#
# This addresses the Capstone 1 gap (DEVLOG Session 1 cont.3):
# chain_of_custody.json was never chattr'd in Capstone 1, making it the
# least-protected file in the evidence chain. Every append here re-locks it.

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import config as cfg

# Snapshot timestamp format — validated before interpolating into PS scripts.
_TS_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')

# ACE type constant — avoids magic number 0 in lock/unlock functions.
# win32security.GetAce()[0][0] returns 0 for ACCESS_ALLOWED_ACE_TYPE.
_ACCESS_ALLOWED_ACE_TYPE = 0

logger = logging.getLogger(__name__)


# ── SHA-256 ───────────────────────────────────────────────────────────────────

def hash_file(filepath) -> str:
    """SHA-256 hex digest of a file. Reads in 64 KB chunks (large-file safe).

    This is the single canonical implementation — reporter.py imports it
    from here rather than reimplementing it (Capstone 1 audit finding #2:
    hash_file() was duplicated across reporter.py and coc_verifier.py).
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# ── ACL LOCKING ───────────────────────────────────────────────────────────────

def _deny_mask() -> int:
    """Deny direct file writes and destructive operations while preserving read access.

    FILE_GENERIC_WRITE is NOT used here: it includes READ_CONTROL (via
    STANDARD_RIGHTS_WRITE), which would deny reading the file — the opposite
    of what we want. Instead, deny only the specific file-write operations
    plus the filesystem-level destructive rights.

    WRITE_DAC is intentionally excluded from the deny mask. A deny-WRITE_DAC
    ACE for Everyone creates a self-locking ACL: SetFileSecurity and icacls
    both open the file with WRITE_DAC access internally, so the deny blocks
    even our own unlock_file() call (Bug 15 — Session 15). The compensating
    control is the SACL: any DACL modification fires Event ID 4670, creating
    a detectable audit trail of bypass attempts. SHA-256 verification catches
    tampering regardless of how the deny ACE was removed. WRITE_OWNER is
    still denied so ownership changes (which would grant implicit WRITE_DAC)
    are blocked and logged.
    """
    import ntsecuritycon as con
    return (
        con.FILE_WRITE_DATA          # overwrite file contents
        | con.FILE_APPEND_DATA       # append to file
        | con.FILE_WRITE_EA          # write extended attributes
        | con.FILE_WRITE_ATTRIBUTES  # modify timestamps, read-only flag
        | con.DELETE                 # delete the file
        | con.WRITE_OWNER            # change file owner (would grant implicit WRITE_DAC)
    )


def _enable_security_privilege() -> None:
    """Enable SeSecurityPrivilege on the current token so SACL writes succeed.

    SACL modification requires this privilege separately from admin rights.
    Failure is non-fatal: DACL protection still applies if SACL cannot be set.
    """
    import win32api
    import win32con
    import win32security

    h = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
    )
    luid = win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege")
    win32security.AdjustTokenPrivileges(
        h, False, [(luid, win32security.SE_PRIVILEGE_ENABLED)]
    )


def lock_file_immutable(filepath) -> None:
    """Deny write/delete/ACL-change to Everyone including Administrators.

    Windows has no chattr +i equivalent. This deny-ACE pattern is the
    compensating control: an explicit Deny ACE beats any Allow ACE for the
    same identity, so even an Administrator sees ACCESS_DENIED unless they
    first take ownership and reset the DACL — an operation that itself fires
    Security Event Log entries 4670 and 4663 via the SACL set here.

    Every call rebuilds the DACL from scratch:
      - Two new Deny ACEs (Everyone, Administrators) placed first
      - Existing Allow ACEs preserved
      - Any prior Deny ACEs replaced (not accumulated)
    """
    import ntsecuritycon as con
    import win32security

    path = str(filepath)
    mask = _deny_mask()

    everyone = win32security.CreateWellKnownSid(win32security.WinWorldSid, None)
    admins = win32security.CreateWellKnownSid(
        win32security.WinBuiltinAdministratorsSid, None
    )

    # ── DACL ─────────────────────────────────────────────────────────────────
    sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
    old_dacl = sd.GetSecurityDescriptorDacl()

    new_dacl = win32security.ACL()
    # Deny ACEs must precede Allow ACEs — Windows evaluates in order.
    new_dacl.AddAccessDeniedAce(win32security.ACL_REVISION, mask, everyone)
    new_dacl.AddAccessDeniedAce(win32security.ACL_REVISION, mask, admins)

    # Carry forward existing Allow ACEs; drop all prior Deny ACEs (replaced above).
    if old_dacl:
        for i in range(old_dacl.GetAceCount()):
            ace_header, ace_mask, ace_sid = old_dacl.GetAce(i)
            if ace_header[0] == _ACCESS_ALLOWED_ACE_TYPE:
                new_dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION, ace_mask, ace_sid
                )

    sd_new = win32security.SECURITY_DESCRIPTOR()
    sd_new.SetSecurityDescriptorDacl(True, new_dacl, False)
    win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd_new)

    # ── SACL — audit any bypass attempt ──────────────────────────────────────
    # Any attempt to modify the DACL, change ownership, or delete the file
    # will fire Event IDs 4670 (ACL/owner change) and 4663 (access attempt).
    # This creates an audit trail even if an attacker neutralises the DACL.
    try:
        _enable_security_privilege()
        sacl = win32security.ACL()
        sacl.AddAuditAccessAce(
            win32security.ACL_REVISION,
            con.FILE_WRITE_DATA | con.DELETE | con.WRITE_DAC | con.WRITE_OWNER,
            everyone,
            True,   # audit success
            True,   # audit failure
        )
        sd_sacl = win32security.SECURITY_DESCRIPTOR()
        sd_sacl.SetSecurityDescriptorSacl(True, sacl, False)
        win32security.SetFileSecurity(
            path, win32security.SACL_SECURITY_INFORMATION, sd_sacl
        )
    except Exception as e:
        # Non-fatal: DACL protection still active without SACL.
        logger.warning(f"SACL not set on {Path(path).name}: {e}")


def unlock_file(filepath) -> None:
    """Remove deny ACEs so a single write can proceed.

    MUST be followed immediately by lock_file_immutable() in the same
    function — never leave a file unlocked across call boundaries.
    The unlock itself fires the SACL audit entry (WRITE_DAC on this file),
    creating a log of every time the lock was temporarily lifted.

    WRITE_DAC is no longer in the deny mask (Bug 15 — Session 15), so
    SetFileSecurity can now remove the deny ACEs without a privilege bypass.
    """
    import win32security

    path = str(filepath)
    sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
    old_dacl = sd.GetSecurityDescriptorDacl()

    new_dacl = win32security.ACL()
    if old_dacl:
        for i in range(old_dacl.GetAceCount()):
            ace_header, ace_mask, ace_sid = old_dacl.GetAce(i)
            # Keep Allow ACEs, drop all Deny ACEs.
            # We are the only source of Deny ACEs on these files.
            if ace_header[0] == _ACCESS_ALLOWED_ACE_TYPE:
                new_dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION, ace_mask, ace_sid
                )

    sd_new = win32security.SECURITY_DESCRIPTOR()
    sd_new.SetSecurityDescriptorDacl(True, new_dacl, False)
    win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd_new)


# ── COC LOG ───────────────────────────────────────────────────────────────────

def _append_coc_entry(entry: dict) -> None:
    """Unlock CoC log → append one JSON line → relock.

    If the log does not exist yet, it is created and immediately locked.
    The try/finally ensures we always relock even if the write raises —
    the file is never left unlocked across a failure.
    """
    log_path = cfg.COC_LOG_FILE

    if log_path.exists():
        unlock_file(log_path)

    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    finally:
        if log_path.exists():
            lock_file_immutable(log_path)


def write_coc_entry(event: str, filepath, sha256: str) -> None:
    """Append a snapshot or report creation entry to chain_of_custody.json."""
    entry = {
        "timestamp": datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
        "event": event,
        "filepath": str(Path(filepath).resolve()),
        "sha256": sha256,
        "agent_id": cfg.AGENT_ID,
        "tool_version": cfg.AGENT_VERSION,
    }
    logger.info(f"CoC entry: {event} — {Path(filepath).name} [{sha256[:16]}...]")
    _append_coc_entry(entry)


def write_halt_entry(detail: str, baseline: str, current: str) -> None:
    """Append a coc_halt event when the detection cycle is aborted.

    Called by run.py when verify_both_snapshots() returns False. Kept as a
    separate public function so run.py does not have to call the private
    _append_coc_entry() directly.
    """
    _append_coc_entry({
        "timestamp":    datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
        "event":        "coc_halt",
        "detail":       detail,
        "baseline":     baseline,
        "current":      current,
        "agent_id":     cfg.AGENT_ID,
        "tool_version": cfg.AGENT_VERSION,
    })
    logger.warning(f"CoC halt recorded: {detail}")


def write_suppression_entry(
    artefact: str,
    change_detected: str,
    suppression_reason: str,
    suppression_rule: str,
    analyst_note: str,
) -> None:
    """Append a suppression event to chain_of_custody.json."""
    entry = {
        "timestamp": datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
        "event": "change_suppressed",
        "artefact": artefact,
        "change_detected": change_detected,
        "suppression_reason": suppression_reason,
        "suppression_rule": suppression_rule,
        "analyst_note": analyst_note,
        "agent_id": cfg.AGENT_ID,
        "tool_version": cfg.AGENT_VERSION,
    }
    logger.info(f"Suppression logged: [{suppression_rule}] {artefact}")
    _append_coc_entry(entry)


# ── SIGN AND LOCK ─────────────────────────────────────────────────────────────

def sign_and_lock(filepath, event: str = "snapshot_created") -> str:
    """Hash a file, ACL-lock it, and write its CoC entry.

    Returns the SHA-256 hex digest. Call immediately after writing a snapshot
    or report — the file is not evidence-grade until this function completes.
    reporter.py uses event="report_created" when signing PDF/JSON reports.
    """
    filepath = Path(filepath)
    sha256 = hash_file(filepath)
    lock_file_immutable(filepath)
    write_coc_entry(event, filepath, sha256)
    logger.info(f"Signed and locked: {filepath.name}")
    return sha256


# ── SNAPSHOT VERIFICATION ─────────────────────────────────────────────────────

def _read_coc_log() -> list:
    """Read all entries from chain_of_custody.json as a list of dicts."""
    log_path = cfg.COC_LOG_FILE
    if not log_path.exists():
        return []
    entries = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning(f"Malformed CoC log line {line_num} skipped")
    return entries


def verify_snapshot(filepath) -> bool:
    """Re-hash filepath and verify against its recorded CoC entry.

    Returns True if the hash matches the CoC-recorded value.
    Returns False and logs a CRITICAL alert if:
      - No CoC entry exists for this file
      - The hash differs from the recorded value

    The caller MUST halt the detection cycle on False.
    Do NOT auto-recover — backup recovery is investigator-initiated.
    """
    filepath = Path(filepath).resolve()
    filepath_str = str(filepath)

    entries = _read_coc_log()
    # Use the last matching CoC entry (most recent sign_and_lock for this file).
    recorded_hash = None
    for entry in entries:
        if (
            entry.get("event") in ("snapshot_created", "report_created")
            and Path(entry.get("filepath", "")).resolve() == filepath
        ):
            recorded_hash = entry.get("sha256")

    if recorded_hash is None:
        logger.critical(f"CoC VIOLATION: no entry found for {filepath.name}")
        _append_coc_entry({
            "timestamp": datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
            "event": "coc_violation",
            "filepath": filepath_str,
            "detail": "no CoC entry found — file may be injected or CoC log tampered",
            "agent_id": cfg.AGENT_ID,
            "tool_version": cfg.AGENT_VERSION,
        })
        return False

    actual_hash = hash_file(filepath)
    if actual_hash != recorded_hash:
        logger.critical(
            f"CoC VIOLATION: hash mismatch for {filepath.name}\n"
            f"  recorded : {recorded_hash}\n"
            f"  actual   : {actual_hash}"
        )
        _append_coc_entry({
            "timestamp": datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
            "event": "coc_violation",
            "filepath": filepath_str,
            "detail": "hash mismatch — file has been modified after signing",
            "recorded_sha256": recorded_hash,
            "actual_sha256": actual_hash,
            "agent_id": cfg.AGENT_ID,
            "tool_version": cfg.AGENT_VERSION,
        })
        return False

    logger.info(f"CoC verified: {filepath.name} [{actual_hash[:16]}...]")
    return True


def verify_both_snapshots(baseline_path, current_path) -> bool:
    """Phase 2 of the detection cycle: verify both snapshots before comparison.

    Runs BEFORE comparator.py. If either snapshot fails, halt the cycle —
    running a comparison on potentially tampered data produces meaningless
    results and could miss real drift. Recovery is investigator-initiated,
    never automatic. Returns True only if both pass.
    """
    baseline_ok = verify_snapshot(baseline_path)
    current_ok = verify_snapshot(current_path)

    if not baseline_ok or not current_ok:
        logger.critical(
            "Detection cycle HALTED — CoC verification failed. "
            "Do not proceed with comparison. "
            "Investigate manually; use backup recovery if required."
        )
        return False

    logger.info("Both snapshots verified — CoC intact. Proceeding to comparison.")
    return True


# ── BACKUP RECOVERY ───────────────────────────────────────────────────────────

def get_verified_backup(filepath) -> "Path | None":
    """Attempt backup recovery after a CoC violation on filepath.

    The backup is verified against the ORIGINAL FILE's CoC-recorded hash —
    not a hash of the backup itself. An attacker who tampers the primary snapshot
    cannot substitute a fabricated backup without matching the immutable CoC ledger.

    Returns the backup Path if it passes verification.
    Returns None if the backup is missing, also tampered, or has no CoC reference.
    The caller MUST halt if None is returned.

    Design matches Capstone 1 coc_verifier.get_verified_backup() (DEVLOG Session 1 cont.3).
    """
    filepath = Path(filepath).resolve()

    # Look up the CoC-recorded hash for the ORIGINAL file.
    entries = _read_coc_log()
    recorded_hash = None
    for entry in entries:
        if (
            entry.get("event") == "snapshot_created"
            and Path(entry.get("filepath", "")).resolve() == filepath
        ):
            recorded_hash = entry.get("sha256")

    if recorded_hash is None:
        logger.warning(
            f"get_verified_backup: no CoC entry for {filepath.name} — cannot verify backup"
        )
        return None

    # Derive backup path: backups/backup_<original_filename>
    backup_path = cfg.DIRS["backups"] / f"backup_{filepath.name}"
    if not backup_path.exists():
        logger.warning(f"get_verified_backup: no backup found for {filepath.name}")
        return None

    backup_hash = hash_file(backup_path)
    if backup_hash == recorded_hash:
        _append_coc_entry({
            "timestamp":          datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
            "event":              "snapshot_recovered",
            "original_filepath":  str(filepath),
            "backup_filepath":    str(backup_path),
            "sha256":             backup_hash,
            "agent_id":           cfg.AGENT_ID,
            "tool_version":       cfg.AGENT_VERSION,
        })
        logger.info(
            f"CoC recovery: {filepath.name} recovered from backup [{backup_hash[:16]}...]"
        )
        return backup_path

    # Backup also fails — both copies are compromised.
    logger.critical(
        f"CoC RECOVERY FAILED: backup hash mismatch for {filepath.name}\n"
        f"  original recorded : {recorded_hash}\n"
        f"  backup actual     : {backup_hash}\n"
        "  Both primary and backup are compromised — halt."
    )
    _append_coc_entry({
        "timestamp":       datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
        "event":           "coc_violation",
        "filepath":        str(backup_path),
        "detail":          "backup hash mismatch — both primary and backup are compromised",
        "recorded_sha256": recorded_hash,
        "actual_sha256":   backup_hash,
        "agent_id":        cfg.AGENT_ID,
        "tool_version":    cfg.AGENT_VERSION,
    })
    return None


# ── WINDOWS UPDATE DETECTION ──────────────────────────────────────────────────

def windows_update_ran_between(ts1: str, ts2: str) -> bool:
    """Return True if Windows Update (Event ID 19) fired between ts1 and ts2.

    ts1 and ts2 are ISO-8601 UTC strings in snapshot timestamp format
    (e.g. "2026-08-09T18:06:33Z"). Event ID 19 in the System log means
    Windows Update successfully installed an update package.

    Used by comparator.py to pass a flag into suppress_services() and
    suppress_critical_binary_hashes() so version/hash changes on Microsoft-
    signed binaries can be contextualised as Windows Update activity rather
    than tamper indicators.

    Raises ValueError if either timestamp does not match the expected format.
    Validates before string interpolation — ts1/ts2 come from snapshot JSON
    which is CoC-verified, but a tampered CoC bypass path (skip_coc_verify=True
    in tests) could inject arbitrary PowerShell via a malformed timestamp.
    """
    if not _TS_RE.match(ts1) or not _TS_RE.match(ts2):
        raise ValueError(
            f"Invalid timestamp format for windows_update_ran_between: "
            f"ts1={ts1!r}, ts2={ts2!r}. Expected YYYY-MM-DDTHH:MM:SSZ."
        )
    # ParseExact expects the literal 'Z' suffix — snapshot format "%Y-%m-%dT%H:%M:%SZ"
    ps_script = (
        "$start = [datetime]::ParseExact('{ts1}', 'yyyy-MM-ddTHH:mm:ssZ', $null).ToLocalTime(); "
        "$end = [datetime]::ParseExact('{ts2}', 'yyyy-MM-ddTHH:mm:ssZ', $null).ToLocalTime(); "
        "try {{ "
        "$ev = Get-WinEvent -FilterHashtable @{{LogName='System';Id=19;StartTime=$start;EndTime=$end}} "
        "-MaxEvents 1 -ErrorAction SilentlyContinue; "
        "if ($ev) {{ Write-Output 'found' }} else {{ Write-Output 'none' }} "
        "}} catch {{ Write-Output 'none' }}"
    ).format(ts1=ts1, ts2=ts2)

    from collectors._shared import run_command

    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        timeout=15,
    )

    if result["status"] in ("ok", "nonzero_exit"):
        found = result.get("stdout", "").strip().lower() == "found"
        logger.info(
            f"Windows Update between {ts1} .. {ts2}: "
            f"{'confirmed (Event ID 19 found)' if found else 'not detected'}"
        )
        return found

    logger.warning(f"windows_update_ran_between query failed: {result.get('status')}")
    return False
