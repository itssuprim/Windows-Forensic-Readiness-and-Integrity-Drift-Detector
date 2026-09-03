# collectors/_shared.py
# Common helpers used by every collector module.
#
# This exists because of a lesson pulled straight from Capstone 1's
# drift_engine.py: 12 of its 36 compare_ functions were near-duplicates
# that differed only by a key name. Same trap applies here — 8 collector
# files each need privilege checks, timeout-wrapped WMI calls, and
# subprocess wrappers. Write it once, import it everywhere.

import logging
import subprocess
import sys
import threading
from typing import Any, Callable, Optional

import config as cfg

logger = logging.getLogger(__name__)


# ── PRIVILEGE CHECK ───────────────────────────
def is_admin() -> bool:
    """Return True if the current process has administrator rights."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as e:
        logger.error(f"Privilege check failed: {e}")
        return False


def require_admin() -> None:
    """Hard stop if not running elevated. Most of the 25 artefacts
    (registry hives under HKLM, service binaries, ACLs, driver list)
    are unreadable or partially readable without admin rights, and a
    partial read that looks like a successful collection is worse
    than no collection at all — it produces false negatives on
    drift. Fail loud, fail before Phase 1 starts."""
    if not is_admin():
        logger.critical(
            "Not running with administrator privileges. "
            "Collection requires elevation. Exiting."
        )
        sys.exit(1)
    logger.info("Privilege check passed — running as administrator.")


# ── TIMEOUT WRAPPER (WMI + anything else that can hang) ──────────
class CollectorTimeoutError(Exception):
    pass


def run_with_timeout(
    fn: Callable[[], Any],
    timeout: float = cfg.WMI_TIMEOUT_SECONDS,
    label: str = "collector call",
) -> Any:
    """Run fn() on a worker thread and enforce a hard timeout.

    WMI queries and some registry/service calls can hang indefinitely
    on a live endpoint (service not responding, WMI repository
    corruption, etc). A single hung collector must not stall the
    entire 8-collector cycle. This is a hard requirement, not a
    nice-to-have — build it before writing collector #1, not after
    collector #1 hangs during testing.

    COM (which WMI uses internally) requires CoInitialize() on every
    thread that touches it — the main thread has it automatically,
    worker threads do not. CoUninitialize() in the finally block
    cleans up even if the collector crashes, which prevents the
    IUnknown release warnings that appear when COM objects are
    garbage-collected on an uninitialized thread.
    """
    result: dict[str, Any] = {}
    error: dict[str, BaseException] = {}

    def _target():
        try:
            import gc
            import pythoncom
            pythoncom.CoInitialize()
            try:
                result["value"] = fn()
            finally:
                gc.collect()  # Force COM object release before CoUninitialize.
                # WMI objects hold COM references — if they're still alive when
                # CoUninitialize() runs, Windows prints IUnknown release warnings.
                # gc.collect() ensures they're dereferenced first.
                pythoncom.CoUninitialize()
        except BaseException as e:  # noqa: BLE001 - must capture everything
            error["value"] = e

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout)

    if t.is_alive():
        logger.error(f"{label} — timed out after {timeout}s")
        raise CollectorTimeoutError(f"{label} exceeded {timeout}s timeout")

    if "value" in error:
        raise error["value"]

    return result.get("value")


# ── REGISTRY READ ─────────────────────────────
def read_registry_value(
    hive: str, subkey: str, value_name: Optional[str] = None
) -> dict:
    """Read a single value, or all values, from a registry key.

    hive: one of "HKLM", "HKCU".
    Returns a dict with status + data, never raises — a missing key
    or missing value is itself forensically meaningful (e.g. RDP key
    absent vs explicitly disabled are different findings) so it is
    reported as data, not swallowed as an exception.
    """
    import winreg

    hive_map = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
    }
    if hive not in hive_map:
        raise ValueError(f"Unsupported hive: {hive}")

    try:
        with winreg.OpenKey(hive_map[hive], subkey) as key:
            if value_name is not None:
                data, reg_type = winreg.QueryValueEx(key, value_name)
                return {"status": "ok", "data": {value_name: data}}

            values = {}
            i = 0
            while True:
                try:
                    name, data, reg_type = winreg.EnumValue(key, i)
                    values[name] = data
                    i += 1
                except OSError:
                    break
            return {"status": "ok", "data": values}
    except FileNotFoundError:
        return {"status": "not_found", "data": {}}
    except PermissionError:
        return {"status": "access_denied", "data": {}}
    except OSError as e:
        return {"status": "error", "data": {}, "error": str(e)}


# ── SUBPROCESS WRAPPER ────────────────────────
def run_command(args: list[str], timeout: float = cfg.SUBPROCESS_TIMEOUT_SECONDS) -> dict:
    """Run a command, capture stdout, never raise on non-zero exit —
    a command that fails (e.g. netsh rule not found) is still a
    collectible fact about system state.

    Uses Popen + communicate() explicitly rather than subprocess.run(
    capture_output=True) — the DEVLOG Session 1 Bug 2 constraint bans
    capture_output=True for large output (firewall rules, services batch).
    communicate() drains both pipes concurrently via internal threads,
    which avoids the pipe-buffer deadlock that capture_output can trigger
    on Windows when stdout or stderr exceeds ~64 KB.
    """
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()  # drain pipes so the process exits cleanly
            logger.error(f"Command timed out: {' '.join(args)}")
            return {"status": "timeout", "returncode": None, "stdout": "", "stderr": ""}
        return {
            "status": "ok" if proc.returncode == 0 else "nonzero_exit",
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }
    except FileNotFoundError as e:
        return {"status": "not_found", "returncode": None, "stdout": "", "stderr": str(e)}