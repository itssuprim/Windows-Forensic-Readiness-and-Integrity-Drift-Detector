# collectors/filesystem.py
# Category F — Filesystem (3 artefacts, SEMI-STATIC/STATIC)
#   critical_binary_hashes  SEMI-STATIC  (mode 2)
#   alternate_data_streams  STATIC       (mode 1)
#   dll_hijack_paths        SEMI-STATIC  (mode 2)

import hashlib
import json
import logging
from pathlib import Path

import config as cfg
from collectors._shared import run_command

logger = logging.getLogger(__name__)

# ADS path array built once from config — CRITICAL_BINARIES is a constant.
# Backslashes in single-quoted PS strings are literal — no escaping needed.
_ADS_PATHS = ",".join(f"'{p}'" for p in cfg.CRITICAL_BINARIES)
_ADS_PS = (
    f"Get-Item -Stream * -Path @({_ADS_PATHS}) -ErrorAction SilentlyContinue"
    " | Where-Object {$_.Stream -ne ':$DATA'}"
    " | Select-Object FileName,Stream,Length"
    " | ConvertTo-Json -Compress"
)

# FileSystemRights is an enum type; [int] cast before -band avoids coercion
# failures on versions where the ACL object returns a named enum string.
# 278 = Write compound flag (WriteData|AppendData|WriteExtendedAttributes|
# WriteAttributes) — stable .NET enum value across framework versions.
# BUILTIN\\\\Users in the Python string produces BUILTIN\\Users in the PS
# string, which is the correct regex escape for the backslash in -match.
_HIJACK_PS = (
    "$dirs=[System.Environment]::GetEnvironmentVariable('PATH','Machine')"
    " -split ';' | Where-Object {$_ -ne ''};"
    "$dirs | ForEach-Object {"
    "  $d=$_;"
    "  $acl=try{Get-Acl $d -EA Stop}catch{$null};"
    "  $w=$false;"
    "  if($acl){"
    "    $w=[bool]($acl.Access | Where-Object {"
    "      $_.AccessControlType -eq 'Allow' -and"
    "      ([int]$_.FileSystemRights -band 278) -and"
    "      ($_.IdentityReference.Value -match"
    "       'Everyone|BUILTIN\\\\Users|Authenticated Users')"
    "    })"
    "  };"
    "  [PSCustomObject]@{Path=$d;Exists=(Test-Path $d);WritableByUsers=$w}"
    "} | ConvertTo-Json -Compress"
)


def collect_critical_binary_hashes() -> dict:
    """SHA-256 hashes of critical system binaries defined in config.CRITICAL_BINARIES.

    Per-file status is included in data rather than raising — a not_found or
    access_denied entry is itself a forensic finding (binary missing or locked
    is a stronger signal than a hash change).
    """
    data = {}
    for path_str in cfg.CRITICAL_BINARIES:
        p = Path(path_str)
        if not p.exists():
            data[path_str] = {"sha256": None, "size_bytes": None, "status": "not_found"}
            continue
        try:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            data[path_str] = {
                "sha256": h.hexdigest(),
                "size_bytes": p.stat().st_size,
                "status": "ok",
            }
        except PermissionError:
            data[path_str] = {"sha256": None, "size_bytes": None, "status": "access_denied"}
        except OSError as e:
            data[path_str] = {"sha256": None, "size_bytes": None, "status": "error", "error": str(e)}
    return {"status": "ok", "data": data}


def collect_alternate_data_streams() -> dict:
    """Alternate Data Streams on CRITICAL_BINARIES via Get-Item -Stream *.

    Scoped to CRITICAL_BINARIES only — System32 at large would add thousands
    of Zone.Identifier entries with no forensic value. Any ADS on a critical
    binary (the :$DATA main stream is filtered) is a tamper indicator.
    Empty dict is the expected clean baseline on an unmodified system.
    """
    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", _ADS_PS],
        timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS,
    )
    if result["status"] not in ("ok", "nonzero_exit"):
        return {"status": result["status"], "data": {}}
    raw = result["stdout"].strip()
    if not raw:
        return {"status": "ok", "data": {}}
    try:
        streams = json.loads(raw)
        if isinstance(streams, dict):
            streams = [streams]
        data: dict = {}
        for s in streams:
            fname = s.get("FileName", "")
            data.setdefault(fname, []).append({
                "stream": s.get("Stream"),
                "length": s.get("Length"),
            })
        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"alternate_data_streams: JSON parse failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}


def collect_dll_hijack_paths() -> dict:
    """Machine PATH directories and their writability by non-privileged identities.

    A PATH directory writable by Users/Everyone/Authenticated Users is a DLL
    hijack surface — a DLL planted there loads before the legitimate one in
    subsequent searches. A non-existent PATH directory is also a hijack risk
    (create the dir and you control the search slot).

    Machine PATH only — user PATH changes per-session and belongs in a
    separate dynamic artefact if needed. Keyed by directory path.

    Caveat: two known limitations. (1) Inspects Allow ACEs only — a Deny ACE
    for the same identity overrides Allow in Windows ACL evaluation, so this
    can false-positive (flags writable when a Deny blocks it in practice).
    (2) The identity regex only checks Everyone/BUILTIN\\Users/Authenticated
    Users — write access granted to any other identity (a named account, a
    custom group, a service account) is invisible to this check and produces
    a false negative. This collector detects the common case, not the
    complete case; treat writable_by_users: false as "not obviously hijackable
    by the standard non-admin groups," not as a proven-safe result.
    """
    result = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", _HIJACK_PS],
        timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS,
    )
    if result["status"] not in ("ok", "nonzero_exit"):
        return {"status": result["status"], "data": {}}
    raw = result["stdout"].strip()
    if not raw:
        return {"status": "ok", "data": {}}
    try:
        dirs = json.loads(raw)
        if isinstance(dirs, dict):
            dirs = [dirs]
        data = {
            d["Path"]: {
                "exists":             d.get("Exists"),
                "writable_by_users":  d.get("WritableByUsers"),
            }
            for d in dirs
            if d.get("Path")
        }
        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"dll_hijack_paths: JSON parse failed: {e}")
        return {"status": "error", "data": {}, "error": str(e)}
