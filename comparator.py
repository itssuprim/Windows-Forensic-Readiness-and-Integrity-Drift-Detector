# comparator.py
# Three-mode drift comparison engine.
#
# Mode 1 — Static  (14 artefacts): added/removed/modified dict diff, no suppression.
# Mode 2 — Semi-Static (7 artefacts): diff + universal gate + per-artefact suppression.
# Mode 3 — Dynamic  (3 artefacts): pre-filter to relevant subset, then Mode 1 diff.
#
# Phase 2 of the detection cycle (CoC verification) runs here, before any
# comparison work. A tampered snapshot halts the cycle — running a diff against
# manipulated data produces meaningless results and must never happen silently.
#
# Windows Update detection is resolved once per cycle and passed into every
# Mode 2 suppression call that needs it (suppress_services,
# suppress_critical_binary_hashes). This coupling is explicit by design —
# see DEVLOG Session 6 corrections.

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import config as cfg
import coc_manager

logger = logging.getLogger(__name__)


# ── DATA TYPES ────────────────────────────────────────────────────────────────

@dataclass
class Change:
    """Raw change detected before gate/suppression decisions."""
    artefact: str
    change_type: str        # "added" | "removed" | "modified"
    key: str
    baseline_value: Any = None
    current_value: Any = None


@dataclass
class Finding:
    """A change that has passed through the gate/suppression layer.

    suppressed=True means the suppressor fired and the change is logged to the
    CoC suppression audit but does not become an alert. suppressed=False means
    either the gate blocked suppression or no suppressor fired — this is an alert.
    Both kinds are returned by run_comparison() so the PDF can render Section 4
    (Suppression Audit Summary) alongside the alert findings.
    """
    artefact: str
    change_type: str        # "added" | "removed" | "modified"
    key: str
    baseline_value: Any = None
    current_value: Any = None
    suppressed: bool = False
    suppression_rule: Optional[str] = None
    suppression_reason: Optional[str] = None


# ── SNAPSHOT I/O ──────────────────────────────────────────────────────────────

class SnapshotLoadError(Exception):
    """Raised when a snapshot file is missing or contains malformed JSON."""


def load_snapshot(path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise SnapshotLoadError(f"Snapshot file not found: {path}")
    except json.JSONDecodeError as e:
        raise SnapshotLoadError(f"Malformed snapshot JSON at {path}: {e}")


# ── UNIVERSAL GATE ────────────────────────────────────────────────────────────

def universal_gate(change: Change) -> bool:
    """Return True to force a Finding regardless of per-artefact suppression.

    Any True here means: bypass suppress_fn entirely, this change becomes an
    alert. The gate conditions are additive — one True is enough.

    Critical artefacts: wmi_subscriptions, run_keys_hklm, run_keys_hkcu,
    lsa_protection, winlogon_keys, event_log_cleared. Any change on these
    is always an alert — suppression never applies. This is the primary
    guard against an attacker adding a persistence mechanism and having it
    suppressed by a misconfigured rule.

    Repeated changes and cross-artefact attack patterns are evaluated at
    the severity_engine layer (Day 8), which has visibility into all findings
    simultaneously. Per-change pattern detection here would require state
    that the comparator does not maintain.
    """
    if change.artefact in cfg.CRITICAL_ARTEFACTS:
        return True
    return False


# ── DIFF PRIMITIVE ────────────────────────────────────────────────────────────

def _diff_dicts(artefact: str, baseline: dict, current: dict) -> list:
    """Return a Change per added/removed/modified key between two dicts."""
    b_keys = set(baseline.keys())
    c_keys = set(current.keys())
    changes = []

    for k in (c_keys - b_keys):
        changes.append(Change(artefact, "added", k,
                              baseline_value=None,
                              current_value=current[k]))
    for k in (b_keys - c_keys):
        changes.append(Change(artefact, "removed", k,
                              baseline_value=baseline[k],
                              current_value=None))
    for k in (b_keys & c_keys):
        if baseline[k] != current[k]:
            changes.append(Change(artefact, "modified", k,
                                  baseline_value=baseline[k],
                                  current_value=current[k]))
    return changes


# ── MODE 1 — STATIC ───────────────────────────────────────────────────────────

def compare_static(artefact: str, baseline: dict, current: dict) -> list:
    """Diff two dicts; every change is a Finding. No suppression layer."""
    return [
        Finding(
            artefact=c.artefact,
            change_type=c.change_type,
            key=c.key,
            baseline_value=c.baseline_value,
            current_value=c.current_value,
        )
        for c in _diff_dicts(artefact, baseline, current)
    ]


# ── MODE 2 — SEMI-STATIC ─────────────────────────────────────────────────────

def compare_semistatic(
    artefact: str,
    baseline: dict,
    current: dict,
    suppress_fn,
    windows_update_confirmed: bool = False,
) -> list:
    """Diff + universal gate + per-artefact suppression function.

    suppress_fn contract (met by every class in suppression.py):
      - callable: suppress_fn(change, windows_update_confirmed=bool) → bool
          True  = suppress (log to CoC, do not alert)
          False = do not suppress (becomes a Finding/alert)
      - suppress_fn.rule_id: str — suppression rule identifier for CoC log
      - suppress_fn.reason(change): str — human-readable reason for CoC log

    When the universal gate fires, suppress_fn is bypassed entirely —
    the change becomes a Finding regardless of what the suppressor would return.
    """
    findings = []

    for change in _diff_dicts(artefact, baseline, current):
        if universal_gate(change):
            findings.append(Finding(
                artefact=change.artefact,
                change_type=change.change_type,
                key=change.key,
                baseline_value=change.baseline_value,
                current_value=change.current_value,
            ))
            continue

        try:
            kwargs = {"windows_update_confirmed": windows_update_confirmed}
            if artefact == "services":
                kwargs["baseline_data"] = baseline
            should_suppress = suppress_fn(change, **kwargs)
        except Exception as e:
            logger.warning(
                f"suppress_fn raised for {artefact}/{change.key}: {e} — alerting"
            )
            should_suppress = False

        if should_suppress:
            try:
                reason  = suppress_fn.reason(change)
                rule_id = suppress_fn.rule_id
            except Exception:
                reason  = "suppression reason unavailable"
                rule_id = "SR-UNKNOWN"

            coc_manager.write_suppression_entry(
                artefact=artefact,
                change_detected=f"{change.change_type}: {change.key}",
                suppression_reason=reason,
                suppression_rule=rule_id,
                analyst_note="auto-suppressed by comparator",
            )
            findings.append(Finding(
                artefact=change.artefact,
                change_type=change.change_type,
                key=change.key,
                baseline_value=change.baseline_value,
                current_value=change.current_value,
                suppressed=True,
                suppression_rule=rule_id,
                suppression_reason=reason,
            ))
        else:
            findings.append(Finding(
                artefact=change.artefact,
                change_type=change.change_type,
                key=change.key,
                baseline_value=change.baseline_value,
                current_value=change.current_value,
            ))

    return findings


# ── MODE 3 — DYNAMIC ─────────────────────────────────────────────────────────

def _filter_ports_below_1024(key: str, value: dict) -> bool:
    """listening_ports: include only ports < 1024 for comparison.

    Key format is "address:port" (e.g. "0.0.0.0:445"). The filter tag
    "ports_below_1024" in config.py is metadata that routes here.
    Collector returns all ports raw; the policy of which ports are
    forensically interesting is applied here, not at collection time.
    """
    try:
        return int(key.rsplit(":", 1)[-1]) < 1024
    except (ValueError, IndexError):
        return False


def _batch_driver_signing(drivers: dict) -> dict:
    """Return {path: is_unsigned} for all unique paths in a loaded_drivers dict.

    One PowerShell call for all paths — same batched pattern as
    _batch_signing_status() in collectors/persistence.py. Drivers with no
    path field are treated as unsigned (conservative).
    """
    import shutil
    import tempfile
    import os
    from collectors._shared import run_command

    ps_exe = shutil.which("powershell.exe") or shutil.which("powershell")
    if not ps_exe:
        logger.error(
            "driver signing: powershell not found via shutil.which — "
            "treating all drivers as unsigned"
        )
        return {}

    unique_paths = {
        v.get("path", "").strip()
        for v in drivers.values()
        if v.get("path", "").strip()
    }
    if not unique_paths:
        return {}

    entries = []
    for p in unique_paths:
        safe = p.replace("'", "''")
        entries.append(f"@{{N='{safe}';E='{safe}'}}")

    ps_array = ",".join(entries)
    ps_script = (
        f"$cache=@{{}};$pairs=@({ps_array});"
        "foreach($p in $pairs){"
        "  if(-not $cache.ContainsKey($p.E)){"
        "    try{$s=Get-AuthenticodeSignature -FilePath $p.E -EA SilentlyContinue;"
        "        $cache[$p.E]=if($s){$s.Status.ToString()}else{'Unknown'}}"
        "    catch{$cache[$p.E]='Error'}"
        "  }"
        "  Write-Output ($p.N+[char]9+$cache[$p.E])"
        "}"
    )

    # Write script to a temp file — avoids WinError 206 (command line too long)
    # when there are 400+ driver paths in the $pairs array.
    script_fd, script_path = tempfile.mkstemp(suffix=".ps1")
    try:
        with os.fdopen(script_fd, "w", encoding="utf-8") as f:
            f.write(ps_script)
        result = run_command(
            [ps_exe, "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", script_path],
            timeout=cfg.SUBPROCESS_TIMEOUT_SECONDS * 6,
        )
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass

    signing_map: dict[str, bool] = {}
    if result["status"] not in ("ok", "nonzero_exit"):
        logger.warning(
            f"driver signing batch PS call failed: {result['status']} "
            f"(exe={ps_exe}, stderr={result.get('stderr', '')[:200]})"
        )
        return signing_map

    for line in result.get("stdout", "").splitlines():
        line = line.strip()
        if "\t" in line:
            path, status = line.split("\t", 1)
            signing_map[path] = status.lower() not in ("valid",)

    return signing_map


def _filter_loaded_drivers(key: str, value: dict) -> bool:
    """loaded_drivers: include only drivers that are unsigned or publisher unknown.

    Signing is resolved in a single batched PS call before the filter runs
    (see compare_dynamic, which calls _batch_driver_signing upfront and passes
    the result via a closure). Drivers with no path field are unsigned by default.
    """
    raise NotImplementedError(
        "_filter_loaded_drivers must not be called directly — "
        "compare_dynamic builds a closure that embeds the batch result."
    )


def _filter_scheduled_tasks(key: str, value: dict) -> bool:
    r"""scheduled_tasks: \Microsoft\ namespace excluded at collection time.
    All data received here is already pre-filtered — pass everything through.
    """
    return True


_DYNAMIC_FILTERS = {
    "listening_ports": _filter_ports_below_1024,
    "scheduled_tasks": _filter_scheduled_tasks,
}


def compare_dynamic(artefact: str, baseline: dict, current: dict) -> list:
    """Apply the artefact's pre-filter to both sides, then run Mode 1 diff.

    For loaded_drivers, signing status is resolved in a single batched PS call
    covering all unique paths from both snapshots. The per-entry filter is then
    a plain dict lookup — no subprocess per driver.
    """
    if artefact == "loaded_drivers":
        combined = {**baseline, **current}
        signing = _batch_driver_signing(combined)

        def _driver_filter(key: str, value: dict) -> bool:
            path = value.get("path", "").strip()
            if not path:
                return True  # no path → treat as unsigned (conservative)
            return signing.get(path, True)  # missing from map → unsigned

        filter_fn = _driver_filter
    else:
        filter_fn = _DYNAMIC_FILTERS.get(artefact)
        if filter_fn is None:
            logger.warning(
                f"No filter function registered for dynamic artefact '{artefact}' "
                f"— falling back to full diff"
            )
            return compare_static(artefact, baseline, current)

    filtered_baseline = {k: v for k, v in baseline.items() if filter_fn(k, v)}
    filtered_current  = {k: v for k, v in current.items()  if filter_fn(k, v)}
    return compare_static(artefact, filtered_baseline, filtered_current)


# ── MAIN ENTRY POINT ─────────────────────────────────────────────────────────

def run_comparison(
    baseline_path,
    current_path,
    suppress_fns: Optional[dict] = None,
    skip_coc_verify: bool = False,
) -> dict:
    """Full detection cycle comparison against a baseline snapshot.

    Args:
        baseline_path:   path to baseline snapshot JSON
        current_path:    path to current (just-collected) snapshot JSON
        suppress_fns:    dict of {artefact_name: suppress_callable} from
                         suppression.py. If None, mode-2 artefacts get no
                         suppression — all changes become findings.
        skip_coc_verify: set True only in unit tests. Never in production.

    Returns:
        {
            "baseline_timestamp":    str,
            "current_timestamp":     str,
            "windows_update_detected": bool,
            "findings":              [Finding, ...],  # all, incl. suppressed
            "alerts":                [Finding, ...],  # non-suppressed only
            "suppressed_count":      int,
        }

    Raises RuntimeError if CoC verification fails — caller must not
    continue the detection cycle.
    """
    baseline_path = Path(baseline_path)
    current_path  = Path(current_path)

    # ── Phase 2: CoC verification — must run before any data is loaded ────────
    if not skip_coc_verify:
        ok = coc_manager.verify_both_snapshots(baseline_path, current_path)
        if not ok:
            raise RuntimeError(
                "CoC verification failed — detection cycle halted. "
                "Do not run comparison on potentially tampered snapshots. "
                "Initiate manual investigation."
            )

    try:
        baseline = load_snapshot(baseline_path)
        current  = load_snapshot(current_path)
    except SnapshotLoadError as e:
        raise RuntimeError(f"Cannot load snapshot for comparison: {e}") from e

    ts_baseline = baseline.get("timestamp", "")
    ts_current  = current.get("timestamp", "")

    # ── Windows Update detection — resolved once, shared across mode-2 calls ──
    windows_update = False
    if ts_baseline and ts_current:
        windows_update = coc_manager.windows_update_ran_between(ts_baseline, ts_current)

    logger.info(
        f"Comparison: {ts_baseline} -> {ts_current} | "
        f"Windows Update detected: {windows_update}"
    )

    suppress_fns = suppress_fns or {}
    all_findings = []

    for artefact_name, spec in cfg.ARTEFACTS.items():
        mode = spec.get("comparator_mode", 1)

        b_entry = baseline["artefacts"].get(artefact_name, {})
        c_entry = current["artefacts"].get(artefact_name, {})

        # Skip artefacts with failed collection — a partial read is worse than
        # no read (could produce false negatives on drift).
        b_status = b_entry.get("collection_status")
        c_status = c_entry.get("collection_status")
        if b_status != "ok":
            logger.warning(f"Skipping {artefact_name}: baseline status={b_status}")
            continue
        if c_status != "ok":
            logger.warning(f"Skipping {artefact_name}: current status={c_status}")
            continue

        b_data = b_entry.get("data", {})
        c_data = c_entry.get("data", {})

        if mode == 1:
            findings = compare_static(artefact_name, b_data, c_data)

        elif mode == 2:
            suppress_fn = suppress_fns.get(artefact_name)
            if suppress_fn is None:
                # No suppressor wired — alert on everything (safe default).
                findings = [
                    Finding(
                        artefact=c.artefact,
                        change_type=c.change_type,
                        key=c.key,
                        baseline_value=c.baseline_value,
                        current_value=c.current_value,
                    )
                    for c in _diff_dicts(artefact_name, b_data, c_data)
                ]
            else:
                findings = compare_semistatic(
                    artefact_name, b_data, c_data,
                    suppress_fn,
                    windows_update_confirmed=windows_update,
                )

        elif mode == 3:
            raw = compare_dynamic(artefact_name, b_data, c_data)
            suppress_fn = suppress_fns.get(artefact_name)
            if suppress_fn is None:
                findings = raw
            else:
                findings = []
                for f in raw:
                    if suppress_fn(f, windows_update_confirmed=windows_update):
                        try:
                            reason  = suppress_fn.reason(f)
                            rule_id = suppress_fn.rule_id
                        except Exception:
                            reason  = "suppression reason unavailable"
                            rule_id = "SR-UNKNOWN"
                        # Write CoC suppression entry — same as mode-2.
                        # This was missing, leaving mode-3 suppressions with
                        # no audit trail in chain_of_custody.json.
                        coc_manager.write_suppression_entry(
                            artefact=artefact_name,
                            change_detected=f"{f.change_type}: {f.key}",
                            suppression_reason=reason,
                            suppression_rule=rule_id,
                            analyst_note="auto-suppressed by comparator",
                        )
                        findings.append(Finding(
                            artefact=f.artefact,
                            change_type=f.change_type,
                            key=f.key,
                            baseline_value=f.baseline_value,
                            current_value=f.current_value,
                            suppressed=True,
                            suppression_rule=rule_id,
                            suppression_reason=reason,
                        ))
                    else:
                        findings.append(f)

        else:
            logger.error(f"Unknown comparator_mode {mode} for {artefact_name} — skipping")
            continue

        alert_count = len([f for f in findings if not f.suppressed])
        supp_count  = len([f for f in findings if f.suppressed])
        if findings:
            logger.info(
                f"{artefact_name}: {alert_count} alert(s), {supp_count} suppressed"
            )

        all_findings.extend(findings)

    alerts    = [f for f in all_findings if not f.suppressed]
    suppressed = [f for f in all_findings if f.suppressed]

    logger.info(
        f"Comparison complete — {len(alerts)} alert(s), "
        f"{len(suppressed)} suppressed, "
        f"{len(all_findings)} total findings"
    )

    return {
        "baseline_timestamp":      ts_baseline,
        "current_timestamp":       ts_current,
        "windows_update_detected": windows_update,
        "findings":                all_findings,
        "alerts":                  alerts,
        "suppressed_count":        len(suppressed),
    }
