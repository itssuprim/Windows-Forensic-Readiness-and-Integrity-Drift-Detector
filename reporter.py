# reporter.py
# Generates JSON and PDF drift reports from comparator + severity engine output.
#
# hash_file() is imported from coc_manager — not re-implemented here.
# hash_file() was previously duplicated across reporter.py and coc_verifier.py;
# the canonical implementation lives in coc_manager.py and every consumer imports from there.

import dataclasses
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as _xe

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

import config as cfg
import coc_manager
from coc_manager import hash_file

logger = logging.getLogger(__name__)

# ── PAGE GEOMETRY ─────────────────────────────────────────────────────────────

_PAGE_W, _PAGE_H = A4
_MARGIN = 0.65 * inch
_TW = _PAGE_W - 2 * _MARGIN   # usable table width ≈ 501 pt

# ── PALETTE ───────────────────────────────────────────────────────────────────

_NAVY    = colors.HexColor("#1B2A4A")
_ROW_ALT = colors.HexColor("#F5F7FA")
_BORDER  = colors.HexColor("#CCCCCC")
_TEXT    = colors.HexColor("#1A1A1A")

_SEV_COLOR = {
    "CRITICAL":  colors.HexColor("#CC0000"),
    "HIGH":      colors.HexColor("#E07000"),
    "MEDIUM":    colors.HexColor("#B08000"),
    "LOW":       colors.HexColor("#1A8C1A"),
    "UNMATCHED": colors.HexColor("#888888"),
    "NONE":      colors.HexColor("#444444"),
}
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNMATCHED": 4}

# ── TEXT STYLES ───────────────────────────────────────────────────────────────

_BASE   = getSampleStyleSheet()
_S_TITLE = ParagraphStyle("WFTitle", fontName="Helvetica-Bold", fontSize=19,
                           textColor=colors.white, leading=23)
_S_SUBT  = ParagraphStyle("WFSubt",  fontName="Helvetica",       fontSize=9,
                           textColor=colors.HexColor("#9AAFC4"), leading=12)
_S_H1    = ParagraphStyle("WFH1",    fontName="Helvetica-Bold",  fontSize=11,
                           textColor=_NAVY, leading=14, spaceBefore=10, spaceAfter=5,
                           keepWithNext=1)
_S_BODY  = ParagraphStyle("WFBody",  fontName="Helvetica",       fontSize=9,
                           textColor=_TEXT, leading=12, spaceAfter=3)
_S_SMALL = ParagraphStyle("WFSmall", fontName="Helvetica",       fontSize=7.5,
                           textColor=_TEXT, leading=10)
_S_META  = ParagraphStyle("WFMeta",  fontName="Helvetica",       fontSize=9,
                           textColor=_TEXT, leading=13)
_S_MONO  = ParagraphStyle("WFMono",  fontName="Courier",         fontSize=7,
                           textColor=_TEXT, leading=9)

# ── PRIMITIVE HELPERS ─────────────────────────────────────────────────────────

def _p(text, style=None):
    return Paragraph(str(text) if text is not None else "", style or _S_SMALL)

def _trunc(s, n=60):
    s = str(s) if s is not None else ""
    return s if len(s) <= n else s[:n - 3] + "..."

def _sev_p(severity: str) -> Paragraph:
    col = _SEV_COLOR.get(severity, colors.grey)
    s = ParagraphStyle("sv", fontName="Helvetica-Bold", fontSize=8,
                       textColor=col, leading=10)
    return Paragraph(severity, s)

def _detail_str(sf) -> str:
    """Format baseline/current values into a readable before→after string."""
    if sf.change_type == "added":
        val = sf.current_value
        if isinstance(val, dict):
            parts = [f"<b>{_xe(k)}:</b> {_xe(_trunc(str(v), 30))}"
                     for k, v in list(val.items())[:5] if v is not None]
            return "Added — " + ", ".join(parts)
        return "Added: " + _xe(_trunc(str(val), 100))
    elif sf.change_type == "removed":
        val = sf.baseline_value
        if isinstance(val, dict):
            parts = [f"<b>{_xe(k)}:</b> {_xe(_trunc(str(v), 30))}"
                     for k, v in list(val.items())[:5] if v is not None]
            return "Removed — " + ", ".join(parts)
        return "Removed: " + _xe(_trunc(str(val), 100))
    else:
        # Use `is not None` rather than `or {}` — `or {}` coerces 0, False,
        # and "" to {}, losing legitimate registry DWORD/boolean values in diffs.
        bv = sf.baseline_value if sf.baseline_value is not None else {}
        cv = sf.current_value  if sf.current_value  is not None else {}
        if isinstance(bv, dict) and isinstance(cv, dict):
            changed = sorted(k for k in set(bv) | set(cv) if bv.get(k) != cv.get(k))
            parts = [
                f"<b>{_xe(k)}:</b> {_xe(_trunc(str(bv.get(k)), 22))}"
                f" → {_xe(_trunc(str(cv.get(k)), 22))}"
                for k in changed[:4]
            ]
            return "<br/>".join(parts)
        return _xe(_trunc(str(bv), 40)) + " → " + _xe(_trunc(str(cv), 40))


# ── TABLE STYLE HELPERS ───────────────────────────────────────────────────────

def _base_tbl():
    return [
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("GRID",          (0, 0), (-1, -1), 0.5, _BORDER),
        ("BACKGROUND",    (0, 0), (-1,  0), _NAVY),
        ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
        ("TEXTCOLOR",     (0, 0), (-1,  0), colors.white),
        ("FONTSIZE",      (0, 0), (-1,  0), 8),
    ]

def _stripe(n, start=1):
    return [
        ("BACKGROUND", (0, start + i), (-1, start + i),
         _ROW_ALT if i % 2 else colors.white)
        for i in range(n)
    ]

def _data_tbl():
    """_base_tbl() variant for tables with no dedicated header row.
    Resets row 0 from navy/white-text back to plain white/black-text."""
    return _base_tbl() + [
        ("BACKGROUND", (0, 0), (-1, 0), colors.white),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.black),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica"),
    ]


# ── SNAPSHOT LOADER ───────────────────────────────────────────────────────────

def _load_current_snapshot(current_timestamp: str) -> dict:
    ts_clean = current_timestamp.replace(":", "").replace("-", "")
    path = cfg.DIRS["snapshots"] / f"snapshot_{ts_clean}.json"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Could not load current snapshot: {e}")
        return {}


# ── SECTION BUILDERS ──────────────────────────────────────────────────────────

def _build_header(comparison_result: dict, scored_result: dict) -> list:
    has_alerts = bool(scored_result.get("scored_alerts"))
    top_sev    = scored_result.get("top_severity", "NONE")

    hdr_tbl = Table(
        [[Paragraph("Windows Forensic Readiness and<br/>Integrity Drift Detector", _S_TITLE)],
         [Paragraph(f"{cfg.TOOL_NAME} v{cfg.AGENT_VERSION}  |  Agent: {cfg.AGENT_ID}", _S_SUBT)]],
        colWidths=[_TW],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), _NAVY),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
            ("TOPPADDING",    (0, 0), (-1,  0), 14),
            ("BOTTOMPADDING", (0, 0), (-1,  0), 3),
            ("TOPPADDING",    (0, 1), (-1,  1), 2),
            ("BOTTOMPADDING", (0, 1), (-1,  1), 14),
        ]),
    )

    if has_alerts:
        banner_bg  = (colors.HexColor("#AA0000") if top_sev == "CRITICAL"
                      else colors.HexColor("#C05000") if top_sev == "HIGH"
                      else colors.HexColor("#B08000"))
        banner_txt = f"DRIFT DETECTED  —  TOP SEVERITY: {top_sev}"
    else:
        banner_bg  = colors.HexColor("#1A7A1A")
        banner_txt = "NO DRIFT  —  SYSTEM CLEAN"

    ban_tbl = Table(
        [[Paragraph(banner_txt, ParagraphStyle("bn", fontName="Helvetica-Bold",
                                               fontSize=11, textColor=colors.white, leading=14))]],
        colWidths=[_TW],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), banner_bg),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("TOPPADDING",    (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ]),
    )
    return [hdr_tbl, ban_tbl, Spacer(1, 0.12 * inch)]


def _build_stat_tiles(scored_result: dict) -> list:
    sc    = scored_result.get("severity_counts", {})
    total = sum(sc.values())
    tiles = [
        ("CRITICAL", sc.get("CRITICAL", 0), _SEV_COLOR["CRITICAL"]),
        ("HIGH",     sc.get("HIGH",     0), _SEV_COLOR["HIGH"]),
        ("MEDIUM",   sc.get("MEDIUM",   0), _SEV_COLOR["MEDIUM"]),
        ("LOW",      sc.get("LOW",      0), _SEV_COLOR["LOW"]),
        ("TOTAL",    total,                  _NAVY),
    ]
    cw = _TW / 5
    def _num(n, col):
        return Paragraph(str(n), ParagraphStyle("tn", fontName="Helvetica-Bold",
                         fontSize=22, textColor=col, leading=26, alignment=1))
    def _lbl(t):
        return Paragraph(t, ParagraphStyle("tl", fontName="Helvetica", fontSize=7.5,
                         textColor=colors.HexColor("#777777"), leading=10, alignment=1))
    data = [
        [_num(count, col) for _, count, col in tiles],
        [_lbl(label)      for label, _, _  in tiles],
    ]
    return [
        Table(data, colWidths=[cw] * 5, style=TableStyle([
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1,  0), 10),
            ("BOTTOMPADDING", (0, 0), (-1,  0), 2),
            ("TOPPADDING",    (0, 1), (-1,  1), 2),
            ("BOTTOMPADDING", (0, 1), (-1,  1), 10),
            ("BOX",           (0, 0), (-1, -1), 0.5, _BORDER),
            ("LINEAFTER",     (0, 0), (-2, -1), 0.5, _BORDER),
            ("BACKGROUND",    (0, 0), (-1, -1), colors.white),
        ])),
        Spacer(1, 0.08 * inch),
    ]


def _build_meta(comparison_result: dict) -> list:
    wu = "Yes" if comparison_result.get("windows_update_detected") else "No"
    lines = [
        f"<b>Generated:</b> {datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT)}",
        f"<b>Baseline snapshot:</b> {comparison_result.get('baseline_timestamp', 'N/A')}",
        f"<b>Current snapshot:</b>  {comparison_result.get('current_timestamp',  'N/A')}",
        f"<b>Windows Update detected between snapshots:</b> {wu}",
    ]
    return [Paragraph(l, _S_META) for l in lines] + [Spacer(1, 0.12 * inch)]


def _build_coc_verify(comparison_result: dict) -> list:
    ts_b = comparison_result.get("baseline_timestamp", "")
    ts_c = comparison_result.get("current_timestamp",  "")

    def _snap_path(ts):
        tc = ts.replace(":", "").replace("-", "")
        return cfg.DIRS["snapshots"] / f"snapshot_{tc}.json"

    # Build a {resolved_filepath: last_sha256} map in one pass over the log.
    # The original code called _read_coc_log() once per snapshot (O(n) scan
    # per call). With hundreds of log entries after weeks of hourly cycles,
    # this was O(n×k) where k=2 snapshots per report. One pass is O(n).
    _coc_entries = coc_manager._read_coc_log()
    _stored_hashes: dict = {}
    for _e in _coc_entries:
        if _e.get("event") in ("snapshot_created", "report_created"):
            _fp = str(Path(_e.get("filepath", "")).resolve())
            _stored_hashes[_fp] = _e.get("sha256")  # last entry wins (most recent)

    def _find_stored(path):
        return _stored_hashes.get(str(Path(path).resolve()))

    def _verdict_p(v):
        col = colors.HexColor("#1A8C1A") if v == "VERIFIED" else colors.HexColor("#CC0000")
        return Paragraph(v, ParagraphStyle("vp", fontName="Helvetica-Bold",
                                            fontSize=8, textColor=col, leading=10))

    cw_lbl  = 65
    cw_hash = int((_TW - cw_lbl - 80) / 2)
    cw_stat = _TW - cw_lbl - 2 * cw_hash
    rows = [["Snapshot", "Stored Hash (CoC)", "Computed Hash", "Status"]]

    for label, ts in [("Baseline", ts_b), ("Current", ts_c)]:
        path   = _snap_path(ts)
        stored = _find_stored(path)
        try:
            actual = hash_file(path) if path.exists() else None
        except Exception:
            actual = None
        verdict = (("VERIFIED" if stored == actual else "MISMATCH")
                   if (stored and actual) else "NOT FOUND")
        rows.append([
            _p(label),
            _p((stored[:32] + "...") if stored else "—", _S_MONO),
            _p((actual[:32] + "...") if actual else "—", _S_MONO),
            _verdict_p(verdict),
        ])

    return [
        Paragraph("Chain of Custody Verification", _S_H1),
        Table(rows, colWidths=[cw_lbl, cw_hash, cw_hash, cw_stat],
              style=TableStyle(_base_tbl() + _stripe(2)), repeatRows=1),
        Spacer(1, 0.12 * inch),
    ]


def _build_findings(scored_result: dict) -> list:
    alerts = scored_result.get("scored_alerts", [])

    if not alerts:
        story = [Paragraph("Findings (0 total)", _S_H1)]
        story.append(Paragraph(
            "No drift detected — system state unchanged and verified.",
            ParagraphStyle("cl", fontName="Helvetica-Bold", fontSize=10,
                           textColor=colors.HexColor("#1A7A1A"), leading=14, spaceAfter=6),
        ))
        return story

    story = [Paragraph(f"Findings ({len(alerts)} total)", _S_H1)]

    scored    = sorted([sf for sf in alerts if sf.severity != "UNMATCHED"],
                       key=lambda sf: _SEV_ORDER.get(sf.severity, 5))
    unmatched = [sf for sf in alerts if sf.severity == "UNMATCHED"]

    cw  = [52, 80, 52, 95, _TW - 52 - 80 - 52 - 95]
    hdr = ["Severity", "Artefact", "Change", "Key / Item", "Detail (before → after)"]

    def _rows(findings):
        return [hdr] + [
            [_sev_p(sf.severity), _p(_trunc(sf.artefact, 22)),
             _p(sf.change_type or ""), _p(_trunc(sf.key, 32)),
             _p(_detail_str(sf), _S_SMALL)]
            for sf in findings
        ]

    if scored:
        story.append(Table(_rows(scored), colWidths=cw,
                           style=TableStyle(_base_tbl() + _stripe(len(scored))),
                           repeatRows=1))

    if unmatched:
        story += [
            Spacer(1, 0.10 * inch),
            Paragraph(
                f"Unscored findings ({len(unmatched)}) — no matching rule in "
                "windows_rules.yaml; manual review required:",
                ParagraphStyle("umh", fontName="Helvetica-Bold", fontSize=8,
                               textColor=_SEV_COLOR["UNMATCHED"], leading=11,
                               spaceAfter=4, keepWithNext=1),
            ),
            Table(_rows(unmatched), colWidths=cw,
                  style=TableStyle(_base_tbl() + _stripe(len(unmatched))),
                  repeatRows=1),
        ]

    story.append(Spacer(1, 0.10 * inch))
    return story


_SR_WHAT = {
    "SR-001": (
        "Service state churn",
        "Windows automatically creates and destroys per-user session service instances "
        "(e.g. OneSyncSvc_XXXXX) each login. Known high-churn Microsoft services "
        "(WaaSMedicSvc, gpsvc, TrustedInstaller, etc.) also rotate state independently "
        "of updates. Microsoft-signed services whose only changes are state or start_type "
        "are suppressed when Windows Update is confirmed (Event ID 19 in System log). "
        "Any change to run_as, binary_path, or display_name always raises an alert "
        "regardless of this rule.",
    ),
    "SR-002": (
        "Critical binary hash change (Windows Update confirmed)",
        "Hash changes on cmd.exe, powershell.exe, svchost.exe, lsass.exe, or "
        "explorer.exe are suppressed only when Windows Update is confirmed between "
        "snapshots (Event ID 19). This is the only safe basis for suppression — "
        "a signing-status check alone cannot distinguish a legitimate Microsoft update "
        "from an attacker replacing a binary with a different signed version.",
    ),
    "SR-003": (
        "Software minor version increment",
        "An installed software entry whose publisher is unchanged and whose version "
        "incremented (not downgraded, not a major-version change) is treated as a "
        "routine patch update. Removals and additions are never suppressed — a package "
        "disappearing or appearing without a baseline entry always raises an alert.",
    ),
    "SR-004": (
        "Firewall rule re-enabled",
        "An existing Allow rule that was disabled (Enabled: False) and is now re-enabled "
        "(Enabled: True) with no change to Action or Direction. New rules and deleted "
        "rules always alert. Rules where Action changes (e.g. Block → Allow) always alert.",
    ),
    "SR-005": (
        "Defender signature update",
        "Windows Defender updates its signature database automatically; signature_version "
        "and signature_last_updated change on every definition update. These are high-"
        "frequency benign churn. Protection-state fields (antivirus_enabled, "
        "real_time_protection_enabled, am_service_enabled, nis_enabled) are never "
        "suppressed under this rule.",
    ),
    "SR-006": (
        "Defender exclusion list reduced",
        "Fewer Defender exclusions means a wider scan surface, which is a safer "
        "configuration. Removals from exclusion lists are suppressed. Additions are "
        "never suppressed — adding a Defender exclusion is a known attacker technique "
        "(MITRE T1562.001) to allow malware to run without triggering scans.",
    ),
    "SR-007": (
        "PATH directory addition / change (non-writable)",
        "A machine PATH directory was added or its attributes changed, but it remains "
        "non-writable by non-privileged identities (Everyone / BUILTIN\\Users / "
        "Authenticated Users). A directory that does not exist or becomes user-writable "
        "always raises an alert as a potential DLL hijack surface.",
    ),
}


_SR_TBL_STYLE_BASE = [
    ("FONTNAME",      (0, 0), (-1, -1), "Helvetica"),
    ("FONTSIZE",      (0, 0), (-1, -1), 8),
    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING",   (0, 0), (-1, -1), 5),
    ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
    ("TOPPADDING",    (0, 0), (-1, -1), 3),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ("GRID",          (0, 0), (-1, -1), 0.4, _BORDER),
    ("BACKGROUND",    (0, 0), (-1,  0), colors.HexColor("#3A4F6E")),
    ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
    ("TEXTCOLOR",     (0, 0), (-1,  0), colors.white),
]

_S_SR_HDR = ParagraphStyle("srh", fontName="Helvetica-Bold", fontSize=9,
                            textColor=_NAVY, leading=12, spaceAfter=3)
_S_SR_DESC = ParagraphStyle("srd", fontName="Helvetica", fontSize=8,
                             textColor=colors.HexColor("#444444"), leading=11,
                             leftIndent=10, spaceAfter=5)
_S_TH = ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=8,
                        textColor=colors.white, leading=10)


def _reason_template(reason: str) -> str:
    """Strip quoted values from a reason string to produce a grouping key.

    Replaces every single-quoted value ('...') with the placeholder '...'
    so that reasons that differ only in the specific key name or value
    map to the same template string and can be collapsed into one row.
    """
    return re.sub(r"'[^']*'", "'...'", (reason or "")[:100])


def _build_suppressed(scored_result: dict) -> list:
    supp = scored_result.get("scored_suppressed", [])
    if not supp:
        return []

    story = [PageBreak()]
    story.append(Paragraph(f"Auto-Suppressed Changes ({len(supp)})", _S_H1))
    story.append(Paragraph(
        "Changes below matched a suppression rule and were excluded from alert findings. "
        "Every suppression is recorded in the Chain of Custody log. "
        "Rows marked <b>×N</b> are collapsed groups — multiple items shared the same "
        "suppression logic; only a representative reason is shown and all affected keys "
        "are listed. Items marked <b>UNMATCHED</b> severity were suppressed normally "
        "but have no matching rule in windows_rules.yaml — not an error, just a gap "
        "in the severity rule set.",
        _S_SMALL,
    ))
    story.append(Spacer(1, 0.10 * inch))

    # ── first pass: group by suppression_rule ────────────────────────────────
    rule_groups: dict[str, list] = {}
    for sf in supp:
        rule = sf.suppression_rule or "UNKNOWN"
        rule_groups.setdefault(rule, []).append(sf)

    cw_chg = 56
    cw_key = 175
    cw_rsn = _TW - cw_chg - cw_key

    for rule_id, items in rule_groups.items():
        what_title, what_desc = _SR_WHAT.get(rule_id, (rule_id, ""))
        count_label = f"({len(items)} item{'s' if len(items) != 1 else ''})"

        hdr_para = Paragraph(
            f"<b>{_xe(rule_id)}</b>  —  {_xe(what_title)}  "
            f"<font color='#888888' size='8'>{count_label}</font>",
            _S_SR_HDR,
        )
        desc_para = (
            Paragraph(_xe(what_desc), _S_SR_DESC) if what_desc else Spacer(1, 2)
        )

        # ── second pass: collapse repeated reason templates within this rule ─
        # Key: (change_type, reason_template)
        # Items that share the same template are collapsed into one row.
        # Items whose template is unique within the rule get their own row.
        sub: dict[tuple, list] = {}
        for sf in items:
            sig = (sf.change_type or "", _reason_template(sf.suppression_reason))
            sub.setdefault(sig, []).append(sf)

        hdr_row = [
            Paragraph("Change",     _S_TH),
            Paragraph("Key / Item", _S_TH),
            Paragraph("Reason",     _S_TH),
        ]
        tbl_rows = [hdr_row]

        for (change_type, _tmpl), sg in sub.items():
            if len(sg) == 1:
                # Unique reason — one row, full key, full reason
                sf = sg[0]
                tbl_rows.append([
                    _p(change_type, _S_SMALL),
                    _p(_trunc(sf.key, 55), _S_SMALL),
                    _p(_xe(sf.suppression_reason or ""), _S_SMALL),
                ])
            else:
                # Repeated template — collapse: show count, list keys, template reason
                MAX_KEYS = 5
                key_parts = [sf.key for sf in sg[:MAX_KEYS]]
                overflow  = len(sg) - MAX_KEYS
                key_str   = ",  ".join(key_parts)
                if overflow > 0:
                    key_str += f"  (+{overflow} more)"
                tmpl_reason = _reason_template(sg[0].suppression_reason or "")
                tbl_rows.append([
                    _p(f"{change_type}  ×{len(sg)}", _S_SMALL),
                    _p(_xe(key_str), _S_SMALL),
                    _p(_xe(tmpl_reason), _S_SMALL),
                ])

        n_data = len(tbl_rows) - 1
        tbl_style = TableStyle(
            _SR_TBL_STYLE_BASE
            + [
                ("BACKGROUND", (0, 1 + i), (-1, 1 + i),
                 _ROW_ALT if i % 2 else colors.white)
                for i in range(n_data)
            ]
        )
        tbl = Table(tbl_rows, colWidths=[cw_chg, cw_key, cw_rsn],
                    repeatRows=1, style=tbl_style)

        story.append(KeepTogether([hdr_para, desc_para]))
        story.append(tbl)
        story.append(Spacer(1, 0.10 * inch))

    return story


def _build_coverage(current_snapshot: dict) -> list:
    artefacts_data = current_snapshot.get("artefacts", {})
    ok    = sum(1 for n in cfg.ARTEFACTS
                if artefacts_data.get(n, {}).get("collection_status") == "ok")
    total = len(cfg.ARTEFACTS)

    # Dedicated page for coverage table
    story = [PageBreak()]
    story.append(Paragraph(f"Artefact Coverage  ({ok}/{total} collected OK)", _S_H1))

    cw = [130, 40, 70, 50, _TW - 130 - 40 - 70 - 50]
    hdr  = ["Artefact", "Cat", "Type", "Mode", "Status"]
    rows = [hdr]
    style_cmds = _base_tbl()

    for i, (name, spec) in enumerate(cfg.ARTEFACTS.items()):
        entry  = artefacts_data.get(name, {})
        status = entry.get("collection_status", "N/A")
        rows.append([
            _p(name,                                 _S_SMALL),
            _p(spec.get("category", ""),             _S_SMALL),
            _p(spec.get("type", ""),                 _S_SMALL),
            _p(str(spec.get("comparator_mode", "")), _S_SMALL),
            _p(status,                               _S_SMALL),
        ])
        row = i + 1
        if status == "ok":
            style_cmds += [
                ("TEXTCOLOR", (4, row), (4, row), colors.HexColor("#1A8C1A")),
                ("FONTNAME",  (4, row), (4, row), "Helvetica-Bold"),
            ]
        elif status != "N/A":
            style_cmds.append(("TEXTCOLOR", (4, row), (4, row), colors.HexColor("#CC0000")))

    style_cmds += _stripe(total)
    story.append(Table(rows, colWidths=cw, style=TableStyle(style_cmds), repeatRows=1))
    story.append(Spacer(1, 0.15 * inch))
    return story


def _build_footer(output_path: Path) -> list:
    path_str = str(output_path)
    cmd = (f"python -c \"from coc_manager import hash_file; "
           f"print(hash_file(r'{path_str}'))\"")
    return [
        HRFlowable(width="100%", thickness=0.5, color=_BORDER, spaceAfter=5),
        Paragraph(
            f"<b>Chain of Custody:</b> This report is SHA-256 hashed immediately after "
            f"generation and recorded in chain_of_custody.json as a <i>report_created</i> "
            f"event. Verify with: "
            f"<font name='Courier' size='6.5'>{_xe(cmd)}</font>",
            _S_SMALL,
        ),
    ]


# ── JSON REPORT ───────────────────────────────────────────────────────────────

def generate_json_report(
    comparison_result: dict,
    scored_result: dict,
    output_path,
) -> str:
    """Write a JSON drift report, then sign and lock it in the CoC.

    Returns the SHA-256 of the written file.
    """
    output_path = Path(output_path)

    def _sf_dict(sf) -> dict:
        d = dataclasses.asdict(sf)
        for k in ("baseline_value", "current_value"):
            if d.get(k) is not None and not isinstance(d[k], (str, int, float, bool, list)):
                d[k] = str(d[k])
        return d

    report = {
        "report_type":   "drift_report",
        "generated_at":  datetime.now(timezone.utc).strftime(cfg.TIMESTAMP_FORMAT),
        "agent_id":      cfg.AGENT_ID,
        "tool_version":  cfg.AGENT_VERSION,
        "comparison": {
            "baseline_timestamp":      comparison_result.get("baseline_timestamp"),
            "current_timestamp":       comparison_result.get("current_timestamp"),
            "windows_update_detected": comparison_result.get("windows_update_detected"),
            "findings_count":          len(comparison_result.get("findings", [])),
            "alerts_count":            len(scored_result.get("scored_alerts", [])),
            "suppressed_count":        comparison_result.get("suppressed_count", 0),
        },
        "severity_counts": scored_result.get("severity_counts", {}),
        "top_severity":    scored_result.get("top_severity", "NONE"),
        "alerts":     [_sf_dict(sf) for sf in scored_result.get("scored_alerts", [])],
        "suppressed": [_sf_dict(sf) for sf in scored_result.get("scored_suppressed", [])],
    }

    if output_path.exists():
        coc_manager.unlock_file(output_path)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info(f"JSON report written: {output_path}")
    sha256 = coc_manager.sign_and_lock(output_path, event="report_created")
    logger.info(f"JSON report signed: {output_path.name} [{sha256[:16]}...]")
    return sha256


# ── PDF REPORT ────────────────────────────────────────────────────────────────

def generate_pdf_report(
    comparison_result: dict,
    scored_result: dict,
    output_path,
) -> str:
    """Write a PDF drift report, then sign and lock it in the CoC.

    Returns the SHA-256 of the written file.
    """
    output_path      = Path(output_path)
    current_snapshot = _load_current_snapshot(
        comparison_result.get("current_timestamp", "")
    )

    if output_path.exists():
        coc_manager.unlock_file(output_path)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=_MARGIN, rightMargin=_MARGIN,
        topMargin=_MARGIN,  bottomMargin=_MARGIN,
        title="WFRIDD Drift Report",
        author=cfg.AGENT_ID,
    )

    story = []
    story += _build_header(comparison_result, scored_result)
    story += _build_stat_tiles(scored_result)
    story += _build_meta(comparison_result)
    story += _build_coc_verify(comparison_result)
    story += _build_findings(scored_result)
    story += _build_suppressed(scored_result)
    story += _build_coverage(current_snapshot)
    story += _build_footer(output_path)

    doc.build(story)
    logger.info(f"PDF report written: {output_path}")
    sha256 = coc_manager.sign_and_lock(output_path, event="report_created")
    logger.info(f"PDF report signed: {output_path.name} [{sha256[:16]}...]")
    return sha256


# ── DEEP AUDIT PDF ─────────────────────────────────────────────────────────────

def generate_deep_audit_pdf(audit_result: dict, output_path) -> Path:
    """Write a 6-page deep audit PDF from audit_result.

    Does NOT sign or lock — the caller (golden_baseline_manager.run_deep_audit)
    calls coc_manager.sign_and_lock() as the next step. Returns the output path.

    Pages:
      1 — Cover
      2 — Executive Summary
      3 — Cumulative Changes by Artefact
      4 — Unresolved Security Findings
      5 — Chain of Custody
      6 — Verification Block
    """
    output_path = Path(output_path)
    if output_path.exists():
        coc_manager.unlock_file(output_path)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=_MARGIN, rightMargin=_MARGIN,
        topMargin=_MARGIN,  bottomMargin=_MARGIN,
        title="WFRIDD Deep Audit Report",
        author=cfg.AGENT_ID,
    )

    story: list = []
    story += _da_cover(audit_result)
    story += _da_exec_summary(audit_result)
    story += _da_changes_by_artefact(audit_result)
    story += _da_unresolved(audit_result)
    story += _da_coc(audit_result)
    story += _da_verification(audit_result)

    doc.build(story)
    logger.info(f"Deep audit PDF written: {output_path.name}")
    return output_path


# ── deep audit section builders ───────────────────────────────────────────────

def _da_cover(ar: dict) -> list:
    """Page 1 — Cover."""
    golden_sha = ar.get("golden_baseline_sha256", "")
    sha_display = (golden_sha[:32] + "...") if len(golden_sha) > 32 else golden_sha

    hdr = Table(
        [[Paragraph("DEEP AUDIT REPORT", _S_TITLE)],
         [Paragraph("Windows Forensic Readiness and Integrity Drift Detector", _S_SUBT)]],
        colWidths=[_TW],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), _NAVY),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
            ("TOPPADDING",    (0, 0), (-1,  0), 18),
            ("BOTTOMPADDING", (0, 0), (-1,  0), 3),
            ("TOPPADDING",    (0, 1), (-1,  1), 2),
            ("BOTTOMPADDING", (0, 1), (-1,  1), 14),
        ]),
    )

    class_tbl = Table(
        [[Paragraph(
            "FORENSIC EVIDENCE — CUMULATIVE DRIFT SINCE INSTALLATION",
            ParagraphStyle("cls", fontName="Helvetica-Bold", fontSize=10,
                           textColor=colors.white, leading=13),
        )]],
        colWidths=[_TW],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#8B0000")),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]),
    )

    meta_rows = [
        ("Installation date",           ar.get("installation_date",       "N/A")),
        ("Audit date",                   ar.get("audit_date",              "N/A")),
        ("Days since installation",      str(ar.get("days_since_installation", 0))),
        ("Golden baseline SHA-256",      sha_display),
        ("Golden baseline integrity",    ar.get("golden_baseline_integrity", "VERIFIED")),
    ]
    meta_data = [[_p(f"<b>{k}</b>", _S_META), _p(v, _S_MONO)] for k, v in meta_rows]
    meta_tbl  = Table(
        meta_data, colWidths=[_TW * 0.38, _TW * 0.62],
        style=TableStyle(
            _data_tbl() + _stripe(len(meta_data), start=0)
        ),
    )

    return [hdr, class_tbl, Spacer(1, 0.18 * inch), meta_tbl, PageBreak()]


def _da_exec_summary(ar: dict) -> list:
    """Page 2 — Executive Summary."""
    desc = (
        "A deep audit compares the current system state against the golden baseline — "
        "an ACL-locked forensic reference snapshot captured at installation time. "
        "Unlike daily drift reports, which compare consecutive snapshots, a deep audit "
        "reveals cumulative drift across the entire operational period and categorises "
        "each change as: <b>Legitimate</b> (suppressed by policy SR-001), "
        "<b>Unresolved</b> (previously alerted in the daily cycle but not remediated), "
        "or <b>Unknown</b> (never seen in any prior daily cycle — requires investigation)."
    )
    sc = ar.get("severity_counts", {})
    total_sev = sum(sc.values())
    rows = [
        ("Total changes since installation",   str(ar.get("total_changes", 0))),
        ("Legitimate changes",                 str(ar.get("legitimate_changes", 0))),
        ("Unresolved security findings",       str(ar.get("unresolved_security_findings", 0))),
        ("Unknown changes",                    str(ar.get("unknown_changes", 0))),
        ("CRITICAL findings",                  str(sc.get("CRITICAL", 0))),
        ("HIGH findings",                      str(sc.get("HIGH", 0))),
        ("MEDIUM findings",                    str(sc.get("MEDIUM", 0))),
        ("LOW findings",                       str(sc.get("LOW", 0))),
        ("Golden baseline integrity",          ar.get("golden_baseline_integrity", "VERIFIED")),
        ("Days since installation",            str(ar.get("days_since_installation", 0))),
    ]
    data = [[_p(f"<b>{k}</b>", _S_META), _p(v, _S_META)] for k, v in rows]
    tbl  = Table(
        data, colWidths=[_TW * 0.55, _TW * 0.45],
        style=TableStyle(_data_tbl() + _stripe(len(data), start=0)),
    )
    return [
        Paragraph("Executive Summary", _S_H1),
        HRFlowable(width=_TW, thickness=0.5, color=_BORDER, spaceAfter=6),
        Paragraph(desc, ParagraphStyle("da_desc", fontName="Helvetica", fontSize=8,
                                       leading=12, textColor=colors.black,
                                       spaceAfter=10)),
        tbl,
        PageBreak(),
    ]


def _da_changes_by_artefact(ar: dict) -> list:
    """Page 3 — Cumulative Changes by Artefact."""
    all_findings = (
        ar.get("legitimate", []) + ar.get("unresolved", []) + ar.get("unknown", [])
    )
    if not all_findings:
        return [
            Paragraph("Cumulative Changes by Artefact", _S_H1),
            HRFlowable(width=_TW, thickness=0.5, color=_BORDER, spaceAfter=6),
            _p("No changes detected since installation."),
            PageBreak(),
        ]

    # Group by artefact
    artefact_counts: dict = {}
    for sf in ar.get("legitimate", []):
        a = getattr(sf, "artefact", sf.get("artefact", "unknown") if isinstance(sf, dict) else "unknown")
        artefact_counts.setdefault(a, {"total": 0, "legitimate": 0, "unresolved": 0, "unknown": 0})
        artefact_counts[a]["total"]      += 1
        artefact_counts[a]["legitimate"] += 1
    for sf in ar.get("unresolved", []):
        a = getattr(sf, "artefact", sf.get("artefact", "unknown") if isinstance(sf, dict) else "unknown")
        artefact_counts.setdefault(a, {"total": 0, "legitimate": 0, "unresolved": 0, "unknown": 0})
        artefact_counts[a]["total"]      += 1
        artefact_counts[a]["unresolved"] += 1
    for sf in ar.get("unknown", []):
        a = getattr(sf, "artefact", sf.get("artefact", "unknown") if isinstance(sf, dict) else "unknown")
        artefact_counts.setdefault(a, {"total": 0, "legitimate": 0, "unresolved": 0, "unknown": 0})
        artefact_counts[a]["total"]    += 1
        artefact_counts[a]["unknown"]  += 1

    hdr = ["Artefact", "Total", "Legitimate", "Unresolved", "Unknown"]
    rows = [hdr]
    for art, counts in sorted(artefact_counts.items()):
        rows.append([
            _p(_xe(art), _S_SMALL),
            _p(str(counts["total"]),      _S_SMALL),
            _p(str(counts["legitimate"]), _S_SMALL),
            _p(str(counts["unresolved"]), _S_SMALL),
            _p(str(counts["unknown"]),    _S_SMALL),
        ])
    cws = [_TW * 0.40, _TW * 0.15, _TW * 0.15, _TW * 0.15, _TW * 0.15]
    tbl = Table(rows, colWidths=cws,
                style=TableStyle(_base_tbl() + _stripe(len(rows) - 1)))

    return [
        Paragraph("Cumulative Changes by Artefact", _S_H1),
        HRFlowable(width=_TW, thickness=0.5, color=_BORDER, spaceAfter=6),
        tbl,
        PageBreak(),
    ]


def _da_unresolved(ar: dict) -> list:
    """Page 4 — Unresolved Security Findings."""
    unresolved = ar.get("unresolved", [])
    elems = [
        Paragraph("Unresolved Security Findings", _S_H1),
        HRFlowable(width=_TW, thickness=0.5, color=_BORDER, spaceAfter=6),
    ]
    if not unresolved:
        elems.append(_p(
            "No unresolved security findings — system clean since installation.",
            _S_META,
        ))
        elems.append(PageBreak())
        return elems

    fd_map = ar.get("unresolved_first_detected", {})
    hdr = ["Artefact", "First Detected", "Key", "MITRE", "Severity"]
    rows = [hdr]
    for sf in unresolved:
        art   = getattr(sf, "artefact",        "") if not isinstance(sf, dict) else sf.get("artefact", "")
        key   = getattr(sf, "key",             "") if not isinstance(sf, dict) else sf.get("key", "")
        mitre = getattr(sf, "mitre_technique", "") if not isinstance(sf, dict) else sf.get("mitre_technique", "")
        sev   = getattr(sf, "severity",        "") if not isinstance(sf, dict) else sf.get("severity", "")
        fd    = fd_map.get(f"{art}::{key}", "N/A")
        fd_display = fd[:19] if fd and len(fd) > 19 else fd
        rows.append([
            _p(_xe(_trunc(art, 30)),   _S_SMALL),
            _p(_xe(fd_display),        _S_SMALL),
            _p(_xe(_trunc(key, 35)),   _S_SMALL),
            _p(_xe(mitre),             _S_SMALL),
            _sev_p(sev),
        ])
    cws = [_TW * 0.22, _TW * 0.18, _TW * 0.28, _TW * 0.14, _TW * 0.18]
    tbl = Table(rows, colWidths=cws,
                style=TableStyle(_base_tbl() + _stripe(len(rows) - 1)))
    elems.append(tbl)
    elems.append(PageBreak())
    return elems


def _da_coc(ar: dict) -> list:
    """Page 5 — Chain of Custody."""
    def _coc_row(label: str, entry: dict) -> list:
        ts  = entry.get("timestamp", "—")
        evt = entry.get("event",     "—")
        sha = entry.get("sha256",    entry.get("current_snapshot_sha256", "—"))
        sha = (sha[:24] + "...") if sha and len(sha) > 24 else (sha or "—")
        return [_p(f"<b>{_xe(label)}</b>", _S_SMALL), _p(_xe(ts), _S_MONO),
                _p(_xe(evt), _S_SMALL), _p(_xe(sha), _S_MONO)]

    hdr = ["Event", "Timestamp", "Type", "SHA-256 (prefix)"]
    rows = [
        hdr,
        _coc_row("Golden Baseline Created", ar.get("coc_golden_created",  {})),
        _coc_row("Deep Audit Initiated",    ar.get("coc_audit_initiated", {})),
        _coc_row("Baseline Verified",       ar.get("coc_golden_verified", {})),
        _coc_row("Deep Audit Completed",    ar.get("coc_audit_completed", {})),
    ]
    cws = [_TW * 0.24, _TW * 0.28, _TW * 0.24, _TW * 0.24]
    tbl = Table(rows, colWidths=cws,
                style=TableStyle(_base_tbl() + _stripe(len(rows) - 1)))
    return [
        Paragraph("Chain of Custody", _S_H1),
        HRFlowable(width=_TW, thickness=0.5, color=_BORDER, spaceAfter=6),
        tbl,
        PageBreak(),
    ]


def _da_verification(ar: dict) -> list:
    """Page 6 — Verification Block."""
    golden_sha  = ar.get("golden_baseline_sha256",  "")
    current_sha = ar.get("current_snapshot_sha256", "")
    verify_cmd  = (
        f"python -c \"import coc_manager; "
        f"print(coc_manager.verify_snapshot(r'{cfg.GOLDEN_BASELINE_DIR}/golden_snapshot.json'))\""
    )
    rows = [
        ("Golden baseline SHA-256",  golden_sha),
        ("Current snapshot SHA-256", current_sha),
        ("Verify command",           verify_cmd),
    ]
    data = [[_p(f"<b>{_xe(k)}</b>", _S_SMALL), _p(_xe(v), _S_MONO)] for k, v in rows]
    tbl  = Table(data, colWidths=[_TW * 0.30, _TW * 0.70],
                 style=TableStyle(_data_tbl() + _stripe(len(data), start=0)))
    return [
        Paragraph("Verification Block", _S_H1),
        HRFlowable(width=_TW, thickness=0.5, color=_BORDER, spaceAfter=6),
        tbl,
    ]
