"""Core engine for MFTPARSE.

Parses an NTFS $MFT CSV export (MFTECmd-style columns) and applies forensic
heuristics to surface timestomping and suspicious file activity.

Key detections
--------------
* Timestomping: $STANDARD_INFORMATION (SI) timestamps that predate or diverge
  from $FILE_NAME (FN) timestamps. FN timestamps are kernel-set on rename/create
  and are much harder for attackers to forge than SI timestamps (touched by the
  common Windows API SetFileTime). SI < FN, or SI timestamps with zeroed
  sub-second precision while FN has precision, are classic timestomp tells.
* Suspicious locations: executables / scripts dropped in temp, recycle bin,
  user profile roots, or other staging directories.
* Masquerading extensions: double extensions and executable content hiding
  behind benign-looking names.
"""
from __future__ import annotations

import csv
import datetime as _dt
import html as _html
import io
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_SUSPICIOUS_DIR_PATTERNS = [
    re.compile(r"\\(Temp|tmp)\\", re.IGNORECASE),
    re.compile(r"\\\$Recycle\.Bin\\", re.IGNORECASE),
    re.compile(r"\\AppData\\Local\\Temp\\", re.IGNORECASE),
    re.compile(r"\\Windows\\Temp\\", re.IGNORECASE),
    re.compile(r"\\PerfLogs\\", re.IGNORECASE),
    re.compile(r"\\ProgramData\\", re.IGNORECASE),
    re.compile(r"\\Users\\Public\\", re.IGNORECASE),
]

_EXEC_EXTS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jse", ".wsf", ".hta", ".jar", ".msi", ".pif", ".cpl",
}

_BENIGN_LOOKING = {
    ".pdf", ".doc", ".docx", ".txt", ".jpg", ".jpeg", ".png", ".gif",
    ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".csv",
}

# Header aliases -> canonical field. Lowercased, non-alnum stripped for match.
_FIELD_ALIASES = {
    "entrynumber": "entry",
    "entry": "entry",
    "recordnumber": "entry",
    "inuse": "in_use",
    "isdirectory": "is_directory",
    "isadirectory": "is_directory",
    "filename": "name",
    "name": "name",
    "parentpath": "parent_path",
    "path": "parent_path",
    "extension": "extension",
    "ext": "extension",
    "filesize": "size",
    "size": "size",
    # $STANDARD_INFORMATION timestamps
    "created0x10": "si_created",
    "sicreated": "si_created",
    "created": "si_created",
    "lastmodified0x10": "si_modified",
    "simodified": "si_modified",
    "lastmodified": "si_modified",
    "modified": "si_modified",
    "lastaccessed0x10": "si_accessed",
    "siaccessed": "si_accessed",
    "lastaccessed": "si_accessed",
    "lastrecordchange0x10": "si_record_changed",
    "sirecordchanged": "si_record_changed",
    # $FILE_NAME timestamps
    "created0x30": "fn_created",
    "fncreated": "fn_created",
    "lastmodified0x30": "fn_modified",
    "fnmodified": "fn_modified",
    "lastaccessed0x30": "fn_accessed",
    "fnaccessed": "fn_accessed",
    "lastrecordchange0x30": "fn_record_changed",
    "fnrecordchanged": "fn_record_changed",
}

_TS_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%m/%d/%Y %H:%M:%S.%f",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
]


def _norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (h or "").lower())


def _parse_ts(raw: str) -> Optional[_dt.datetime]:
    if not raw:
        return None
    s = raw.strip().rstrip("Z").strip()
    if not s or s in ("0", "-", "N/A"):
        return None
    for fmt in _TS_FORMATS:
        try:
            return _dt.datetime.strptime(s, fmt)
        except ValueError:
            continue
    # last resort: ISO
    try:
        return _dt.datetime.fromisoformat(s)
    except ValueError:
        return None


def _ts_str(ts: Optional[_dt.datetime]) -> Optional[str]:
    if ts is None:
        return None
    return ts.strftime("%Y-%m-%d %H:%M:%S.%f")


def _truthy(raw: str) -> bool:
    return (raw or "").strip().lower() in ("1", "true", "yes", "y", "t")


@dataclass
class MftRecord:
    entry: Optional[int] = None
    name: str = ""
    parent_path: str = ""
    extension: str = ""
    size: Optional[int] = None
    in_use: bool = True
    is_directory: bool = False
    si_created: Optional[_dt.datetime] = None
    si_modified: Optional[_dt.datetime] = None
    si_accessed: Optional[_dt.datetime] = None
    si_record_changed: Optional[_dt.datetime] = None
    fn_created: Optional[_dt.datetime] = None
    fn_modified: Optional[_dt.datetime] = None
    fn_accessed: Optional[_dt.datetime] = None
    fn_record_changed: Optional[_dt.datetime] = None

    @property
    def full_path(self) -> str:
        parent = (self.parent_path or "").rstrip("\\/")
        if parent and self.name:
            return f"{parent}\\{self.name}"
        return self.name or parent

    @property
    def ext_lower(self) -> str:
        ext = self.extension
        if not ext and "." in self.name:
            ext = self.name[self.name.rfind("."):]
        if ext and not ext.startswith("."):
            ext = "." + ext
        return ext.lower()


@dataclass
class Finding:
    rule: str
    severity: str
    entry: Optional[int]
    path: str
    detail: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class AnalysisResult:
    findings: list = field(default_factory=list)
    total_records: int = 0
    analyzed_records: int = 0
    counts: dict = field(default_factory=dict)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


def parse_mft_csv(text: str) -> list:
    """Parse an $MFT CSV export into MftRecord objects."""
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return []
    header = rows[0]
    colmap = {}
    for idx, col in enumerate(header):
        canon = _FIELD_ALIASES.get(_norm_header(col))
        if canon and canon not in colmap:
            colmap[canon] = idx
    records = []
    for row in rows[1:]:
        if not any(c.strip() for c in row):
            continue

        def cell(name: str) -> str:
            i = colmap.get(name)
            if i is None or i >= len(row):
                return ""
            return row[i]

        entry_raw = cell("entry").strip()
        try:
            entry = int(entry_raw) if entry_raw else None
        except ValueError:
            entry = None
        size_raw = cell("size").strip().replace(",", "")
        try:
            size = int(size_raw) if size_raw else None
        except ValueError:
            size = None
        rec = MftRecord(
            entry=entry,
            name=cell("name").strip(),
            parent_path=cell("parent_path").strip(),
            extension=cell("extension").strip(),
            size=size,
            in_use=_truthy(cell("in_use")) if colmap.get("in_use") is not None else True,
            is_directory=_truthy(cell("is_directory")),
            si_created=_parse_ts(cell("si_created")),
            si_modified=_parse_ts(cell("si_modified")),
            si_accessed=_parse_ts(cell("si_accessed")),
            si_record_changed=_parse_ts(cell("si_record_changed")),
            fn_created=_parse_ts(cell("fn_created")),
            fn_modified=_parse_ts(cell("fn_modified")),
            fn_accessed=_parse_ts(cell("fn_accessed")),
            fn_record_changed=_parse_ts(cell("fn_record_changed")),
        )
        records.append(rec)
    return records


def _has_subsecond(ts: Optional[_dt.datetime]) -> bool:
    return ts is not None and ts.microsecond != 0


def _check_timestomp(rec: MftRecord) -> list:
    findings = []
    si_c, fn_c = rec.si_created, rec.fn_created
    si_m, fn_m = rec.si_modified, rec.fn_modified
    # Rule 1: SI created predates FN created. FN is set by the kernel at
    # create/rename; SI < FN by a meaningful margin means SI was backdated.
    if si_c and fn_c and si_c < fn_c:
        delta = (fn_c - si_c).total_seconds()
        if delta > 1:
            findings.append(Finding(
                rule="timestomp_si_before_fn",
                severity="high",
                entry=rec.entry,
                path=rec.full_path,
                detail=(
                    f"$SI created ({_ts_str(si_c)}) predates $FN created "
                    f"({_ts_str(fn_c)}) by {delta:.0f}s — likely backdated."
                ),
                evidence={
                    "si_created": _ts_str(si_c),
                    "fn_created": _ts_str(fn_c),
                    "delta_seconds": round(delta, 3),
                },
            ))
    # Rule 2: SI modified predates SI created — impossible without tampering.
    if si_c and si_m and si_m < si_c:
        delta = (si_c - si_m).total_seconds()
        if delta > 1:
            findings.append(Finding(
                rule="timestomp_modified_before_created",
                severity="high",
                entry=rec.entry,
                path=rec.full_path,
                detail=(
                    f"$SI modified ({_ts_str(si_m)}) is earlier than $SI "
                    f"created ({_ts_str(si_c)}) — chronologically impossible."
                ),
                evidence={
                    "si_created": _ts_str(si_c),
                    "si_modified": _ts_str(si_m),
                },
            ))
    # Rule 3: SI sub-second precision zeroed while FN retains precision. The
    # SetFileTime API used by most timestomp tools writes truncated values.
    si_zero = (si_c is not None and not _has_subsecond(si_c)
               and si_m is not None and not _has_subsecond(si_m))
    fn_prec = _has_subsecond(fn_c) or _has_subsecond(fn_m)
    if si_zero and fn_prec:
        findings.append(Finding(
            rule="timestomp_zeroed_subsecond",
            severity="medium",
            entry=rec.entry,
            path=rec.full_path,
            detail=(
                "$SI timestamps have zeroed sub-second precision while $FN "
                "retains it — signature of SetFileTime-based timestomping."
            ),
            evidence={
                "si_created": _ts_str(si_c),
                "si_modified": _ts_str(si_m),
                "fn_created": _ts_str(fn_c),
                "fn_modified": _ts_str(fn_m),
            },
        ))
    return findings


def _check_location(rec: MftRecord) -> list:
    findings = []
    if rec.is_directory:
        return findings
    path = rec.full_path
    if rec.ext_lower in _EXEC_EXTS:
        for pat in _SUSPICIOUS_DIR_PATTERNS:
            if pat.search(path):
                findings.append(Finding(
                    rule="executable_in_suspicious_dir",
                    severity="medium",
                    entry=rec.entry,
                    path=path,
                    detail=(
                        f"Executable/script ({rec.ext_lower}) located in a "
                        f"common staging/drop directory."
                    ),
                    evidence={"extension": rec.ext_lower},
                ))
                break
    return findings


def _check_masquerade(rec: MftRecord) -> list:
    findings = []
    if rec.is_directory or not rec.name:
        return findings
    name = rec.name
    # Double extension where a benign-looking ext is followed by an exec ext.
    parts = [p for p in name.split(".") if p]
    if len(parts) >= 3:
        final_ext = "." + parts[-1].lower()
        mid_ext = "." + parts[-2].lower()
        if final_ext in _EXEC_EXTS and mid_ext in _BENIGN_LOOKING:
            findings.append(Finding(
                rule="double_extension_masquerade",
                severity="high",
                entry=rec.entry,
                path=rec.full_path,
                detail=(
                    f"Double extension '{mid_ext}{final_ext}' — executable "
                    f"disguised as a {mid_ext} document."
                ),
                evidence={"name": name},
            ))
    # Right-to-left override character used to spoof extensions.
    if "‮" in name:
        findings.append(Finding(
            rule="rtlo_filename",
            severity="critical",
            entry=rec.entry,
            path=rec.full_path,
            detail="Filename contains a right-to-left override (U+202E) used to spoof its extension.",
            evidence={"name": name.replace("‮", "<RTLO>")},
        ))
    return findings


def analyze(records: Iterable) -> AnalysisResult:
    result = AnalysisResult()
    for rec in records:
        result.total_records += 1
        result.analyzed_records += 1
        for fn in (_check_timestomp, _check_location, _check_masquerade):
            for finding in fn(rec):
                result.findings.append(finding)
                result.counts[finding.severity] = result.counts.get(finding.severity, 0) + 1
    result.findings.sort(
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.entry if f.entry is not None else 1 << 30)
    )
    return result


# ----------------------------------------------------------------------------
# Renderers
# ----------------------------------------------------------------------------
_SEV_LABELS = ["critical", "high", "medium", "low", "info"]


def _summary_line(result: AnalysisResult) -> str:
    parts = [f"{s}={result.counts.get(s, 0)}" for s in _SEV_LABELS if result.counts.get(s)]
    sev = ", ".join(parts) if parts else "none"
    return (f"Records: {result.analyzed_records}/{result.total_records}  "
            f"Findings: {len(result.findings)}  ({sev})")


def render_table(result: AnalysisResult) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append("MFTPARSE — $MFT Forensic Analysis")
    lines.append("=" * 78)
    lines.append(_summary_line(result))
    lines.append("-" * 78)
    if not result.findings:
        lines.append("No suspicious activity detected.")
        return "\n".join(lines)
    hdr = f"{'SEV':<8} {'ENTRY':>7}  {'RULE':<32} PATH"
    lines.append(hdr)
    lines.append("-" * 78)
    for f in result.findings:
        entry = "" if f.entry is None else str(f.entry)
        lines.append(f"{f.severity.upper():<8} {entry:>7}  {f.rule:<32} {f.path}")
        lines.append(f"         {f.detail}")
    lines.append("-" * 78)
    lines.append(_summary_line(result))
    return "\n".join(lines)


def render_json(result: AnalysisResult) -> str:
    payload = {
        "tool": "mftparse",
        "summary": {
            "total_records": result.total_records,
            "analyzed_records": result.analyzed_records,
            "finding_count": len(result.findings),
            "severity_counts": result.counts,
        },
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2)


_SEV_COLORS = {
    "critical": "#7e1416",
    "high": "#c0392b",
    "medium": "#d68910",
    "low": "#2980b9",
    "info": "#566573",
}


def render_html(result: AnalysisResult) -> str:
    def esc(s):
        return _html.escape(str(s)) if s is not None else ""

    generated = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_cards = []
    for s in _SEV_LABELS:
        c = result.counts.get(s, 0)
        sev_cards.append(
            f'<div class="card" style="border-top:4px solid {_SEV_COLORS[s]}">'
            f'<div class="num">{c}</div><div class="lbl">{s.upper()}</div></div>'
        )
    rows = []
    for f in result.findings:
        color = _SEV_COLORS.get(f.severity, "#566573")
        ev = "; ".join(f"{esc(k)}={esc(v)}" for k, v in f.evidence.items())
        rows.append(
            "<tr>"
            f'<td><span class="badge" style="background:{color}">{esc(f.severity.upper())}</span></td>'
            f"<td>{esc('' if f.entry is None else f.entry)}</td>"
            f"<td><code>{esc(f.rule)}</code></td>"
            f"<td class=\"path\">{esc(f.path)}</td>"
            f"<td>{esc(f.detail)}<div class=\"ev\">{ev}</div></td>"
            "</tr>"
        )
    body_rows = "\n".join(rows) if rows else (
        '<tr><td colspan="5" class="none">No suspicious activity detected.</td></tr>'
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MFTPARSE Report</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
         background: #f4f6f8; color: #1c2833; }}
  header {{ background: #1c2833; color: #fff; padding: 24px 32px; }}
  header h1 {{ margin: 0; font-size: 22px; }}
  header .meta {{ color: #aeb6bf; font-size: 13px; margin-top: 6px; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 24px 32px; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{ background: #fff; border-radius: 8px; padding: 16px 22px; min-width: 110px;
          box-shadow: 0 1px 3px rgba(0,0,0,.1); text-align: center; }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card .lbl {{ font-size: 11px; letter-spacing: 1px; color: #566573; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
          border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  th, td {{ text-align: left; padding: 10px 14px; font-size: 13px;
           border-bottom: 1px solid # eee; vertical-align: top; }}
  th {{ background: #eaecee; font-size: 11px; letter-spacing: .5px; text-transform: uppercase; }}
  tr:hover td {{ background: #fbfcfd; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 11px;
           font-weight: 700; white-space: nowrap; }}
  code {{ background: #eef1f3; padding: 1px 5px; border-radius: 3px; font-size: 12px; }}
  .path {{ font-family: Consolas, monospace; font-size: 12px; word-break: break-all; }}
  .ev {{ color: #7f8c8d; font-size: 11px; margin-top: 4px; font-family: Consolas, monospace; }}
  .none {{ text-align: center; color: #27ae60; padding: 24px; font-weight: 600; }}
</style></head><body>
<header>
  <h1>MFTPARSE — $MFT Forensic Analysis</h1>
  <div class="meta">Generated {esc(generated)} &middot; {result.analyzed_records}/{result.total_records} records analyzed &middot; {len(result.findings)} findings</div>
</header>
<div class="wrap">
  <div class="cards">{''.join(sev_cards)}</div>
  <table>
    <thead><tr><th>Severity</th><th>Entry</th><th>Rule</th><th>Path</th><th>Detail</th></tr></thead>
    <tbody>
{body_rows}
    </tbody>
  </table>
</div>
</body></html>
"""
