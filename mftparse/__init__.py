"""MFTPARSE — NTFS $MFT CSV forensic analyzer.

Defensive forensics: detect timestomping and suspicious file activity in an
NTFS Master File Table export (CSV). Standard library only, zero install.
"""
from .core import (
    MftRecord,
    Finding,
    AnalysisResult,
    parse_mft_csv,
    analyze,
    render_table,
    render_json,
    render_html,
)

TOOL_NAME = "mftparse"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "MftRecord",
    "Finding",
    "AnalysisResult",
    "parse_mft_csv",
    "analyze",
    "render_table",
    "render_json",
    "render_html",
]
