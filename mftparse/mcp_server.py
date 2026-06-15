"""MFTPARSE MCP server — exposes analyze() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import sys

from mftparse.core import analyze, parse_mft_csv, render_json


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-mftparse[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print(
            "Install the MCP extra: pip install 'cognis-mftparse[mcp]'",
            file=sys.stderr,
        )
        return 1
    app = FastMCP("mftparse")

    @app.tool()
    def mftparse_scan(csv_text: str) -> str:
        """Analyze an NTFS $MFT CSV export for timestomping and suspicious
        file activity. Pass the full CSV text; returns JSON findings."""
        try:
            records = parse_mft_csv(csv_text)
            result = analyze(records)
            return render_json(result)
        except Exception as exc:  # pragma: no cover
            return render_json(
                type("_Err", (), {
                    "findings": [],
                    "total_records": 0,
                    "analyzed_records": 0,
                    "counts": {},
                    "has_findings": False,
                    "_error": str(exc),
                })()
            )

    app.run()
    return 0
