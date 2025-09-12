"""MFTPARSE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from mftparse.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-mftparse[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-mftparse[mcp]'")
        return 1
    app = FastMCP("mftparse")

    @app.tool()
    def mftparse_scan(target: str) -> str:
        """Analyze an NTFS $MFT CSV for timestomping and suspicious file activity. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
