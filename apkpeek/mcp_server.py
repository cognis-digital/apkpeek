"""APKPEEK MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from apkpeek.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-apkpeek[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-apkpeek[mcp]'")
        return 1
    app = FastMCP("apkpeek")

    @app.tool()
    def apkpeek_scan(target: str) -> str:
        """One-command static triage of Android APK/AAB binaries: surfaces hardcoded secrets, exported components, dangerous permissions, and insecure manifest flags as a single SARIF report.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
