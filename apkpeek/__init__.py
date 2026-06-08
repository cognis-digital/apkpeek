"""apkpeek — MobSF-style Android static-analysis engine (stdlib only).

Part of the Cognis Neural Suite. Public API + identity are re-exported
from ``apkpeek.core``.
"""
from apkpeek.core import (  # noqa: F401
    TOOL_NAME,
    TOOL_VERSION,
    Finding,
    SEVERITY_ORDER,
    PERMISSION_DB,
    parse_axml,
    extract_metadata,
    analyze_manifest,
    analyze_network_security_config,
    scan_secrets,
    scan_apk,
    compute_score,
    to_sarif,
)

__version__ = TOOL_VERSION
__all__ = [
    "TOOL_NAME", "TOOL_VERSION", "Finding", "SEVERITY_ORDER", "PERMISSION_DB",
    "parse_axml", "extract_metadata", "analyze_manifest",
    "analyze_network_security_config", "scan_secrets", "scan_apk",
    "compute_score", "to_sarif",
]
