"""Command-line interface for APKPEEK.

Examples:
    # Human-readable table
    apkpeek scan app.apk

    # JSON for piping into jq / CI
    apkpeek scan app.apk --format json | jq '.summary'

    # SARIF for code-scanning dashboards (GitHub, etc.)
    apkpeek scan app.apk --format sarif -o results.sarif

    # Gate a build: fail (exit 1) if any finding >= high
    apkpeek scan app.apk --fail-on high

Exit codes:
    0  scan ran, no findings at/above the --fail-on threshold
    1  findings at/above the threshold were detected
    2  usage / runtime error (bad path, etc.)
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import scan_apk, to_sarif, SEVERITY_ORDER


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Static triage of Android APKs: secrets, exported components, "
        "dangerous permissions, insecure flags. Outputs table / JSON / SARIF.",
        epilog="Example: apkpeek scan app.apk --format sarif -o out.sarif --fail-on high",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan an APK (or AndroidManifest.xml) for issues.")
    s.add_argument("apk", help="Path to .apk file (or a plain/binary AndroidManifest.xml).")
    s.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Output format (default: table). 'sarif' emits SARIF 2.1.0.",
    )
    s.add_argument("-o", "--output", help="Write output to this file instead of stdout.")
    s.add_argument(
        "--fail-on",
        choices=list(SEVERITY_ORDER.keys()),
        default="high",
        help="Exit non-zero if any finding is at/above this severity (default: high). "
        "Use 'critical' to be lenient or 'info' to fail on anything.",
    )
    s.add_argument(
        "--no-secrets",
        action="store_true",
        help="Skip scanning bundled files for hard-coded secrets (manifest only).",
    )
    return p


def _render_table(report: dict) -> str:
    lines: List[str] = []
    lines.append(f"APKPEEK scan: {report['target']}")
    if not report["manifest_present"]:
        lines.append("  (no AndroidManifest.xml found)")
    findings = report["findings"]
    if not findings:
        lines.append("  No findings. ✓")
    else:
        sev_w = max(len(f["severity"]) for f in findings)
        rule_w = max(len(f["rule_id"]) for f in findings)
        for f in findings:
            lines.append(
                f"  [{f['severity'].upper():<{sev_w}}] {f['rule_id']:<{rule_w}}  {f['message']}"
            )
            if f.get("location"):
                lines.append(f"           └ {f['location']}")
    s = report["summary"]
    lines.append("")
    lines.append(
        "Summary: "
        + "  ".join(
            f"{k}={s.get(k, 0)}" for k in ["critical", "high", "medium", "low", "info"]
        )
    )
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            report = scan_apk(args.apk, scan_secrets_in_files=not args.no_secrets)
        except FileNotFoundError:
            print(f"error: file not found: {args.apk}", file=sys.stderr)
            return 2
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

        if args.format == "json":
            out = json.dumps(report, indent=2)
        elif args.format == "sarif":
            out = json.dumps(to_sarif(report, TOOL_NAME, TOOL_VERSION), indent=2)
        else:
            out = _render_table(report)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out + "\n")
            print(f"wrote {args.format} output to {args.output}", file=sys.stderr)
        else:
            print(out)

        threshold = SEVERITY_ORDER[args.fail_on]
        worst = max(
            (SEVERITY_ORDER.get(f["severity"], 0) for f in report["findings"]),
            default=-1,
        )
        return 1 if worst >= threshold else 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
