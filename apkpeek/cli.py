"""Command-line interface for APKPEEK.

Subcommands:
    scan      Full static triage of an APK (manifest + NSC + secrets + score).
    manifest  Decode/print AndroidManifest.xml and show metadata only.
    rules     List the bundled detection rules / permission database.
    version   Print tool name + version.

Examples:
    apkpeek scan app.apk
    apkpeek scan app.apk --format json | jq '.security_score'
    apkpeek scan app.apk --format sarif -o results.sarif
    apkpeek scan app.apk --fail-on high
    apkpeek manifest app.apk
    apkpeek rules

Exit codes:
    0  ran, no findings at/above the --fail-on threshold
    1  findings at/above the threshold were detected
    2  usage / runtime error (bad path, etc.)
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    scan_apk, to_sarif, extract_metadata, _decode_xml_blob,
    SEVERITY_ORDER, PERMISSION_DB, _SECRET_PATTERNS,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Static triage of Android APKs (MobSF-style): exported components, "
        "dangerous permissions, insecure flags, network-security-config, secrets, "
        "and a 0-100 security score. Outputs table / JSON / SARIF.",
        epilog="Example: apkpeek scan app.apk --format sarif -o out.sarif --fail-on high",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Full scan of an APK (or AndroidManifest.xml).")
    s.add_argument("apk", help="Path to .apk (or a plain/binary AndroidManifest.xml).")
    s.add_argument("--format", choices=["table", "json", "sarif"], default="table",
                   help="Output format (default: table).")
    s.add_argument("-o", "--output", help="Write output to this file instead of stdout.")
    s.add_argument("--fail-on", choices=list(SEVERITY_ORDER.keys()), default="high",
                   help="Exit non-zero if any finding is at/above this severity (default: high).")
    s.add_argument("--no-secrets", action="store_true",
                   help="Skip scanning bundled files for hard-coded secrets.")

    m = sub.add_parser("manifest", help="Decode the manifest and print metadata only.")
    m.add_argument("apk", help="Path to .apk (or AndroidManifest.xml).")
    m.add_argument("--format", choices=["table", "json"], default="table")
    m.add_argument("--xml", action="store_true", help="Also print the decoded XML.")

    r = sub.add_parser("rules", help="List bundled detection rules and permission DB.")
    r.add_argument("--format", choices=["table", "json"], default="table")

    sub.add_parser("version", help="Print tool name and version.")
    return p


def _render_table(report: dict) -> str:
    lines: List[str] = []
    lines.append(f"APKPEEK {TOOL_VERSION} — scan: {report['target']}")
    meta = report.get("metadata") or {}
    if meta.get("package"):
        lines.append(f"  package: {meta['package']}  version: {meta.get('version_name') or '?'} "
                     f"(code {meta.get('version_code')})")
        lines.append(f"  sdk: min={meta.get('min_sdk')} target={meta.get('target_sdk')} "
                     f"max={meta.get('max_sdk')}")
        comps = meta.get("components", {})
        lines.append("  components: " + ", ".join(f"{k}={v}" for k, v in comps.items()))
        lines.append(f"  permissions requested: {len(meta.get('permissions', []))}")
    if not report["manifest_present"]:
        lines.append("  (no AndroidManifest.xml found)")
    lines.append(f"  SECURITY SCORE: {report.get('security_score')}/100  (grade {report.get('grade')})")
    lines.append("")

    findings = report["findings"]
    if not findings:
        lines.append("  No findings.")
    else:
        sev_w = max(len(f["severity"]) for f in findings)
        rule_w = max(len(f["rule_id"]) for f in findings)
        for f in findings:
            lines.append(f"  [{f['severity'].upper():<{sev_w}}] {f['rule_id']:<{rule_w}}  {f['message']}")
            tags = []
            if f.get("cwe"):
                tags.append(f["cwe"])
            if f.get("masvs"):
                tags.append(f["masvs"])
            loc = f.get("location") or ""
            tail = "  ".join(t for t in [loc, "  ".join(tags)] if t)
            if tail:
                lines.append(f"           - {tail}")
    s = report["summary"]
    lines.append("")
    lines.append("Summary: " + "  ".join(
        f"{k}={s.get(k, 0)}" for k in ["critical", "high", "medium", "low", "info"]))
    return "\n".join(lines)


def _render_manifest_table(meta: dict) -> str:
    lines = ["APKPEEK manifest metadata"]
    lines.append(f"  package:       {meta.get('package')}")
    lines.append(f"  app_label:     {meta.get('app_label')}")
    lines.append(f"  version_name:  {meta.get('version_name')}")
    lines.append(f"  version_code:  {meta.get('version_code')}")
    lines.append(f"  min_sdk:       {meta.get('min_sdk')}")
    lines.append(f"  target_sdk:    {meta.get('target_sdk')}")
    lines.append(f"  max_sdk:       {meta.get('max_sdk')}")
    comps = meta.get("components", {})
    lines.append("  components:    " + ", ".join(f"{k}={v}" for k, v in comps.items()))
    perms = meta.get("permissions", [])
    lines.append(f"  permissions ({len(perms)}):")
    for p in perms:
        lines.append(f"    - {p}")
    cperms = meta.get("custom_permissions", [])
    if cperms:
        lines.append(f"  custom_permissions ({len(cperms)}):")
        for cp in cperms:
            lines.append(f"    - {cp['name']} [protectionLevel={cp['protectionLevel']}]")
    return "\n".join(lines)


def _load_meta(path: str) -> dict:
    import zipfile
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            if "AndroidManifest.xml" not in z.namelist():
                return {}
            xml = _decode_xml_blob(z.read("AndroidManifest.xml"))
    else:
        with open(path, "rb") as fh:
            xml = _decode_xml_blob(fh.read())
    meta = extract_metadata(xml)
    meta["_xml"] = xml
    return meta


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"{TOOL_NAME} {TOOL_VERSION}")
        return 0

    if args.command == "rules":
        if args.format == "json":
            print(json.dumps({
                "permissions": {k: {"severity": v[0], "description": v[1]}
                                for k, v in PERMISSION_DB.items()},
                "secret_rules": [{"id": r[0], "severity": r[1], "label": r[3]}
                                 for r in _SECRET_PATTERNS],
            }, indent=2))
        else:
            print(f"APKPEEK bundled rules — {len(PERMISSION_DB)} permissions, "
                  f"{len(_SECRET_PATTERNS)} secret patterns\n")
            print("Permission database:")
            for name, (sev, desc) in PERMISSION_DB.items():
                print(f"  [{sev.upper():<8}] {name}\n             {desc}")
            print("\nSecret patterns:")
            for rid, sev, _rx, label in _SECRET_PATTERNS:
                print(f"  [{sev.upper():<8}] {rid:<18} {label}")
        return 0

    if args.command == "manifest":
        try:
            meta = _load_meta(args.apk)
        except FileNotFoundError:
            print(f"error: file not found: {args.apk}", file=sys.stderr)
            return 2
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if not meta:
            print("error: no AndroidManifest.xml found", file=sys.stderr)
            return 2
        xml = meta.pop("_xml", "")
        if args.format == "json":
            print(json.dumps(meta, indent=2))
        else:
            print(_render_manifest_table(meta))
            if args.xml:
                print("\n--- decoded AndroidManifest.xml ---")
                print(xml)
        return 0

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
        worst = max((SEVERITY_ORDER.get(f["severity"], 0) for f in report["findings"]), default=-1)
        return 1 if worst >= threshold else 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
