"""APKPEEK command-line interface.

Subcommands:
  scan         - full static analysis of an .apk / AndroidManifest.xml
  manifest     - decode + dump the manifest (package, sdk, flags, components)
  permissions  - list requested permissions with protection levels
  secrets      - scan only for hard-coded secret strings
  perms-db     - list the bundled permission catalog
  rules        - list the bundled secret-string rule pack

Global flags: --version, --format {table,json}

Exit codes:
  0  success, no findings
  1  usage / runtime error
  2  findings present (or secrets found)
"""

from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    PERMISSION_CATALOG,
    SECRET_RULES,
    SEVERITY_ORDER,
    Engine,
    Finding,
    _strip_android_prefix,
    analyze,
    analyze_manifest_file,
    sort_findings,
    summarize,
)

EXIT_OK = 0
EXIT_ERR = 1
EXIT_FINDINGS = 2


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------
def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _table(rows: list[list[str]], headers: list[str]) -> str:
    if not rows:
        return "  ".join(headers) + "\n(no rows)"
    cols = list(zip(*([headers] + rows)))
    widths = [max(len(str(c)) for c in col) for col in cols]
    line = "  ".join(str(h).ljust(w) for h, w in zip(headers, widths))
    out = [line, "  ".join("-" * w for w in widths)]
    for r in rows:
        out.append("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))
    return "\n".join(out)


def _render_findings(findings: list[Finding], fmt: str) -> None:
    findings = sort_findings(findings)
    if fmt == "json":
        _print_json({"findings": [f.as_dict() for f in findings],
                     "summary": summarize(findings)})
        return
    if not findings:
        print("No findings.")
        return
    rows = [[f.severity.upper(), f.id, f.where, f.title] for f in findings]
    print(_table(rows, ["SEVERITY", "RULE", "WHERE", "TITLE"]))
    s = summarize(findings)
    print("\n" + "  ".join(
        f"{k}={s[k]}" for k in ("critical", "high", "medium", "low", "info")
        if s.get(k)))
    print(f"total={s['total']}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def _cmd_scan(args) -> int:
    try:
        report = analyze(args.target, scan_dex=not args.no_dex,
                         entropy=args.entropy)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERR
    findings = report.findings
    if args.min_severity:
        thr = SEVERITY_ORDER[args.min_severity]
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= thr]
    if args.format == "json":
        d = report.as_dict()
        d["findings"] = [f.as_dict() for f in findings]
        d["summary"] = summarize(findings)
        _print_json(d)
    else:
        print(f"# {TOOL_NAME} {TOOL_VERSION} - {report.target}")
        print(f"package={report.manifest.package or '(unknown)'} "
              f"minSdk={report.manifest.min_sdk} "
              f"targetSdk={report.manifest.target_sdk} "
              f"debuggable={report.manifest.debuggable} "
              f"allowBackup={report.manifest.allow_backup}\n")
        _render_findings(findings, "table")
    return EXIT_FINDINGS if findings else EXIT_OK


def _cmd_manifest(args) -> int:
    try:
        report = analyze_manifest_file(args.target, entropy=args.entropy) \
            if not _is_zip(args.target) else analyze(args.target)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERR
    m = report.manifest
    if args.format == "json":
        d = report.as_dict()
        d.pop("findings", None)
        _print_json(d)
        return EXIT_OK
    print(f"package      : {m.package or '(unknown)'}")
    print(f"minSdk       : {m.min_sdk}")
    print(f"targetSdk    : {m.target_sdk}")
    print(f"debuggable   : {m.debuggable}")
    print(f"allowBackup  : {m.allow_backup}")
    print(f"cleartext    : {m.uses_cleartext_traffic}")
    print(f"netSecConfig : {m.network_security_config}")
    print(f"permissions  : {len(set(m.permissions))}")
    print()
    rows = [[c.kind, c.name or "(unnamed)", "yes" if c.exported else "no",
             "yes" if c.has_intent_filter else "no", c.permission or "-"]
            for c in m.components]
    print(_table(rows, ["KIND", "NAME", "EXPORTED", "INTENT-FILTER", "PERMISSION"]))
    return EXIT_OK


def _cmd_permissions(args) -> int:
    try:
        report = analyze(args.target)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERR
    perms = sorted(set(report.manifest.permissions))
    rows = []
    risky = 0
    for p in perms:
        short = _strip_android_prefix(p)
        meta = PERMISSION_CATALOG.get(short, {"level": "normal/unknown",
                                              "group": "-"})
        if meta["level"] in ("dangerous", "signature"):
            risky += 1
        rows.append([short, meta["level"], meta["group"], p])
    if args.format == "json":
        _print_json({"package": report.manifest.package,
                     "permissions": [
                         {"name": r[3], "short": r[0], "level": r[1],
                          "group": r[2]} for r in rows],
                     "risky": risky})
        return EXIT_FINDINGS if risky else EXIT_OK
    print(_table(rows, ["PERMISSION", "LEVEL", "GROUP", "FULL"]))
    print(f"\nrisky (dangerous/signature) = {risky} / {len(rows)}")
    return EXIT_FINDINGS if risky else EXIT_OK


def _cmd_secrets(args) -> int:
    engine = Engine(secret_entropy_threshold=args.entropy)
    findings: list[Finding] = []
    try:
        import zipfile
        if zipfile.is_zipfile(args.target):
            with zipfile.ZipFile(args.target) as zf:
                for n in zf.namelist():
                    findings += engine.scan_blob_secrets(zf.read(n), n)
        else:
            with open(args.target, "rb") as fh:
                findings += engine.scan_blob_secrets(fh.read(), args.target)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERR
    _render_findings(findings, args.format)
    return EXIT_FINDINGS if findings else EXIT_OK


def _cmd_perms_db(args) -> int:
    rows = [[k, v["level"], v["group"]]
            for k, v in sorted(PERMISSION_CATALOG.items())]
    if args.format == "json":
        _print_json({"permissions": [
            {"name": r[0], "level": r[1], "group": r[2]} for r in rows]})
        return EXIT_OK
    print(_table(rows, ["PERMISSION", "LEVEL", "GROUP"]))
    print(f"\n{len(rows)} permissions in catalog")
    return EXIT_OK


def _cmd_rules(args) -> int:
    rows = [[r.id, r.severity, r.description] for r in SECRET_RULES]
    if args.format == "json":
        _print_json({"rules": [
            {"id": r.id, "severity": r.severity, "description": r.description}
            for r in SECRET_RULES]})
        return EXIT_OK
    print(_table(rows, ["ID", "SEVERITY", "DESCRIPTION"]))
    print(f"\n{len(rows)} secret rules")
    return EXIT_OK


def _is_zip(path: str) -> bool:
    import zipfile
    try:
        return zipfile.is_zipfile(path)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    fmt_parent = argparse.ArgumentParser(add_help=False)
    fmt_parent.add_argument("--format", choices=["table", "json"],
                            default="table", help="output format")

    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="APKPEEK - static Android APK / manifest security analyzer "
                    "(MobSF-style, zero install).")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    def add_target(parser, entropy=True):
        parser.add_argument("target",
                            help=".apk file or AndroidManifest.xml (binary/text)")
        if entropy:
            parser.add_argument("--entropy", type=float, default=4.0,
                                help="min Shannon entropy for heuristic secrets")

    sc = sub.add_parser("scan", parents=[fmt_parent],
                        help="full static analysis of an apk/manifest")
    add_target(sc)
    sc.add_argument("--no-dex", action="store_true",
                    help="skip scanning DEX/resources for secrets")
    sc.add_argument("--min-severity", choices=list(SEVERITY_ORDER),
                    help="only report findings at this severity or worse")
    sc.set_defaults(func=_cmd_scan)

    mf = sub.add_parser("manifest", parents=[fmt_parent],
                        help="decode and dump the manifest")
    add_target(mf)
    mf.set_defaults(func=_cmd_manifest)

    pm = sub.add_parser("permissions", parents=[fmt_parent],
                        help="list requested permissions + protection levels")
    add_target(pm, entropy=False)
    pm.set_defaults(func=_cmd_permissions)

    se = sub.add_parser("secrets", parents=[fmt_parent],
                        help="scan only for hard-coded secret strings")
    add_target(se)
    se.set_defaults(func=_cmd_secrets)

    pd = sub.add_parser("perms-db", parents=[fmt_parent],
                        help="list the bundled permission catalog")
    pd.set_defaults(func=_cmd_perms_db)

    rl = sub.add_parser("rules", parents=[fmt_parent],
                        help="list the bundled secret-string rules")
    rl.set_defaults(func=_cmd_rules)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_OK
    if not hasattr(args, "format"):
        args.format = "table"
    # Validate --entropy range before dispatching.
    if hasattr(args, "entropy"):
        if not (0.0 <= args.entropy <= 8.0):
            print(
                f"error: --entropy {args.entropy} is out of range; "
                "valid range is 0.0 to 8.0",
                file=sys.stderr,
            )
            return EXIT_ERR
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_ERR
    except Exception as exc:  # noqa: BLE001
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return EXIT_ERR


if __name__ == "__main__":
    sys.exit(main())
