"""Smoke tests for APKPEEK. No network; builds a real APK (zip) in a tmp dir."""
import io
import json
import os
import struct
import zipfile

import pytest

from apkpeek import (
    scan_apk,
    analyze_manifest,
    scan_secrets,
    to_sarif,
    parse_axml,
    TOOL_NAME,
    TOOL_VERSION,
)
from apkpeek.cli import main

DEMO_MANIFEST = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "demos", "01-basic", "sample_manifest.xml"
)

MANIFEST_TEXT = open(DEMO_MANIFEST, encoding="utf-8").read() if os.path.exists(DEMO_MANIFEST) else ""

SECRET_JSON = json.dumps(
    {
        "aws_key": "AKIAIOSFODNN7EXAMPLE",
        "google": "AIzaEXAMPLE0EXAMPLE0EXAMPLE0EXAMPLE0EXA",
        "note": "do not commit",
    }
)


def _build_apk(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", MANIFEST_TEXT)
        z.writestr("assets/config.json", SECRET_JSON)
        z.writestr("classes.dex", b"\x00dexbinary")
    return path


def test_metadata():
    assert TOOL_NAME == "apkpeek"
    assert TOOL_VERSION.count(".") == 2


def test_manifest_analysis_flags_core_issues():
    findings = analyze_manifest(MANIFEST_TEXT)
    rule_ids = {f.rule_id for f in findings}
    assert "APK-DEBUG" in rule_ids
    assert "APK-BACKUP" in rule_ids
    assert "APK-CLEARTEXT" in rule_ids
    assert "APK-EXPORT" in rule_ids
    assert "APK-PERM" in rule_ids


def test_exported_provider_is_high_and_guarded_service_is_low():
    findings = analyze_manifest(MANIFEST_TEXT)
    provider = [f for f in findings if f.rule_id == "APK-EXPORT" and f.detail.get("type") == "provider"]
    assert provider and provider[0].severity == "high"
    # The service is exported but permission-guarded -> downgraded to low.
    svc = [f for f in findings if f.rule_id == "APK-EXPORT" and f.detail.get("type") == "service"]
    assert svc and svc[0].severity == "low"
    # The android:exported=false activity must NOT be flagged.
    names = [f.detail.get("component", "") for f in findings if f.rule_id == "APK-EXPORT"]
    assert not any("PrivateActivity" in n for n in names)


def test_secret_scanner_detects_keys():
    findings = scan_secrets("config.json", SECRET_JSON.encode())
    ids = {f.rule_id for f in findings}
    assert "SEC-AWS-AKID" in ids
    assert "SEC-GOOGLE-API" in ids
    # Secrets must be redacted, never echoed in full.
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.message


def test_scan_apk_end_to_end(tmp_path):
    apk = _build_apk(str(tmp_path / "app.apk"))
    report = scan_apk(apk)
    assert report["manifest_present"] is True
    ids = {f["rule_id"] for f in report["findings"]}
    assert "APK-DEBUG" in ids
    assert "SEC-AWS-AKID" in ids  # found inside assets/config.json
    assert report["summary"]["high"] >= 1


def test_no_secrets_flag(tmp_path):
    apk = _build_apk(str(tmp_path / "app.apk"))
    report = scan_apk(apk, scan_secrets_in_files=False)
    ids = {f["rule_id"] for f in report["findings"]}
    assert not any(i.startswith("SEC-") for i in ids)


def test_sarif_shape():
    report = scan_apk(DEMO_MANIFEST)
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "apkpeek"
    assert len(run["results"]) == len(report["findings"])
    for r in run["results"]:
        assert r["level"] in ("note", "warning", "error")


def test_parse_axml_roundtrip_minimal():
    """Build a tiny valid AXML blob and confirm the decoder reads it back."""
    blob = _make_axml("manifest", [("package", "com.t")])
    xml = parse_axml(blob)
    assert "manifest" in xml
    assert "com.t" in xml


def test_parse_axml_rejects_text():
    with pytest.raises(ValueError):
        parse_axml(b"<?xml version='1.0'?><manifest/>")


def test_cli_json_and_exit_codes(tmp_path, capsys):
    apk = _build_apk(str(tmp_path / "app.apk"))
    rc = main(["scan", apk, "--format", "json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "findings" in data and data["summary"]["high"] >= 1
    # default --fail-on high -> exit 1 because we have high findings.
    assert rc == 1
    # lenient threshold: critical only. Demo has no critical manifest finding,
    # but the bundled AWS key IS critical, so on the full apk it stays 1.
    rc2 = main(["scan", DEMO_MANIFEST, "--fail-on", "critical"])
    assert rc2 == 0  # manifest-only, no critical findings


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert TOOL_VERSION in capsys.readouterr().out


# ---- helper: minimal AXML encoder for the round-trip test ----
def _make_axml(tag, attrs):
    # String pool order: [tag, attrname..., attrval...]
    strings = [tag]
    for k, v in attrs:
        if k not in strings:
            strings.append(k)
    for k, v in attrs:
        if v not in strings:
            strings.append(v)

    def enc_pool(strs):
        # UTF-16 string pool.
        offsets = []
        data = b""
        for s in strs:
            offsets.append(len(data))
            b = s.encode("utf-16-le")
            data += struct.pack("<H", len(s)) + b + b"\x00\x00"
        header = 28
        strings_start = header + 4 * len(strs)
        body = struct.pack("<" + "I" * len(offsets), *offsets) + data
        size = header + len(body)
        if size % 4:
            pad = 4 - (size % 4)
            body += b"\x00" * pad
            size += pad
        chunk = struct.pack(
            "<HHIIIIII", 0x0001, 28, size, len(strs), 0, 0, strings_start, 0
        ) + body
        return chunk

    pool = enc_pool(strings)
    idx = {s: i for i, s in enumerate(strings)}

    # Start element chunk.
    attr_blocks = b""
    for k, v in attrs:
        attr_blocks += struct.pack(
            "<iiiIi", -1, idx[k], idx[v], (0x03 << 24), idx[v]
        )
    start_hdr = struct.pack("<HHI", 0x0102, 16, 16 + 20 + len(attr_blocks))
    start_body = struct.pack(
        "<iiHHHHHH", 0, idx[tag], 20, len(attrs), 0, 0, 0, 0
    )
    # Header above is 8 bytes; the 16-byte header includes lineNumber+comment.
    start_chunk = (
        struct.pack("<HHI", 0x0102, 16, 16 + 20 + len(attr_blocks))
        + struct.pack("<ii", 0xFFFFFFFF - 0 if False else 0, 0)  # lineNo, comment placeholder
    )
    # Build precisely per layout used by parser:
    # header(8) | lineNumber(4) | comment(4) | ns(4) name(4) | attrStart(2) attrSize(2) attrCount(2) idIndex(2) classIndex(2) styleIndex(2)
    body = (
        struct.pack("<ii", 0, -1)            # lineNumber, comment
        + struct.pack("<ii", -1, idx[tag])   # ns, name
        + struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
        + attr_blocks
    )
    size = 8 + len(body)
    start_chunk = struct.pack("<HHI", 0x0102, 16, size) + body

    end_body = struct.pack("<ii", 0, -1) + struct.pack("<ii", -1, idx[tag])
    end_chunk = struct.pack("<HHI", 0x0103, 16, 8 + len(end_body)) + end_body

    inner = pool + start_chunk + end_chunk
    total = 8 + len(inner)
    return struct.pack("<HHI", 0x0003, 8, total) + inner
