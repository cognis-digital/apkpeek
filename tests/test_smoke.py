"""Smoke tests for APKPEEK. No network; builds a real APK (zip) in a tmp dir."""
import json
import os
import struct
import zipfile

import pytest

from apkpeek import (
    analyze,
    analyze_apk,
    decode_binary_axml_full,
    is_binary_axml,
    parse_manifest_text,
    Engine,
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
        # Place secrets in res/raw/ so analyze_apk scans them
        z.writestr("res/raw/config.json", SECRET_JSON)
        z.writestr("classes.dex", b"\x00dexbinary")
    return path


def test_metadata():
    assert TOOL_NAME == "apkpeek"
    assert TOOL_VERSION.count(".") == 2


def test_manifest_analysis_flags_core_issues():
    m = parse_manifest_text(MANIFEST_TEXT)
    engine = Engine()
    findings = engine.analyze_manifest(m)
    ids = {f.id for f in findings}
    # debuggable=true → flag-debuggable
    assert "flag-debuggable" in ids
    # allowBackup=true → flag-allowbackup
    assert "flag-allowbackup" in ids
    # usesCleartextTraffic=true → cleartext-explicit
    assert "cleartext-explicit" in ids
    # exported components present → exported-component
    assert "exported-component" in ids
    # dangerous/high-risk permissions → perm-dangerous or perm-high-risk
    assert ids & {"perm-dangerous", "perm-high-risk", "perm-signature"}


def test_exported_provider_is_critical_and_guarded_service_is_medium():
    m = parse_manifest_text(MANIFEST_TEXT)
    engine = Engine()
    findings = engine.analyze_manifest(m)
    # Unprotected exported provider → critical
    provider = [f for f in findings
                if f.id == "exported-component" and f.where == "<provider>"]
    assert provider and provider[0].severity == "critical"
    # Exported service with a permission guard → medium (downgraded from high)
    service = [f for f in findings
               if f.id == "exported-component" and f.where == "<service>"]
    assert service and service[0].severity == "medium"
    # The android:exported=false activity must NOT be flagged.
    names = [f.title for f in findings if f.id == "exported-component"]
    assert not any("PrivateActivity" in n for n in names)


def test_secret_scanner_detects_keys():
    engine = Engine()
    findings = engine.scan_secrets(SECRET_JSON, "config.json")
    ids = {f.id for f in findings}
    # AWS access key pattern: rule id is "secret-aws-access-key"
    assert "secret-aws-access-key" in ids
    # Google API key pattern: rule id is "secret-google-api-key"
    assert "secret-google-api-key" in ids
    # Secrets must be redacted, never echoed in full.
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.title
        assert "AKIAIOSFODNN7EXAMPLE" not in f.detail


def test_scan_apk_end_to_end(tmp_path):
    apk = _build_apk(str(tmp_path / "app.apk"))
    report = analyze(apk)
    d = report.as_dict()
    # manifest was present and parsed
    assert report.manifest.package == "com.example.vulnerable"
    ids = {f["id"] for f in d["findings"]}
    assert "flag-debuggable" in ids
    assert "secret-aws-access-key" in ids  # found inside assets/config.json
    assert d["summary"]["critical"] >= 1


def test_no_secrets_flag(tmp_path):
    apk = _build_apk(str(tmp_path / "app.apk"))
    report = analyze_apk(apk, scan_dex=False)
    d = report.as_dict()
    ids = {f["id"] for f in d["findings"]}
    assert not any(i.startswith("secret-") for i in ids)


def test_report_dict_shape(tmp_path):
    """Report.as_dict() returns the expected top-level keys and shapes."""
    apk = _build_apk(str(tmp_path / "app.apk"))
    report = analyze(apk)
    d = report.as_dict()
    assert d["tool"] == "apkpeek"
    assert isinstance(d["findings"], list)
    assert isinstance(d["summary"], dict)
    assert "total" in d["summary"]
    for f in d["findings"]:
        assert "id" in f
        assert "severity" in f
        assert f["severity"] in ("critical", "high", "medium", "low", "info")


def test_parse_axml_roundtrip_minimal():
    """Build a tiny valid AXML blob and confirm the decoder reads it back."""
    blob = _make_axml("manifest", [("package", "com.t")])
    assert is_binary_axml(blob)
    elements = decode_binary_axml_full(blob)
    names = [e.name for e in elements]
    assert "manifest" in names
    elem = elements[0]
    assert elem.attrs.get("package") == "com.t"


def test_parse_axml_rejects_non_axml():
    """Plain-text XML is not binary AXML."""
    text_bytes = b"<?xml version='1.0'?><manifest/>"
    assert not is_binary_axml(text_bytes)
    # decode_binary_axml_full should raise on non-AXML input
    with pytest.raises((ValueError, Exception)):
        decode_binary_axml_full(text_bytes)


def test_cli_json_and_exit_codes(tmp_path, capsys):
    apk = _build_apk(str(tmp_path / "app.apk"))
    rc = main(["scan", apk, "--format", "json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "findings" in data and data["summary"]["total"] > 0
    # exit 2 because there are findings
    assert rc == 2
    # Using --min-severity critical on demo manifest: debuggable=true → critical,
    # so still exits 2.  Use a clean manifest (no findings) for exit 0.
    clean_mf = str(tmp_path / "clean.xml")
    with open(clean_mf, "w", encoding="utf-8") as fh:
        fh.write(
            '<?xml version="1.0"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
            ' package="com.example.clean">\n'
            '  <uses-sdk android:targetSdkVersion="34" />\n'
            '  <application android:allowBackup="false">\n'
            '    <activity android:name=".Main" android:exported="false" />\n'
            '  </application>\n'
            '</manifest>\n'
        )
    rc2 = main(["scan", clean_mf, "--format", "json"])
    capsys.readouterr()
    assert rc2 == 0  # no findings in a clean manifest


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
    start_body = struct.pack("<iiHHHHHH", 0, idx[tag], 20, len(attrs), 0, 0, 0, 0)
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
