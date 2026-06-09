"""Deep tests for apkpeek: AXML decoding, manifest analysis, permission catalog
and secret scanning. No network. Standard library only."""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apkpeek import (  # noqa: E402
    PERMISSION_CATALOG,
    SECRET_RULES,
    TOOL_NAME,
    TOOL_VERSION,
    Engine,
    analyze,
    decode_binary_axml_full,
    parse_manifest_text,
    shannon_entropy,
)
from apkpeek.cli import main  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demos", "02-deep")
APK = os.path.join(DEMO, "leakybank.apk")
TEXT_MANIFEST = os.path.join(DEMO, "AndroidManifest.xml")


def _ensure_apk():
    if not os.path.exists(APK):
        subprocess.check_call([sys.executable,
                               os.path.join(DEMO, "build_fixture_apk.py")])


def _ids(findings):
    return {f.id for f in findings}


# --- metadata ---------------------------------------------------------------
def test_metadata():
    assert TOOL_NAME == "apkpeek"
    assert TOOL_VERSION
    assert len(SECRET_RULES) >= 15
    assert len(PERMISSION_CATALOG) >= 40


def test_rule_and_perm_integrity():
    ids = [r.id for r in SECRET_RULES]
    assert len(ids) == len(set(ids)), "duplicate secret rule ids"
    for r in SECRET_RULES:
        assert r.regex.pattern
        assert r.severity in ("critical", "high", "medium", "low", "info")
    for name, meta in PERMISSION_CATALOG.items():
        assert meta["level"] in ("dangerous", "signature", "normal")
        assert meta["group"]


# --- text-manifest analysis -------------------------------------------------
def test_text_manifest_parses():
    with open(TEXT_MANIFEST, "r", encoding="utf-8") as fh:
        m = parse_manifest_text(fh.read())
    assert m.package == "com.example.leakybank"
    assert m.target_sdk == 22
    assert m.debuggable is True
    assert m.allow_backup is True
    assert m.uses_cleartext_traffic is True
    # implicit-exported via intent-filter (receiver had no explicit exported)
    receivers = [c for c in m.components if c.kind == "receiver"]
    assert receivers and receivers[0].exported is True
    # explicit exported=false stays internal
    internal = [c for c in m.components if c.name == ".InternalSettings"]
    assert internal and internal[0].exported is False


def test_text_manifest_findings():
    report = analyze(TEXT_MANIFEST)
    ids = _ids(report.findings)
    assert "flag-debuggable" in ids
    assert "flag-allowbackup" in ids
    assert "cleartext-explicit" in ids
    assert "exported-component" in ids
    assert "perm-high-risk" in ids
    assert "secret-google-api-key" in ids
    assert "secret-aws-access-key" in ids
    # exported provider must be critical
    prov = [f for f in report.findings
            if f.id == "exported-component" and f.where == "<provider>"]
    assert prov and prov[0].severity == "critical"


# --- binary AXML decoding (the headline feature) ----------------------------
def test_binary_axml_decode():
    _ensure_apk()
    import zipfile
    data = zipfile.ZipFile(APK).read("AndroidManifest.xml")
    els = decode_binary_axml_full(data)
    names = [e.name for e in els]
    assert "manifest" in names
    assert "application" in names
    assert names.count("uses-permission") == 3
    app = [e for e in els if e.name == "application"][0]
    assert app.attrs.get("debuggable") == "true"
    assert app.attrs.get("usesCleartextTraffic") == "true"


def test_apk_full_analysis():
    _ensure_apk()
    report = analyze(APK)
    assert report.manifest.package == "com.example.leakybank"
    assert report.manifest.debuggable is True
    assert report.manifest.target_sdk == 22
    ids = _ids(report.findings)
    # manifest-derived
    assert "flag-debuggable" in ids
    assert "cleartext-explicit" in ids
    assert "exported-component" in ids
    assert "perm-high-risk" in ids       # BIND_ACCESSIBILITY_SERVICE / READ_SMS
    # DEX/resource secret-string scan
    assert "secret-github-pat" in ids
    assert "secret-stripe-secret" in ids
    assert "secret-slack-token" in ids
    assert "secret-private-key" in ids


# --- secret scanner ---------------------------------------------------------
def test_entropy_gate():
    eng = Engine(secret_entropy_threshold=4.0)
    # low-entropy generic assignment must be suppressed
    low = eng.scan_secrets('password="aaaaaaaaaaaa"', "x")
    assert not any(f.id == "secret-generic-secret" for f in low)
    # high-entropy real token is reported
    hi = eng.scan_secrets('token="aB3xQ9zK2mP7wL5nR1tY"', "x")
    assert any(f.id == "secret-generic-secret" for f in hi)


def test_shannon_entropy_monotonic():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("aB3xQ9zK")
    assert shannon_entropy("") == 0.0


# --- CLI contract -----------------------------------------------------------
def test_cli_scan_exit_code_and_json(capsys):
    _ensure_apk()
    rc = main(["scan", APK, "--format", "json"])
    assert rc == 2  # findings present -> non-zero
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["tool"] == "apkpeek"
    assert doc["package"] == "com.example.leakybank"
    assert doc["summary"]["total"] > 0
    assert isinstance(doc["findings"], list)


def test_cli_permissions_json(capsys):
    rc = main(["permissions", TEXT_MANIFEST, "--format", "json"])
    assert rc == 2  # risky perms present
    doc = json.loads(capsys.readouterr().out)
    levels = {p["level"] for p in doc["permissions"]}
    assert "signature" in levels or "dangerous" in levels


def test_cli_rules_and_perms_db(capsys):
    assert main(["rules", "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert len(doc["rules"]) == len(SECRET_RULES)
    assert main(["perms-db", "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert len(doc["permissions"]) == len(PERMISSION_CATALOG)


def test_cli_clean_manifest_zero_exit(tmp_path, capsys):
    clean = tmp_path / "AndroidManifest.xml"
    clean.write_text(
        '<?xml version="1.0"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="com.example.clean">\n'
        '  <uses-sdk android:targetSdkVersion="34" />\n'
        '  <application android:allowBackup="false">\n'
        '    <activity android:name=".Main" android:exported="false" />\n'
        '  </application>\n'
        '</manifest>\n', encoding="utf-8")
    rc = main(["scan", str(clean), "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["total"] == 0
    assert rc == 0
