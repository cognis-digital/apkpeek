"""Deep-feature tests for the MobSF-style APKPEEK engine. No network."""
import importlib.util
import json
import os

import pytest

from apkpeek import (
    TOOL_NAME, TOOL_VERSION, PERMISSION_DB,
    scan_apk, analyze_manifest, analyze_network_security_config,
    extract_metadata, scan_secrets, compute_score, to_sarif,
)
from apkpeek.cli import main

DEEP_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demos", "02-deep")
MANIFEST = os.path.join(DEEP_DIR, "AndroidManifest.xml")
NSC = os.path.join(DEEP_DIR, "network_security_config.xml")
SECRETS = os.path.join(DEEP_DIR, "secrets.json")


def _load_builder():
    spec = importlib.util.spec_from_file_location("build_apk", os.path.join(DEEP_DIR, "build_apk.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------- metadata
def test_metadata_in_core():
    assert TOOL_NAME == "apkpeek"
    assert TOOL_VERSION.count(".") == 2
    assert len(PERMISSION_DB) >= 50  # genuinely useful, not a toy list


def test_extract_metadata():
    xml = open(MANIFEST, encoding="utf-8").read()
    meta = extract_metadata(xml)
    assert meta["package"] == "com.example.bankspy"
    assert meta["version_code"] == 42
    assert meta["version_name"] == "3.1.0"
    assert meta["min_sdk"] == 19 and meta["target_sdk"] == 28
    assert meta["components"]["provider"] == 1
    assert "android.permission.READ_SMS" in meta["permissions"]
    assert any(cp["name"].endswith("C2_CALLBACK") for cp in meta["custom_permissions"])


# ---------------------------------------------------------------- manifest
def test_manifest_flags_all_core_classes():
    findings = analyze_manifest(open(MANIFEST, encoding="utf-8").read())
    ids = {f.rule_id for f in findings}
    for rid in ("APK-DEBUG", "APK-BACKUP", "APK-CLEARTEXT", "APK-PERM",
                "APK-PERM-COMBO", "APK-CUSTOMPERM", "APK-EXPORT",
                "APK-MINSDK", "APK-TARGETSDK", "APK-TASKHIJACK"):
        assert rid in ids, f"missing {rid}"


def test_red_flag_permission_combo_is_high():
    findings = analyze_manifest(open(MANIFEST, encoding="utf-8").read())
    combos = [f for f in findings if f.rule_id == "APK-PERM-COMBO"]
    assert combos and all(f.severity == "high" for f in combos)
    # banking-trojan signal (notification + accessibility) must be detected
    assert any("banking-trojan" in f.message for f in combos)


def test_exported_severity_grading():
    findings = analyze_manifest(open(MANIFEST, encoding="utf-8").read())
    exp = {f.detail.get("type"): f for f in findings if f.rule_id == "APK-EXPORT"}
    assert exp["provider"].severity == "high"          # unguarded provider
    assert exp["service"].severity == "low"            # permission-guarded
    assert exp["receiver"].detail["explicit"] is False  # implicitly exported
    names = [f.detail.get("component", "") for f in findings if f.rule_id == "APK-EXPORT"]
    assert not any("PrivateActivity" in n for n in names)  # exported=false skipped


def test_findings_carry_cwe_and_masvs():
    findings = analyze_manifest(open(MANIFEST, encoding="utf-8").read())
    debug = [f for f in findings if f.rule_id == "APK-DEBUG"][0]
    assert debug.cwe.startswith("CWE-")
    assert debug.masvs.startswith("MASVS-")


# ------------------------------------------------------ network security config
def test_nsc_analysis():
    findings = analyze_network_security_config(open(NSC, encoding="utf-8").read())
    ids = {f.rule_id for f in findings}
    assert "NSC-CLEARTEXT-BASE" in ids
    assert "NSC-CLEARTEXT-DOMAIN" in ids
    assert "NSC-USER-CA" in ids
    assert "NSC-NO-PINNING" in ids


# ---------------------------------------------------------------- secrets
def test_secret_scanner_breadth():
    findings = scan_secrets("secrets.json", open(SECRETS, "rb").read())
    ids = {f.rule_id for f in findings}
    for rid in ("SEC-AWS-AKID", "SEC-GOOGLE-API", "SEC-GITHUB-PAT",
                "SEC-STRIPE", "SEC-SLACK-WEBHOOK", "SEC-IP-URL"):
        assert rid in ids, f"missing {rid}"
    # entropy pass catches the random session_secret
    assert "SEC-ENTROPY" in ids
    # nothing is echoed in full
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.message


# ---------------------------------------------------------------- scoring
def test_score_and_grade():
    finds = analyze_manifest(open(MANIFEST, encoding="utf-8").read())
    score = compute_score([f.to_dict() for f in finds])
    assert 0 <= score["security_score"] <= 100
    assert score["grade"] in ("A", "B", "C", "D", "F")
    # this manifest is dangerous -> should be a poor grade
    assert score["grade"] in ("D", "F")


# ---------------------------------------------------------------- end-to-end APK
def test_scan_real_apk_end_to_end(tmp_path):
    apk = _load_builder().build(str(tmp_path / "demo.apk"))
    report = scan_apk(apk)
    assert report["manifest_present"] is True
    assert report["metadata"]["package"] == "com.example.bankspy"
    ids = {f["rule_id"] for f in report["findings"]}
    # manifest + NSC + secrets all fired through the zip path
    assert "APK-DEBUG" in ids
    assert "NSC-USER-CA" in ids
    assert "SEC-AWS-AKID" in ids
    assert report["security_score"] < 40  # F territory
    assert report["grade"] == "F"
    assert report["tool"]["name"] == "apkpeek"


def test_no_secrets_flag(tmp_path):
    apk = _load_builder().build(str(tmp_path / "demo.apk"))
    report = scan_apk(apk, scan_secrets_in_files=False)
    ids = {f["rule_id"] for f in report["findings"]}
    assert not any(i.startswith("SEC-") for i in ids)
    # manifest/NSC findings still present
    assert "APK-DEBUG" in ids


# ---------------------------------------------------------------- SARIF
def test_sarif_includes_cwe():
    report = scan_apk(MANIFEST)
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == len(report["findings"])
    assert any(r["properties"].get("cwe") for r in results)


# ---------------------------------------------------------------- CLI
def test_cli_scan_json_and_exit(tmp_path, capsys):
    apk = _load_builder().build(str(tmp_path / "demo.apk"))
    rc = main(["scan", apk, "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["security_score"] < 40
    assert rc == 1  # default --fail-on high, has high findings


def test_cli_manifest_subcommand(capsys):
    rc = main(["manifest", MANIFEST, "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["package"] == "com.example.bankspy"


def test_cli_rules_subcommand(capsys):
    rc = main(["rules", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["permissions"]) >= 50
    assert len(data["secret_rules"]) >= 10


def test_cli_version_subcommand(capsys):
    rc = main(["version"])
    assert rc == 0
    assert TOOL_VERSION in capsys.readouterr().out


def test_cli_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert TOOL_VERSION in capsys.readouterr().out
