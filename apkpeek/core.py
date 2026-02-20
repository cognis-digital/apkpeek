"""Core engine for APKPEEK: real binary-AXML decoding + APK static triage.

No third-party imports. Works on real .apk files (which are ZIP archives whose
AndroidManifest.xml is in Android's binary XML / AXML format) and also on plain
text AndroidManifest.xml files for easy testing.
"""
from __future__ import annotations

import io
import re
import struct
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# ----------------------------------------------------------------------------
# Severity
# ----------------------------------------------------------------------------
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    location: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ----------------------------------------------------------------------------
# Binary AXML decoder (real implementation)
# ----------------------------------------------------------------------------
# Chunk type constants from Android's ResChunk_header.
_RES_XML_TYPE = 0x0003
_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_START_ELEMENT_TYPE = 0x0102
_RES_XML_END_ELEMENT_TYPE = 0x0103
_RES_XML_START_NAMESPACE_TYPE = 0x0100
_RES_XML_END_NAMESPACE_TYPE = 0x0101
_RES_XML_RESOURCE_MAP_TYPE = 0x0180

# Common resource value types.
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12

_UTF8_FLAG = 1 << 8


def _read_string_pool(data: bytes, start: int) -> Tuple[List[str], int]:
    """Parse a string pool chunk; return (strings, next_offset)."""
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, start)
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<IIIII", data, start + 8
    )
    is_utf8 = bool(flags & _UTF8_FLAG)
    offsets_base = start + 28
    string_data_base = start + strings_start
    strings: List[str] = []
    for i in range(string_count):
        (off,) = struct.unpack_from("<I", data, offsets_base + i * 4)
        pos = string_data_base + off
        if is_utf8:
            # UTF-8: two length fields (char count, byte count), each may be 2 bytes.
            pos, _charlen = _decode_utf8_len(data, pos)
            pos, bytelen = _decode_utf8_len(data, pos)
            raw = data[pos:pos + bytelen]
            strings.append(raw.decode("utf-8", "replace"))
        else:
            ulen = data[pos] | (data[pos + 1] << 8)
            pos += 2
            if ulen & 0x8000:  # high bit => length is 4 bytes
                ulen = (ulen & 0x7FFF) << 16 | (data[pos] | (data[pos + 1] << 8))
                pos += 2
            raw = data[pos:pos + ulen * 2]
            strings.append(raw.decode("utf-16-le", "replace"))
    return strings, start + chunk_size


def _decode_utf8_len(data: bytes, pos: int) -> Tuple[int, int]:
    val = data[pos]
    pos += 1
    if val & 0x80:
        val = ((val & 0x7F) << 8) | data[pos]
        pos += 1
    return pos, val


def _attr_value(strings: List[str], value_type: int, value_data: int, raw_str_idx: int) -> Any:
    if value_type == _TYPE_STRING:
        if 0 <= raw_str_idx < len(strings):
            return strings[raw_str_idx]
        return ""
    if value_type == _TYPE_INT_BOOLEAN:
        return value_data != 0
    if value_type in (_TYPE_INT_DEC, _TYPE_INT_HEX):
        return value_data
    return value_data


def parse_axml(data: bytes) -> str:
    """Decode binary AndroidManifest.xml (AXML) to a readable XML string.

    Raises ValueError if the blob is not AXML.
    """
    if len(data) < 8:
        raise ValueError("too small to be AXML")
    magic, _hsize, _csize = struct.unpack_from("<HHI", data, 0)
    if magic != _RES_XML_TYPE:
        raise ValueError("not a binary XML chunk")

    strings: List[str] = []
    pos = 8
    out: List[str] = ['<?xml version="1.0" encoding="utf-8"?>']
    ns_uri_to_prefix: Dict[str, str] = {}

    while pos + 8 <= len(data):
        c_type, c_hsize, c_size = struct.unpack_from("<HHI", data, pos)
        if c_size < 8:
            break
        if c_type == _RES_STRING_POOL_TYPE:
            strings, _ = _read_string_pool(data, pos)
        elif c_type == _RES_XML_RESOURCE_MAP_TYPE:
            pass
        elif c_type == _RES_XML_START_NAMESPACE_TYPE:
            prefix_idx, uri_idx = struct.unpack_from("<ii", data, pos + 16)
            if 0 <= uri_idx < len(strings) and 0 <= prefix_idx < len(strings):
                ns_uri_to_prefix[strings[uri_idx]] = strings[prefix_idx]
        elif c_type == _RES_XML_START_ELEMENT_TYPE:
            ns_idx, name_idx = struct.unpack_from("<ii", data, pos + 16)
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, pos + 24)
            name = strings[name_idx] if 0 <= name_idx < len(strings) else "unknown"
            attrs: List[str] = []
            ab = pos + 16 + attr_start
            for i in range(attr_count):
                a_ns, a_name, a_rawval, a_typedval, a_data = struct.unpack_from(
                    "<iiiIi", data, ab + i * 20
                )
                value_type = (a_typedval >> 24) & 0xFF
                aname = strings[a_name] if 0 <= a_name < len(strings) else "attr"
                prefix = ""
                if 0 <= a_ns < len(strings):
                    prefix = ns_uri_to_prefix.get(strings[a_ns], "")
                full = f"{prefix}:{aname}" if prefix else aname
                val = _attr_value(strings, value_type, a_data, a_rawval)
                if isinstance(val, bool):
                    val = "true" if val else "false"
                attrs.append(f'{full}="{_xml_escape(str(val))}"')
            attr_str = (" " + " ".join(attrs)) if attrs else ""
            out.append(f"<{name}{attr_str}>")
        elif c_type == _RES_XML_END_ELEMENT_TYPE:
            ns_idx, name_idx = struct.unpack_from("<ii", data, pos + 16)
            name = strings[name_idx] if 0 <= name_idx < len(strings) else "unknown"
            out.append(f"</{name}>")
        pos += c_size
    return "\n".join(out)


def _xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ----------------------------------------------------------------------------
# Manifest analysis
# ----------------------------------------------------------------------------
_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Dangerous (runtime) permissions per Android docs -> severity.
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "high",
    "android.permission.SEND_SMS": "high",
    "android.permission.RECEIVE_SMS": "high",
    "android.permission.READ_CONTACTS": "medium",
    "android.permission.WRITE_CONTACTS": "medium",
    "android.permission.RECORD_AUDIO": "high",
    "android.permission.CAMERA": "medium",
    "android.permission.ACCESS_FINE_LOCATION": "high",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "high",
    "android.permission.READ_CALL_LOG": "high",
    "android.permission.WRITE_CALL_LOG": "high",
    "android.permission.READ_EXTERNAL_STORAGE": "medium",
    "android.permission.WRITE_EXTERNAL_STORAGE": "medium",
    "android.permission.READ_PHONE_STATE": "medium",
    "android.permission.SYSTEM_ALERT_WINDOW": "medium",
    "android.permission.REQUEST_INSTALL_PACKAGES": "high",
    "android.permission.QUERY_ALL_PACKAGES": "low",
}

_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


def _ns_attr(elem: ET.Element, name: str) -> Optional[str]:
    """Read an android:* attribute, namespaced or plain."""
    v = elem.get(f"{{{_ANDROID_NS}}}{name}")
    if v is None:
        v = elem.get(f"android:{name}")
    if v is None:
        v = elem.get(name)
    return v


def _truthy(v: Optional[str]) -> bool:
    return str(v).strip().lower() == "true"


def analyze_manifest(xml_text: str) -> List[Finding]:
    """Analyze a (decoded) AndroidManifest.xml string for security findings."""
    findings: List[Finding] = []
    # Strip android: prefixes are kept; register namespace so parsing succeeds.
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return [Finding("APK000", "info", f"manifest parse error: {e}", "AndroidManifest.xml")]

    pkg = root.get("package", "")

    # Permissions.
    for perm in root.iter("uses-permission"):
        name = _ns_attr(perm, "name")
        if not name:
            continue
        if name in DANGEROUS_PERMISSIONS:
            findings.append(
                Finding(
                    "APK-PERM",
                    DANGEROUS_PERMISSIONS[name],
                    f"Dangerous permission requested: {name}",
                    "AndroidManifest.xml",
                    {"permission": name},
                )
            )

    app = root.find("application")
    if app is not None:
        if _truthy(_ns_attr(app, "debuggable")):
            findings.append(
                Finding(
                    "APK-DEBUG",
                    "high",
                    "Application is debuggable (android:debuggable=true) — must be false in release builds.",
                    "application",
                )
            )
        if _truthy(_ns_attr(app, "allowBackup")):
            findings.append(
                Finding(
                    "APK-BACKUP",
                    "medium",
                    "android:allowBackup=true allows app data extraction via adb backup.",
                    "application",
                )
            )
        if _truthy(_ns_attr(app, "usesCleartextTraffic")):
            findings.append(
                Finding(
                    "APK-CLEARTEXT",
                    "medium",
                    "android:usesCleartextTraffic=true permits unencrypted HTTP traffic.",
                    "application",
                )
            )

        # Exported components.
        for tag in _COMPONENT_TAGS:
            for comp in app.iter(tag):
                cname = _ns_attr(comp, "name") or "<anonymous>"
                exported_attr = _ns_attr(comp, "exported")
                has_filter = comp.find("intent-filter") is not None
                # Determine effective exported state.
                if exported_attr is not None:
                    exported = _truthy(exported_attr)
                    explicit = True
                else:
                    # Implicitly exported if it declares an intent-filter.
                    exported = has_filter
                    explicit = False
                if not exported:
                    continue
                perm = _ns_attr(comp, "permission")
                sev = "medium"
                detail = {"component": cname, "type": tag, "explicit": explicit}
                if tag == "provider":
                    sev = "high"
                if not explicit and has_filter:
                    msg = (
                        f"{tag} '{cname}' is implicitly exported (intent-filter, no "
                        f"android:exported) — risky on API < 31."
                    )
                else:
                    msg = f"{tag} '{cname}' is exported."
                if perm:
                    msg += f" Guarded by permission {perm}."
                    detail["permission"] = perm
                    sev = "low"
                else:
                    msg += " No permission guard."
                findings.append(Finding("APK-EXPORT", sev, msg, cname or pkg, detail))

    return findings


# ----------------------------------------------------------------------------
# Secret scanning
# ----------------------------------------------------------------------------
# (rule_id, severity, compiled regex, label)
_SECRET_PATTERNS: List[Tuple[str, str, re.Pattern, str]] = [
    ("SEC-AWS-AKID", "critical", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id"),
    ("SEC-GOOGLE-API", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    ("SEC-GITHUB-PAT", "critical", re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), "GitHub personal access token"),
    ("SEC-SLACK", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"), "Slack token"),
    ("SEC-STRIPE", "critical", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{16,}\b"), "Stripe live secret key"),
    ("SEC-PRIVKEY", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "Private key block"),
    ("SEC-JWT", "medium", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "JWT"),
    ("SEC-FIREBASE", "medium", re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"), "Firebase database URL"),
    ("SEC-GENERIC", "low", re.compile(r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[=:]\s*['\"][^'\"]{6,}['\"]"), "Generic hard-coded credential"),
]

_TEXT_EXTS = (".xml", ".json", ".txt", ".properties", ".js", ".html", ".cfg", ".ini", ".yaml", ".yml", ".gradle", ".kt", ".java", ".md", ".smali")


def scan_secrets(name: str, data: bytes) -> List[Finding]:
    """Scan a single file's bytes for hard-coded secrets."""
    findings: List[Finding] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", "replace")
    seen: set = set()
    for rule_id, sev, rx, label in _SECRET_PATTERNS:
        for m in rx.finditer(text):
            token = m.group(0)
            key = (rule_id, token)
            if key in seen:
                continue
            seen.add(key)
            line = text.count("\n", 0, m.start()) + 1
            redacted = token[:6] + "…" + token[-2:] if len(token) > 12 else token[:3] + "…"
            findings.append(
                Finding(
                    rule_id,
                    sev,
                    f"Possible {label} found: {redacted}",
                    f"{name}:{line}",
                    {"label": label, "match_preview": redacted, "file": name, "line": line},
                )
            )
    return findings


# ----------------------------------------------------------------------------
# Top-level scan
# ----------------------------------------------------------------------------
def _load_manifest_xml(z: zipfile.ZipFile) -> Optional[str]:
    if "AndroidManifest.xml" not in z.namelist():
        return None
    raw = z.read("AndroidManifest.xml")
    # Try binary AXML first; fall back to plain text.
    try:
        return parse_axml(raw)
    except (ValueError, struct.error, IndexError):
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1", "replace")


def scan_apk(path: str, *, max_file_bytes: int = 5_000_000, scan_secrets_in_files: bool = True) -> Dict[str, Any]:
    """Scan an APK (or a raw/plain AndroidManifest.xml) and return a report dict.

    The report dict has keys:
        target, manifest_xml, findings (list of dicts), summary (severity counts).
    """
    findings: List[Finding] = []
    manifest_xml: Optional[str] = None
    target = path

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            manifest_xml = _load_manifest_xml(z)
            if manifest_xml:
                findings.extend(analyze_manifest(manifest_xml))
            if scan_secrets_in_files:
                for info in z.infolist():
                    if info.is_dir() or info.file_size > max_file_bytes:
                        continue
                    if info.filename == "AndroidManifest.xml":
                        if manifest_xml:
                            findings.extend(scan_secrets(info.filename, manifest_xml.encode("utf-8")))
                        continue
                    if info.filename.lower().endswith(_TEXT_EXTS):
                        findings.extend(scan_secrets(info.filename, z.read(info.filename)))
    else:
        # Treat as a plain (possibly binary) AndroidManifest.xml file.
        with open(path, "rb") as fh:
            raw = fh.read()
        try:
            manifest_xml = parse_axml(raw)
        except (ValueError, struct.error, IndexError):
            manifest_xml = raw.decode("utf-8", "replace")
        findings.extend(analyze_manifest(manifest_xml))
        if scan_secrets_in_files:
            findings.extend(scan_secrets(path, manifest_xml.encode("utf-8")))

    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.rule_id))
    summary: Dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    return {
        "target": target,
        "manifest_present": manifest_xml is not None,
        "manifest_xml": manifest_xml,
        "findings": [f.to_dict() for f in findings],
        "summary": summary,
    }


# ----------------------------------------------------------------------------
# SARIF 2.1.0
# ----------------------------------------------------------------------------
_SARIF_LEVEL = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def to_sarif(report: Dict[str, Any], tool_name: str = "apkpeek", tool_version: str = "1.0.0") -> Dict[str, Any]:
    findings = report.get("findings", [])
    rule_ids = sorted({f["rule_id"] for f in findings})
    rules = [
        {"id": rid, "name": rid, "shortDescription": {"text": rid}}
        for rid in rule_ids
    ]
    results = []
    for f in findings:
        loc = f.get("location") or report.get("target", "")
        results.append(
            {
                "ruleId": f["rule_id"],
                "level": _SARIF_LEVEL.get(f["severity"], "warning"),
                "message": {"text": f["message"]},
                "properties": {"severity": f["severity"], **f.get("detail", {})},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(loc).split(":")[0] or "AndroidManifest.xml"}
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://example.com/apkpeek",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
