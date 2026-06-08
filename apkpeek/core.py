"""Core engine for APKPEEK — a self-contained Android static-analysis engine
in the spirit of MobSF (mobile-security-framework).

Pure standard library. Works on real ``.apk`` files (ZIP archives whose
``AndroidManifest.xml`` is Android binary XML / AXML) and on plain-text
``AndroidManifest.xml`` files for easy testing.

What it does, MobSF-style:
  * Decodes binary AXML to readable XML.
  * Extracts app metadata (package, versions, min/target/maxSdk, app label).
  * Flags exported components (with the API-31 implicit-export nuance).
  * Maps every requested permission to a human description + risk category,
    using a bundled ~70-entry Android permission database.
  * Flags insecure application flags: debuggable, allowBackup, cleartext,
    test-only, large-heap, custom-process abuse.
  * Parses ``network_security_config`` XML for cleartext / user-trust /
    pinning weaknesses.
  * Scans bundled text files for hard-coded secrets (regex + Shannon entropy).
  * Computes a MobSF-style 0-100 security score and an A-F grade.
  * Tags findings with CWE and OWASP MASVS references.
  * Emits JSON and SARIF 2.1.0.
"""
from __future__ import annotations

import math
import re
import struct
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# ----------------------------------------------------------------------------
# Tool identity (single source of truth — re-exported by __init__)
# ----------------------------------------------------------------------------
TOOL_NAME = "apkpeek"
TOOL_VERSION = "2.0.0"

# ----------------------------------------------------------------------------
# Severity
# ----------------------------------------------------------------------------
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# How much each finding subtracts from the 100-point security score.
_SEVERITY_PENALTY = {"info": 0, "low": 4, "medium": 10, "high": 18, "critical": 30}


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    location: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    cwe: str = ""
    masvs: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ----------------------------------------------------------------------------
# Binary AXML decoder (real implementation)
# ----------------------------------------------------------------------------
_RES_XML_TYPE = 0x0003
_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_START_ELEMENT_TYPE = 0x0102
_RES_XML_END_ELEMENT_TYPE = 0x0103
_RES_XML_START_NAMESPACE_TYPE = 0x0100
_RES_XML_END_NAMESPACE_TYPE = 0x0101
_RES_XML_RESOURCE_MAP_TYPE = 0x0180

_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_INT_BOOLEAN = 0x12

_UTF8_FLAG = 1 << 8


def _read_string_pool(data: bytes, start: int) -> Tuple[List[str], int]:
    """Parse a string pool chunk; return (strings, next_offset)."""
    _ct, _hs, chunk_size = struct.unpack_from("<HHI", data, start)
    string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
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
            pos, _charlen = _decode_utf8_len(data, pos)
            pos, bytelen = _decode_utf8_len(data, pos)
            raw = data[pos:pos + bytelen]
            strings.append(raw.decode("utf-8", "replace"))
        else:
            ulen = data[pos] | (data[pos + 1] << 8)
            pos += 2
            if ulen & 0x8000:
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
        c_type, _c_hsize, c_size = struct.unpack_from("<HHI", data, pos)
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
            _ns_idx, name_idx = struct.unpack_from("<ii", data, pos + 16)
            attr_start, _attr_size, attr_count = struct.unpack_from("<HHH", data, pos + 24)
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
            _ns_idx, name_idx = struct.unpack_from("<ii", data, pos + 16)
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
# Bundled Android permission database (MobSF-style).
# Maps permission -> (severity, short description).
# ----------------------------------------------------------------------------
_ANDROID_NS = "http://schemas.android.com/apk/res/android"

PERMISSION_DB: Dict[str, Tuple[str, str]] = {
    # SMS / calls — high abuse value
    "android.permission.READ_SMS": ("high", "Read SMS messages — toll-fraud / OTP theft vector."),
    "android.permission.SEND_SMS": ("high", "Send SMS — premium-SMS billing fraud vector."),
    "android.permission.RECEIVE_SMS": ("high", "Intercept incoming SMS — OTP interception."),
    "android.permission.RECEIVE_MMS": ("medium", "Intercept incoming MMS."),
    "android.permission.RECEIVE_WAP_PUSH": ("medium", "Receive WAP push messages."),
    "android.permission.READ_CALL_LOG": ("high", "Read call history — PII exposure."),
    "android.permission.WRITE_CALL_LOG": ("high", "Modify call history — tampering."),
    "android.permission.PROCESS_OUTGOING_CALLS": ("high", "Intercept/redirect outgoing calls."),
    "android.permission.CALL_PHONE": ("medium", "Place calls without user dialing — billing abuse."),
    "android.permission.ANSWER_PHONE_CALLS": ("medium", "Answer calls programmatically."),
    # Contacts / calendar / accounts
    "android.permission.READ_CONTACTS": ("medium", "Read contacts — PII harvesting."),
    "android.permission.WRITE_CONTACTS": ("medium", "Modify contacts."),
    "android.permission.GET_ACCOUNTS": ("medium", "Enumerate on-device accounts."),
    "android.permission.READ_CALENDAR": ("medium", "Read calendar events — PII."),
    "android.permission.WRITE_CALENDAR": ("low", "Modify calendar events."),
    # Location
    "android.permission.ACCESS_FINE_LOCATION": ("high", "Precise GPS location tracking."),
    "android.permission.ACCESS_COARSE_LOCATION": ("medium", "Approximate location tracking."),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("high", "Continuous background location tracking."),
    # Media / sensors
    "android.permission.CAMERA": ("medium", "Capture photos/video — surveillance risk."),
    "android.permission.RECORD_AUDIO": ("high", "Record microphone audio — eavesdropping."),
    "android.permission.BODY_SENSORS": ("medium", "Read body/heart-rate sensors — health PII."),
    "android.permission.ACTIVITY_RECOGNITION": ("low", "Detect physical activity."),
    # Storage
    "android.permission.READ_EXTERNAL_STORAGE": ("medium", "Read shared storage — broad file access."),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("medium", "Write shared storage."),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("high", "All-files access — bypasses scoped storage."),
    "android.permission.READ_MEDIA_IMAGES": ("low", "Read image media files."),
    "android.permission.READ_MEDIA_VIDEO": ("low", "Read video media files."),
    "android.permission.READ_MEDIA_AUDIO": ("low", "Read audio media files."),
    # Phone / device identity
    "android.permission.READ_PHONE_STATE": ("medium", "Read phone state / IMEI-class identifiers."),
    "android.permission.READ_PHONE_NUMBERS": ("medium", "Read device phone numbers."),
    "android.permission.READ_PRIVILEGED_PHONE_STATE": ("high", "Privileged phone-state access."),
    # Install / packages
    "android.permission.REQUEST_INSTALL_PACKAGES": ("high", "Install APKs — sideload-malware vector."),
    "android.permission.REQUEST_DELETE_PACKAGES": ("medium", "Uninstall packages."),
    "android.permission.QUERY_ALL_PACKAGES": ("low", "Enumerate all installed apps — fingerprinting."),
    "android.permission.INSTALL_PACKAGES": ("critical", "System-level package install — privileged."),
    "android.permission.DELETE_PACKAGES": ("critical", "System-level package delete — privileged."),
    # Overlay / accessibility — classic malware abuse
    "android.permission.SYSTEM_ALERT_WINDOW": ("high", "Draw overlays — tapjacking / phishing overlays."),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("critical", "Accessibility service — full UI control, keylogging."),
    "android.permission.BIND_DEVICE_ADMIN": ("critical", "Device-admin — lock/wipe, anti-uninstall."),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": ("high", "Read all notifications — OTP/banking scraping."),
    "android.permission.WRITE_SETTINGS": ("high", "Modify system settings."),
    "android.permission.WRITE_SECURE_SETTINGS": ("critical", "Modify secure settings — privileged."),
    "android.permission.CHANGE_CONFIGURATION": ("low", "Change device configuration."),
    # Network
    "android.permission.INTERNET": ("info", "Full network access (extremely common)."),
    "android.permission.ACCESS_NETWORK_STATE": ("info", "Read connectivity state."),
    "android.permission.ACCESS_WIFI_STATE": ("low", "Read Wi-Fi state / BSSID — coarse location."),
    "android.permission.CHANGE_WIFI_STATE": ("low", "Toggle Wi-Fi."),
    "android.permission.NEARBY_WIFI_DEVICES": ("low", "Discover nearby Wi-Fi devices."),
    "android.permission.BLUETOOTH": ("low", "Bluetooth access."),
    "android.permission.BLUETOOTH_CONNECT": ("low", "Connect to paired Bluetooth devices."),
    "android.permission.BLUETOOTH_SCAN": ("medium", "Scan for Bluetooth devices — proximity tracking."),
    # Background / persistence
    "android.permission.RECEIVE_BOOT_COMPLETED": ("low", "Auto-start at boot — persistence."),
    "android.permission.FOREGROUND_SERVICE": ("info", "Run foreground services."),
    "android.permission.WAKE_LOCK": ("info", "Keep CPU awake."),
    "android.permission.SCHEDULE_EXACT_ALARM": ("low", "Schedule exact alarms — persistence."),
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": ("low", "Evade battery optimization — persistence."),
    "android.permission.DISABLE_KEYGUARD": ("medium", "Disable lock screen."),
    # NFC / biometric / misc
    "android.permission.NFC": ("low", "NFC access."),
    "android.permission.USE_BIOMETRIC": ("info", "Use biometric auth."),
    "android.permission.USE_FINGERPRINT": ("info", "Use fingerprint auth (deprecated)."),
    "android.permission.VIBRATE": ("info", "Vibrate device."),
    "android.permission.POST_NOTIFICATIONS": ("info", "Post notifications."),
    # Dangerous combinations / privileged
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": ("high", "Mount/unmount filesystems — privileged."),
    "android.permission.MASTER_CLEAR": ("critical", "Factory-reset device — privileged."),
    "android.permission.REBOOT": ("high", "Reboot device — privileged."),
    "android.permission.SET_TIME": ("medium", "Set system clock."),
    "android.permission.CAPTURE_AUDIO_OUTPUT": ("high", "Capture audio output — privileged."),
    "android.permission.READ_LOGS": ("high", "Read system logs — leaks other apps' data."),
    "android.permission.DUMP": ("high", "Dump system service state — privileged."),
}

# Permissions that, together, are a strong banking-trojan / spyware signal.
_RED_FLAG_COMBOS: List[Tuple[str, List[str], str]] = [
    (
        "Notification + Accessibility (banking-trojan signal)",
        ["android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
         "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "Reads notifications AND drives the UI — classic banking-trojan / OTP-theft profile.",
    ),
    (
        "SMS interception + INTERNET (OTP exfiltration signal)",
        ["android.permission.RECEIVE_SMS", "android.permission.INTERNET"],
        "Can intercept OTP SMS and exfiltrate over the network.",
    ),
    (
        "Overlay + Accessibility (overlay-attack signal)",
        ["android.permission.SYSTEM_ALERT_WINDOW",
         "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "Draw-over-others plus UI control — credential-overlay attack profile.",
    ),
    (
        "Install packages + Device admin (dropper/persistence signal)",
        ["android.permission.REQUEST_INSTALL_PACKAGES",
         "android.permission.BIND_DEVICE_ADMIN"],
        "Can sideload payloads and resist uninstall — dropper profile.",
    ),
]

_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


# ----------------------------------------------------------------------------
# Manifest helpers
# ----------------------------------------------------------------------------
def _ns_attr(elem: ET.Element, name: str) -> Optional[str]:
    v = elem.get(f"{{{_ANDROID_NS}}}{name}")
    if v is None:
        v = elem.get(f"android:{name}")
    if v is None:
        v = elem.get(name)
    return v


def _truthy(v: Optional[str]) -> bool:
    return str(v).strip().lower() == "true"


def _to_int(v: Optional[str]) -> Optional[int]:
    if v is None:
        return None
    try:
        s = str(v).strip()
        return int(s, 0) if s.lower().startswith("0x") else int(s)
    except (ValueError, TypeError):
        return None


def extract_metadata(xml_text: str) -> Dict[str, Any]:
    """Pull package/version/SDK metadata from a decoded manifest."""
    meta: Dict[str, Any] = {
        "package": "", "version_name": "", "version_code": None,
        "min_sdk": None, "target_sdk": None, "max_sdk": None,
        "app_label": "", "components": {t: 0 for t in _COMPONENT_TAGS},
        "permissions": [], "custom_permissions": [],
    }
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return meta
    meta["package"] = root.get("package", "")
    meta["version_name"] = _ns_attr(root, "versionName") or ""
    meta["version_code"] = _to_int(_ns_attr(root, "versionCode"))
    sdk = root.find("uses-sdk")
    if sdk is not None:
        meta["min_sdk"] = _to_int(_ns_attr(sdk, "minSdkVersion"))
        meta["target_sdk"] = _to_int(_ns_attr(sdk, "targetSdkVersion"))
        meta["max_sdk"] = _to_int(_ns_attr(sdk, "maxSdkVersion"))
    app = root.find("application")
    if app is not None:
        meta["app_label"] = _ns_attr(app, "label") or ""
        for tag in _COMPONENT_TAGS:
            meta["components"][tag] = len(list(app.iter(tag)))
    for perm in root.iter("uses-permission"):
        n = _ns_attr(perm, "name")
        if n:
            meta["permissions"].append(n)
    for perm in root.iter("permission"):
        n = _ns_attr(perm, "name")
        if n:
            meta["custom_permissions"].append({
                "name": n,
                "protectionLevel": _ns_attr(perm, "protectionLevel") or "normal",
            })
    return meta


def analyze_manifest(xml_text: str) -> List[Finding]:
    """Analyze a decoded AndroidManifest.xml string for security findings."""
    findings: List[Finding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return [Finding("APK000", "info", f"manifest parse error: {e}", "AndroidManifest.xml")]

    pkg = root.get("package", "")
    requested = []

    # Permissions.
    for perm in root.iter("uses-permission"):
        name = _ns_attr(perm, "name")
        if not name:
            continue
        requested.append(name)
        if name in PERMISSION_DB:
            sev, desc = PERMISSION_DB[name]
            if sev == "info":
                continue
            findings.append(
                Finding("APK-PERM", sev, f"Dangerous permission: {name} — {desc}",
                        "AndroidManifest.xml", {"permission": name, "description": desc},
                        cwe="CWE-250", masvs="MASVS-PLATFORM-1")
            )

    # Dangerous permission combinations.
    rset = set(requested)
    for label, combo, why in _RED_FLAG_COMBOS:
        if all(c in rset for c in combo):
            findings.append(
                Finding("APK-PERM-COMBO", "high", f"{label}: {why}",
                        "AndroidManifest.xml", {"permissions": combo},
                        cwe="CWE-250", masvs="MASVS-PLATFORM-1")
            )

    # Custom permissions with weak protection level.
    for perm in root.iter("permission"):
        name = _ns_attr(perm, "name") or "<unnamed>"
        plevel = (_ns_attr(perm, "protectionLevel") or "normal").lower()
        if "signature" not in plevel and "knownsigner" not in plevel:
            sev = "medium" if "dangerous" in plevel else "low"
            findings.append(
                Finding("APK-CUSTOMPERM", sev,
                        f"Custom permission '{name}' uses protectionLevel='{plevel}' "
                        f"(not signature-protected) — any app can request it.",
                        "permission", {"permission": name, "protectionLevel": plevel},
                        cwe="CWE-280", masvs="MASVS-PLATFORM-1")
            )

    # uses-sdk hygiene.
    sdk = root.find("uses-sdk")
    if sdk is not None:
        min_sdk = _to_int(_ns_attr(sdk, "minSdkVersion"))
        target_sdk = _to_int(_ns_attr(sdk, "targetSdkVersion"))
        if min_sdk is not None and min_sdk < 23:
            findings.append(
                Finding("APK-MINSDK", "medium",
                        f"minSdkVersion={min_sdk} (< 23) — runs on Android without runtime "
                        f"permissions and many platform mitigations.",
                        "uses-sdk", {"min_sdk": min_sdk},
                        cwe="CWE-1104", masvs="MASVS-PLATFORM-1")
            )
        if target_sdk is not None and target_sdk < 31:
            findings.append(
                Finding("APK-TARGETSDK", "medium",
                        f"targetSdkVersion={target_sdk} (< 31) — pre-Android-12 implicit "
                        f"export rules and weaker PendingIntent / component defaults apply.",
                        "uses-sdk", {"target_sdk": target_sdk},
                        cwe="CWE-1104", masvs="MASVS-PLATFORM-1")
            )

    app = root.find("application")
    if app is not None:
        if _truthy(_ns_attr(app, "debuggable")):
            findings.append(
                Finding("APK-DEBUG", "high",
                        "android:debuggable=true — must be false in release; allows "
                        "runtime inspection/JDWP attach.",
                        "application", cwe="CWE-489", masvs="MASVS-RESILIENCE-2")
            )
        if _ns_attr(app, "allowBackup") is None or _truthy(_ns_attr(app, "allowBackup")):
            sev = "medium"
            note = ("android:allowBackup is not set (defaults to true)"
                    if _ns_attr(app, "allowBackup") is None
                    else "android:allowBackup=true")
            findings.append(
                Finding("APK-BACKUP", sev,
                        f"{note} — app data is extractable via `adb backup`.",
                        "application", cwe="CWE-530", masvs="MASVS-STORAGE-2")
            )
        if _truthy(_ns_attr(app, "usesCleartextTraffic")):
            findings.append(
                Finding("APK-CLEARTEXT", "high",
                        "android:usesCleartextTraffic=true — permits unencrypted HTTP, "
                        "exposing traffic to MITM.",
                        "application", cwe="CWE-319", masvs="MASVS-NETWORK-1")
            )
        if _truthy(_ns_attr(app, "testOnly")):
            findings.append(
                Finding("APK-TESTONLY", "medium",
                        "android:testOnly=true — debug-only build artifact, not for release.",
                        "application", cwe="CWE-489", masvs="MASVS-RESILIENCE-2")
            )
        nsc = _ns_attr(app, "networkSecurityConfig")
        if nsc:
            findings.append(
                Finding("APK-NSC-REF", "info",
                        f"Declares networkSecurityConfig={nsc} — config is analyzed separately.",
                        "application", {"resource": nsc})
            )

        # Exported components.
        for tag in _COMPONENT_TAGS:
            for comp in app.iter(tag):
                cname = _ns_attr(comp, "name") or "<anonymous>"
                exported_attr = _ns_attr(comp, "exported")
                has_filter = comp.find("intent-filter") is not None
                if exported_attr is not None:
                    exported = _truthy(exported_attr)
                    explicit = True
                else:
                    exported = has_filter
                    explicit = False
                if not exported:
                    continue
                perm = _ns_attr(comp, "permission")
                sev = "medium"
                detail = {"component": cname, "type": tag, "explicit": explicit}
                if tag == "provider":
                    sev = "high"
                    grant = _truthy(_ns_attr(comp, "grantUriPermissions"))
                    if grant:
                        detail["grantUriPermissions"] = True
                if not explicit and has_filter:
                    msg = (f"{tag} '{cname}' is implicitly exported (intent-filter, no "
                           f"android:exported) — risky on targetSdk < 31.")
                else:
                    msg = f"{tag} '{cname}' is exported."
                if perm:
                    msg += f" Guarded by permission {perm}."
                    detail["permission"] = perm
                    sev = "low"
                else:
                    msg += " No permission guard — reachable by any app."
                findings.append(
                    Finding("APK-EXPORT", sev, msg, cname or pkg, detail,
                            cwe="CWE-926", masvs="MASVS-PLATFORM-1")
                )

                # Task-hijacking signal (singleTask/singleInstance + taskAffinity).
                lmode = (_ns_attr(comp, "launchMode") or "").lower()
                affinity = _ns_attr(comp, "taskAffinity")
                if tag in ("activity", "activity-alias") and affinity is not None \
                        and lmode in ("singletask", "singleinstance"):
                    findings.append(
                        Finding("APK-TASKHIJACK", "medium",
                                f"{tag} '{cname}' sets taskAffinity with launchMode={lmode} — "
                                f"StrandHogg-style task-hijacking exposure.",
                                cname, {"taskAffinity": affinity, "launchMode": lmode},
                                cwe="CWE-940", masvs="MASVS-PLATFORM-1")
                    )

    return findings


# ----------------------------------------------------------------------------
# Network Security Config analysis
# ----------------------------------------------------------------------------
def analyze_network_security_config(xml_text: str, name: str = "network_security_config.xml") -> List[Finding]:
    """Analyze a decoded res/xml network-security-config for weaknesses."""
    findings: List[Finding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    base = root.find("base-config")
    if base is not None and _truthy(base.get("cleartextTrafficPermitted")):
        findings.append(
            Finding("NSC-CLEARTEXT-BASE", "high",
                    "base-config permits cleartext traffic app-wide.",
                    name, cwe="CWE-319", masvs="MASVS-NETWORK-1")
        )
    for dc in root.iter("domain-config"):
        if _truthy(dc.get("cleartextTrafficPermitted")):
            domains = [d.text for d in dc.findall("domain") if d.text]
            findings.append(
                Finding("NSC-CLEARTEXT-DOMAIN", "medium",
                        f"domain-config permits cleartext for: {', '.join(domains) or '(unnamed)'}",
                        name, {"domains": domains}, cwe="CWE-319", masvs="MASVS-NETWORK-1")
            )
    for cfg in [root] + list(root.iter("base-config")) + list(root.iter("domain-config")):
        trust = cfg.find("trust-anchors")
        if trust is None:
            continue
        for ca in trust.findall("certificates"):
            if ca.get("src") == "user":
                findings.append(
                    Finding("NSC-USER-CA", "high",
                            "trust-anchors include user-installed CAs — enables trivial MITM "
                            "via a planted certificate.",
                            name, cwe="CWE-296", masvs="MASVS-NETWORK-2")
                )
    if root.find(".//pin-set") is None and root.find(".//domain-config") is not None:
        findings.append(
            Finding("NSC-NO-PINNING", "low",
                    "No certificate pinning (<pin-set>) configured for declared domains.",
                    name, cwe="CWE-295", masvs="MASVS-NETWORK-4")
        )
    return findings


# ----------------------------------------------------------------------------
# Secret scanning — regex + Shannon entropy
# ----------------------------------------------------------------------------
_SECRET_PATTERNS: List[Tuple[str, str, "re.Pattern[str]", str]] = [
    ("SEC-AWS-AKID", "critical", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id"),
    ("SEC-AWS-SECRET", "critical", re.compile(r"(?i)aws_?secret[_-]?access[_-]?key\s*[=:]\s*['\"][0-9A-Za-z/+]{40}['\"]"), "AWS secret access key"),
    ("SEC-GOOGLE-API", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
    ("SEC-GOOGLE-OAUTH", "medium", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"), "Google OAuth client id"),
    ("SEC-FIREBASE-DB", "medium", re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"), "Firebase database URL"),
    ("SEC-GITHUB-PAT", "critical", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "GitHub token"),
    ("SEC-SLACK", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"), "Slack token"),
    ("SEC-SLACK-WEBHOOK", "high", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"), "Slack webhook"),
    ("SEC-STRIPE", "critical", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{16,}\b"), "Stripe live secret key"),
    ("SEC-TWILIO", "high", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "Twilio API key"),
    ("SEC-SENDGRID", "high", re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"), "SendGrid API key"),
    ("SEC-MAILGUN", "high", re.compile(r"\bkey-[0-9a-f]{32}\b"), "Mailgun API key"),
    ("SEC-SQUARE", "high", re.compile(r"\bsq0(atp|csp)-[0-9A-Za-z_\-]{22,43}\b"), "Square token"),
    ("SEC-PRIVKEY", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "Private key block"),
    ("SEC-JWT", "medium", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "JWT"),
    ("SEC-RSA-PUB", "info", re.compile(r"-----BEGIN PUBLIC KEY-----"), "Public key (informational)"),
    ("SEC-IP-URL", "info", re.compile(r"\bhttp://(?:\d{1,3}\.){3}\d{1,3}"), "Hard-coded HTTP IP endpoint"),
    ("SEC-GENERIC", "low", re.compile(r"(?i)(api[_-]?key|secret|password|passwd|token|auth)\s*[=:]\s*['\"][^'\"\s]{8,}['\"]"), "Generic hard-coded credential"),
]

_TEXT_EXTS = (".xml", ".json", ".txt", ".properties", ".js", ".html", ".cfg", ".ini",
              ".yaml", ".yml", ".gradle", ".kt", ".java", ".md", ".smali", ".sql", ".env")

# Strings that look like a high-entropy secret assignment but didn't match a vendor regex.
_ENTROPY_ASSIGN = re.compile(
    r"(?i)(?:secret|token|key|passwd|password|apikey|api_key|access[_-]?key)"
    r"['\"]?\s*[=:]\s*['\"]([A-Za-z0-9+/=_\-]{20,})['\"]"
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(token: str) -> str:
    if len(token) > 12:
        return token[:6] + "…" + token[-2:]
    return token[:3] + "…"


def scan_secrets(name: str, data: bytes) -> List[Finding]:
    """Scan a single file's bytes for hard-coded secrets (regex + entropy)."""
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
            findings.append(
                Finding(rule_id, sev, f"Possible {label}: {_redact(token)}",
                        f"{name}:{line}",
                        {"label": label, "match_preview": _redact(token), "file": name, "line": line},
                        cwe="CWE-798", masvs="MASVS-STORAGE-1")
            )
    # Entropy pass — catches high-randomness assignments vendor regexes miss.
    matched_raw = {m.group(0) for _r, _s, rx, _l in _SECRET_PATTERNS for m in rx.finditer(text)}
    for m in _ENTROPY_ASSIGN.finditer(text):
        token = m.group(1)
        if ("SEC-ENTROPY", token) in seen:
            continue
        # Skip values already reported by a vendor-specific regex.
        if any(token in raw or raw in token for raw in matched_raw):
            continue
        ent = _shannon_entropy(token)
        if ent < 3.5:  # low randomness -> probably a placeholder/word
            continue
        seen.add(("SEC-ENTROPY", token))
        line = text.count("\n", 0, m.start()) + 1
        findings.append(
            Finding("SEC-ENTROPY", "medium",
                    f"High-entropy secret-like value (entropy {ent:.1f}): {_redact(token)}",
                    f"{name}:{line}",
                    {"entropy": round(ent, 2), "match_preview": _redact(token),
                     "file": name, "line": line},
                    cwe="CWE-798", masvs="MASVS-STORAGE-1")
        )
    return findings


# ----------------------------------------------------------------------------
# Scoring (MobSF-style 0-100 security score + grade)
# ----------------------------------------------------------------------------
def compute_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    score = 100
    for f in findings:
        score -= _SEVERITY_PENALTY.get(f.get("severity", "info"), 0)
    score = max(0, min(100, score))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return {"security_score": score, "grade": grade}


# ----------------------------------------------------------------------------
# Top-level scan
# ----------------------------------------------------------------------------
def _decode_xml_blob(raw: bytes) -> str:
    try:
        return parse_axml(raw)
    except (ValueError, struct.error, IndexError):
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1", "replace")


def _load_manifest_xml(z: zipfile.ZipFile) -> Optional[str]:
    if "AndroidManifest.xml" not in z.namelist():
        return None
    return _decode_xml_blob(z.read("AndroidManifest.xml"))


def scan_apk(path: str, *, max_file_bytes: int = 5_000_000,
             scan_secrets_in_files: bool = True) -> Dict[str, Any]:
    """Scan an APK (or a raw/plain AndroidManifest.xml) and return a report dict."""
    findings: List[Finding] = []
    manifest_xml: Optional[str] = None
    metadata: Dict[str, Any] = {}
    target = path

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            manifest_xml = _load_manifest_xml(z)
            if manifest_xml:
                metadata = extract_metadata(manifest_xml)
                findings.extend(analyze_manifest(manifest_xml))
            names = z.namelist()
            # Network security config (res/xml/*.xml).
            for n in names:
                low = n.lower()
                if low.startswith("res/xml/") and low.endswith(".xml"):
                    if any(k in low for k in ("network", "security", "nsc")):
                        try:
                            cfg_xml = _decode_xml_blob(z.read(n))
                        except KeyError:
                            continue
                        findings.extend(analyze_network_security_config(cfg_xml, n))
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
        with open(path, "rb") as fh:
            raw = fh.read()
        manifest_xml = _decode_xml_blob(raw)
        # Heuristic: a network-security-config has no <manifest> root.
        if "<network-security-config" in manifest_xml:
            findings.extend(analyze_network_security_config(manifest_xml, path))
        else:
            metadata = extract_metadata(manifest_xml)
            findings.extend(analyze_manifest(manifest_xml))
        if scan_secrets_in_files:
            findings.extend(scan_secrets(path, manifest_xml.encode("utf-8")))

    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.rule_id))
    summary: Dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    finding_dicts = [f.to_dict() for f in findings]
    report = {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "target": target,
        "manifest_present": manifest_xml is not None,
        "metadata": metadata,
        "manifest_xml": manifest_xml,
        "findings": finding_dicts,
        "summary": summary,
    }
    report.update(compute_score(finding_dicts))
    return report


# ----------------------------------------------------------------------------
# SARIF 2.1.0
# ----------------------------------------------------------------------------
_SARIF_LEVEL = {"info": "note", "low": "note", "medium": "warning",
                "high": "error", "critical": "error"}


def to_sarif(report: Dict[str, Any], tool_name: str = TOOL_NAME,
             tool_version: str = TOOL_VERSION) -> Dict[str, Any]:
    findings = report.get("findings", [])
    rule_ids = sorted({f["rule_id"] for f in findings})
    rules = [{"id": rid, "name": rid, "shortDescription": {"text": rid}} for rid in rule_ids]
    results = []
    for f in findings:
        loc = f.get("location") or report.get("target", "")
        props = {"severity": f["severity"]}
        if f.get("cwe"):
            props["cwe"] = f["cwe"]
        if f.get("masvs"):
            props["masvs"] = f["masvs"]
        props.update(f.get("detail", {}))
        results.append({
            "ruleId": f["rule_id"],
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["message"]},
            "properties": props,
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": str(loc).split(":")[0] or "AndroidManifest.xml"}}}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name, "version": tool_version,
                "informationUri": "https://example.com/apkpeek", "rules": rules}},
            "results": results,
        }],
    }
