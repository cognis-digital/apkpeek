"""APKPEEK core engine — a zero-install Android manifest & APK security analyzer.

In the spirit of MobSF, this module performs a *static* security review of an
Android application package without any third-party dependencies.  It can read:

  * a real ``.apk`` (a ZIP archive — we pull ``AndroidManifest.xml`` and any
    ``classes*.dex`` / ``resources.arsc`` out of it),
  * a raw binary ``AndroidManifest.xml`` (Android's compiled AXML format), or
  * a plain-text / decoded ``AndroidManifest.xml``.

It then runs a bundled rule pack to surface:

  * exported components (activity / service / receiver / provider) that are
    reachable by other apps,
  * dangerous / signature-level permissions the app requests,
  * the ``debuggable`` and ``allowBackup`` application flags,
  * cleartext-traffic configuration (``usesCleartextTraffic`` / network-security
    config / API-level defaults),
  * hard-coded secret strings (API keys, tokens, private keys) found in the
    manifest and in DEX/resource string tables.

Everything here is the Python standard library only.
"""

from __future__ import annotations

import base64
import math
import re
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Iterable

TOOL_NAME = "apkpeek"
TOOL_VERSION = "1.0.0"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---------------------------------------------------------------------------
# Bundled data: Android dangerous / signature permission catalog
# ---------------------------------------------------------------------------
# Protection level for the AOSP framework permissions most relevant to a
# security review.  "dangerous" perms gate user data; "signature" perms are
# normally reserved for system/OEM apps and are a red flag in a 3rd-party app.
PERMISSION_CATALOG: dict[str, dict[str, str]] = {
    # --- runtime "dangerous" permissions (user-granted) -------------------
    "READ_CALENDAR": {"level": "dangerous", "group": "CALENDAR"},
    "WRITE_CALENDAR": {"level": "dangerous", "group": "CALENDAR"},
    "CAMERA": {"level": "dangerous", "group": "CAMERA"},
    "READ_CONTACTS": {"level": "dangerous", "group": "CONTACTS"},
    "WRITE_CONTACTS": {"level": "dangerous", "group": "CONTACTS"},
    "GET_ACCOUNTS": {"level": "dangerous", "group": "CONTACTS"},
    "ACCESS_FINE_LOCATION": {"level": "dangerous", "group": "LOCATION"},
    "ACCESS_COARSE_LOCATION": {"level": "dangerous", "group": "LOCATION"},
    "ACCESS_BACKGROUND_LOCATION": {"level": "dangerous", "group": "LOCATION"},
    "RECORD_AUDIO": {"level": "dangerous", "group": "MICROPHONE"},
    "READ_PHONE_STATE": {"level": "dangerous", "group": "PHONE"},
    "READ_PHONE_NUMBERS": {"level": "dangerous", "group": "PHONE"},
    "CALL_PHONE": {"level": "dangerous", "group": "PHONE"},
    "ANSWER_PHONE_CALLS": {"level": "dangerous", "group": "PHONE"},
    "READ_CALL_LOG": {"level": "dangerous", "group": "CALL_LOG"},
    "WRITE_CALL_LOG": {"level": "dangerous", "group": "CALL_LOG"},
    "PROCESS_OUTGOING_CALLS": {"level": "dangerous", "group": "CALL_LOG"},
    "BODY_SENSORS": {"level": "dangerous", "group": "SENSORS"},
    "ACTIVITY_RECOGNITION": {"level": "dangerous", "group": "ACTIVITY_RECOGNITION"},
    "SEND_SMS": {"level": "dangerous", "group": "SMS"},
    "RECEIVE_SMS": {"level": "dangerous", "group": "SMS"},
    "READ_SMS": {"level": "dangerous", "group": "SMS"},
    "RECEIVE_WAP_PUSH": {"level": "dangerous", "group": "SMS"},
    "RECEIVE_MMS": {"level": "dangerous", "group": "SMS"},
    "READ_EXTERNAL_STORAGE": {"level": "dangerous", "group": "STORAGE"},
    "WRITE_EXTERNAL_STORAGE": {"level": "dangerous", "group": "STORAGE"},
    "ACCESS_MEDIA_LOCATION": {"level": "dangerous", "group": "STORAGE"},
    "READ_MEDIA_IMAGES": {"level": "dangerous", "group": "STORAGE"},
    "READ_MEDIA_VIDEO": {"level": "dangerous", "group": "STORAGE"},
    "READ_MEDIA_AUDIO": {"level": "dangerous", "group": "STORAGE"},
    "BLUETOOTH_CONNECT": {"level": "dangerous", "group": "NEARBY_DEVICES"},
    "BLUETOOTH_SCAN": {"level": "dangerous", "group": "NEARBY_DEVICES"},
    "UWB_RANGING": {"level": "dangerous", "group": "NEARBY_DEVICES"},
    "POST_NOTIFICATIONS": {"level": "dangerous", "group": "NOTIFICATIONS"},
    # --- signature / system permissions (suspicious in a 3rd-party app) ----
    "INSTALL_PACKAGES": {"level": "signature", "group": "SYSTEM"},
    "DELETE_PACKAGES": {"level": "signature", "group": "SYSTEM"},
    "WRITE_SECURE_SETTINGS": {"level": "signature", "group": "SYSTEM"},
    "MOUNT_UNMOUNT_FILESYSTEMS": {"level": "signature", "group": "SYSTEM"},
    "READ_LOGS": {"level": "signature", "group": "SYSTEM"},
    "MANAGE_EXTERNAL_STORAGE": {"level": "signature", "group": "STORAGE"},
    "BIND_DEVICE_ADMIN": {"level": "signature", "group": "SYSTEM"},
    "BIND_ACCESSIBILITY_SERVICE": {"level": "signature", "group": "SYSTEM"},
    "SYSTEM_ALERT_WINDOW": {"level": "signature", "group": "OVERLAY"},
    "REQUEST_INSTALL_PACKAGES": {"level": "normal", "group": "SYSTEM"},
    "PACKAGE_USAGE_STATS": {"level": "signature", "group": "SYSTEM"},
    "CAPTURE_AUDIO_OUTPUT": {"level": "signature", "group": "SYSTEM"},
    "MODIFY_PHONE_STATE": {"level": "signature", "group": "SYSTEM"},
}

# Permissions that, while documented as signature, are commonly abused by
# malware / spyware to gain persistent control.  Surfaced at critical.
HIGH_RISK_PERMISSIONS = {
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "SYSTEM_ALERT_WINDOW",
    "INSTALL_PACKAGES",
    "REQUEST_INSTALL_PACKAGES",
    "WRITE_SECURE_SETTINGS",
    "MANAGE_EXTERNAL_STORAGE",
    "READ_SMS",
    "RECEIVE_SMS",
    "READ_CALL_LOG",
}


# ---------------------------------------------------------------------------
# Bundled data: secret-string rule pack
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SecretRule:
    id: str
    description: str
    severity: str
    regex: "re.Pattern[str]"


def _r(pat: str) -> "re.Pattern[str]":
    return re.compile(pat)


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule("aws-access-key", "AWS Access Key ID", "critical",
               _r(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    SecretRule("aws-secret-key", "AWS Secret Access Key (heuristic)", "critical",
               _r(r"(?i)aws(.{0,20})?(secret|sk)[\"'\s:=]+([A-Za-z0-9/+]{40})\b")),
    SecretRule("google-api-key", "Google API key", "high",
               _r(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    SecretRule("google-oauth", "Google OAuth client id", "medium",
               _r(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b")),
    SecretRule("firebase-db", "Firebase database URL", "medium",
               _r(r"\bhttps://[a-z0-9\-]+\.firebaseio\.com\b")),
    SecretRule("gcm-fcm-key", "Firebase/GCM legacy server key", "high",
               _r(r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b")),
    SecretRule("slack-token", "Slack token", "high",
               _r(r"\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b")),
    SecretRule("slack-webhook", "Slack incoming webhook", "medium",
               _r(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+")),
    SecretRule("github-pat", "GitHub personal access token", "critical",
               _r(r"\bghp_[0-9A-Za-z]{36}\b")),
    SecretRule("github-fine", "GitHub fine-grained token", "critical",
               _r(r"\bgithub_pat_[0-9A-Za-z_]{82}\b")),
    SecretRule("stripe-secret", "Stripe secret key", "critical",
               _r(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}\b")),
    SecretRule("stripe-pub", "Stripe publishable key", "low",
               _r(r"\bpk_(?:live|test)_[0-9A-Za-z]{24,}\b")),
    SecretRule("twilio-sid", "Twilio account SID", "high",
               _r(r"\bAC[0-9a-fA-F]{32}\b")),
    SecretRule("sendgrid", "SendGrid API key", "high",
               _r(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b")),
    SecretRule("mailgun", "Mailgun API key", "high",
               _r(r"\bkey-[0-9a-f]{32}\b")),
    SecretRule("jwt", "JSON Web Token", "medium",
               _r(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    SecretRule("private-key", "Private key block", "critical",
               _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    SecretRule("generic-secret", "Generic hard-coded secret assignment", "medium",
               _r(r"(?i)(api[_\-]?key|secret|passwd|password|token|auth)"
                  r"[\"'\s]{0,3}[:=][\"'\s]{0,3}([A-Za-z0-9_\-]{12,})")),
    SecretRule("base64-blob", "High-entropy base64 blob", "low",
               _r(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")),
)

# tokens that look like secrets but are framework constants / placeholders
SECRET_STOPWORDS = {
    "android", "androidx", "example", "placeholder", "changeme", "your_api_key",
    "true", "false", "null", "string", "drawable", "mipmap", "layout",
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------------------------------------------------------------------------
# Binary AXML decoder (Android compiled XML chunk format)
# ---------------------------------------------------------------------------
# Reference: frameworks/base ResourceTypes.h.  We implement just enough of the
# chunk parser to recover element names, attribute names and attribute values
# from a compiled AndroidManifest.xml.
_RES_STRING_POOL = 0x0001
_RES_XML_TYPE = 0x0003
_RES_XML_START_ELEMENT = 0x0102
_RES_XML_END_ELEMENT = 0x0103
_RES_XML_RES_MAP = 0x0180

# common android: attribute resource ids -> name (subset we care about)
_ATTR_RES_NAMES = {
    0x01010003: "name",
    0x01010010: "permission",
    0x0101001a: "exported",
    0x0101001b: "process",
    0x0101001d: "debuggable",
    0x01010280: "allowBackup",
    0x0101048c: "usesCleartextTraffic",
    0x0101054c: "networkSecurityConfig",
    0x01010571: "roundIcon",
}


class _AxmlError(ValueError):
    pass


def _read_string_pool(buf: bytes, off: int) -> tuple[list[str], int]:
    typ, hdr_size, size = struct.unpack_from("<HHI", buf, off)
    if typ != _RES_STRING_POOL:
        raise _AxmlError("expected string pool")
    string_count, _style_count, flags, strings_start, _styles_start = \
        struct.unpack_from("<IIIII", buf, off + 8)
    is_utf8 = bool(flags & (1 << 8))
    offsets = [struct.unpack_from("<I", buf, off + 28 + i * 4)[0]
               for i in range(string_count)]
    base = off + strings_start
    out: list[str] = []
    for o in offsets:
        p = base + o
        if is_utf8:
            # u16 length (chars) then u16 length (bytes), each may be 1-2 bytes
            n, p = _decode_len8(buf, p)
            blen, p = _decode_len8(buf, p)
            out.append(buf[p:p + blen].decode("utf-8", "replace"))
        else:
            n, p = _decode_len16(buf, p)
            out.append(buf[p:p + n * 2].decode("utf-16-le", "replace"))
    return out, off + size


def _decode_len8(buf: bytes, p: int) -> tuple[int, int]:
    v = buf[p]
    p += 1
    if v & 0x80:
        v = ((v & 0x7F) << 8) | buf[p]
        p += 1
    return v, p


def _decode_len16(buf: bytes, p: int) -> tuple[int, int]:
    v = struct.unpack_from("<H", buf, p)[0]
    p += 2
    if v & 0x8000:
        hi = v & 0x7FFF
        lo = struct.unpack_from("<H", buf, p)[0]
        p += 2
        v = (hi << 16) | lo
    return v, p


def is_binary_axml(data: bytes) -> bool:
    if len(data) < 8:
        return False
    typ, _hdr, _size = struct.unpack_from("<HHI", data, 0)
    return typ == _RES_XML_TYPE


@dataclass
class XmlElement:
    name: str
    attrs: dict[str, str]


def decode_binary_axml(data: bytes) -> list[XmlElement]:
    """Decode a compiled AndroidManifest.xml into a flat list of start elements
    (each with its resolved attribute name->value map)."""
    typ, hdr_size, total = struct.unpack_from("<HHI", data, 0)
    if typ != _RES_XML_TYPE:
        raise _AxmlError("not a binary XML resource")
    off = hdr_size
    strings: list[str] = []
    elements: list[XmlElement] = []

    def s(idx: int) -> str:
        if 0 <= idx < len(strings):
            return strings[idx]
        return ""

    while off + 8 <= len(data):
        c_type, c_hdr, c_size = struct.unpack_from("<HHI", data, off)
        if c_size <= 0:
            break
        if c_type == _RES_STRING_POOL:
            strings, _ = _read_string_pool(data, off)
        elif c_type == _RES_XML_START_ELEMENT:
            body = off + c_hdr
            ns_idx, name_idx = struct.unpack_from("<ii", data, body)
            attr_start, attr_size, attr_count = \
                struct.unpack_from("<HHH", data, body + 8)
            ap = body + attr_start
            attrs: dict[str, str] = {}
            for _ in range(attr_count):
                a_ns, a_name, a_raw, a_typed_size_res0, a_data = \
                    struct.unpack_from("<iiiiI", data, ap)
                # attribute name: prefer the resource-id map name when the
                # string-pool entry is blank (common in compiled manifests)
                aname = s(a_name)
                if not aname and a_name < len(_res_map):
                    aname = _ATTR_RES_NAMES.get(_res_map[a_name], "")
                value = _decode_attr_value(a_raw, a_typed_size_res0, a_data, s)
                if aname:
                    attrs[aname] = value
                ap += 20
            elements.append(XmlElement(s(name_idx), attrs))
        off += c_size

    return elements


# resource-map chunk lets us map attribute name indices -> android attr ids
_res_map: list[int] = []


def _decode_attr_value(raw_idx: int, typed_size_res0: int, data: int,
                       s) -> str:
    # the typed value's data type is the high byte of typed_size_res0
    vtype = (typed_size_res0 >> 24) & 0xFF
    if raw_idx >= 0:
        return s(raw_idx)
    if vtype == 0x12:  # TYPE_INT_BOOLEAN
        return "true" if data != 0 else "false"
    if vtype in (0x10, 0x11):  # int dec / hex
        return str(data)
    if vtype == 0x03:  # string (rare when raw_idx < 0)
        return s(data)
    return str(data)


def decode_binary_axml_full(data: bytes) -> list[XmlElement]:
    """Wrapper that also parses the resource-map chunk before elements so we can
    resolve android: attribute names that compile to empty string-pool slots."""
    global _res_map
    _res_map = []
    typ, hdr_size, total = struct.unpack_from("<HHI", data, 0)
    off = hdr_size
    while off + 8 <= len(data):
        c_type, c_hdr, c_size = struct.unpack_from("<HHI", data, off)
        if c_size <= 0:
            break
        if c_type == _RES_XML_RES_MAP:
            count = (c_size - c_hdr) // 4
            _res_map = list(struct.unpack_from("<%dI" % count, data, off + c_hdr))
            break
        off += c_size
    return decode_binary_axml(data)


# ---------------------------------------------------------------------------
# Manifest model
# ---------------------------------------------------------------------------
@dataclass
class Component:
    kind: str               # activity|service|receiver|provider
    name: str
    exported: bool
    has_intent_filter: bool
    permission: str | None


@dataclass
class Manifest:
    package: str = ""
    min_sdk: int | None = None
    target_sdk: int | None = None
    debuggable: bool = False
    allow_backup: bool = True       # AOSP default is true
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    permissions: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)


def _strip_android_prefix(name: str) -> str:
    if name.startswith("android.permission."):
        return name[len("android.permission."):]
    return name.rsplit(".", 1)[-1] if "." in name else name


def _parse_bool(v: str | None) -> bool | None:
    if v is None:
        return None
    return str(v).strip().lower() in ("true", "1")


def parse_manifest_from_elements(elements: list[XmlElement]) -> Manifest:
    m = Manifest()
    for el in elements:
        nm = el.name.split("}")[-1]
        a = el.attrs
        if nm == "manifest":
            m.package = a.get("package", m.package)
        elif nm == "uses-sdk":
            if a.get("minSdkVersion"):
                m.min_sdk = _safe_int(a["minSdkVersion"])
            if a.get("targetSdkVersion"):
                m.target_sdk = _safe_int(a["targetSdkVersion"])
        elif nm == "uses-permission" or nm == "uses-permission-sdk-23":
            perm = a.get("name") or a.get("{http://schemas.android.com/apk/res/android}name")
            if perm:
                m.permissions.append(perm)
        elif nm == "application":
            m.debuggable = _parse_bool(a.get("debuggable")) or False
            ab = _parse_bool(a.get("allowBackup"))
            m.allow_backup = True if ab is None else ab
            m.uses_cleartext_traffic = _parse_bool(a.get("usesCleartextTraffic"))
            m.network_security_config = a.get("networkSecurityConfig")
        elif nm in ("activity", "activity-alias", "service", "receiver", "provider"):
            kind = "activity" if nm == "activity-alias" else nm
            name = a.get("name", "")
            exported = _parse_bool(a.get("exported"))
            comp = Component(
                kind=kind, name=name,
                exported=bool(exported) if exported is not None else False,
                has_intent_filter=False,
                permission=a.get("permission"),
            )
            comp._exported_explicit = exported  # type: ignore[attr-defined]
            m.components.append(comp)
        elif nm == "intent-filter":
            if m.components:
                m.components[-1].has_intent_filter = True
    # resolve implicit exported: a component with an intent-filter is exported
    # by default (and providers default exported=true pre-API17).
    for c in m.components:
        explicit = getattr(c, "_exported_explicit", None)
        if explicit is None:
            c.exported = c.has_intent_filter
    return m


def parse_manifest_text(text: str) -> Manifest:
    """Parse a decoded plain-text AndroidManifest.xml using xml.etree, while
    preserving android: attribute names."""
    import xml.etree.ElementTree as ET
    ns = "{http://schemas.android.com/apk/res/android}"
    root = ET.fromstring(text)
    elements: list[XmlElement] = []

    def attrs_of(node) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in node.attrib.items():
            out[k.replace(ns, "")] = v
        return out

    def walk(node):
        elements.append(XmlElement(node.tag.split("}")[-1], attrs_of(node)))
        for ch in list(node):
            walk(ch)

    walk(root)
    return parse_manifest_from_elements(elements)


def _safe_int(v) -> int | None:
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Findings + engine
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    where: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id, "severity": self.severity, "title": self.title,
            "detail": self.detail, "where": self.where,
        }


def _printable_strings(blob: bytes, min_len: int = 6) -> Iterable[str]:
    cur = bytearray()
    for b in blob:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                yield cur.decode("ascii", "replace")
            cur = bytearray()
    if len(cur) >= min_len:
        yield cur.decode("ascii", "replace")


class Engine:
    """The static analysis engine.  Feed it a Manifest plus optional raw bytes
    (DEX / resources) and it returns a list of Findings."""

    def __init__(self, secret_entropy_threshold: float = 4.0):
        self.secret_entropy_threshold = secret_entropy_threshold

    # -- component / permission / flag analysis ---------------------------
    def analyze_manifest(self, m: Manifest) -> list[Finding]:
        out: list[Finding] = []
        out += self._check_flags(m)
        out += self._check_cleartext(m)
        out += self._check_permissions(m)
        out += self._check_components(m)
        return out

    def _check_flags(self, m: Manifest) -> list[Finding]:
        out = []
        if m.debuggable:
            out.append(Finding(
                "flag-debuggable", "critical",
                "Application is debuggable",
                "android:debuggable=\"true\" ships a debug build; any device "
                "user can attach jdwp and read app memory / inject code.",
                where="<application>"))
        if m.allow_backup:
            out.append(Finding(
                "flag-allowbackup", "medium",
                "Backup of application data allowed",
                "android:allowBackup defaults to true; an attacker with adb can "
                "extract the app's private data via `adb backup`. Set it to false.",
                where="<application>"))
        return out

    def _check_cleartext(self, m: Manifest) -> list[Finding]:
        out = []
        if m.uses_cleartext_traffic is True:
            out.append(Finding(
                "cleartext-explicit", "high",
                "Cleartext (HTTP) traffic explicitly enabled",
                "android:usesCleartextTraffic=\"true\" allows unencrypted HTTP, "
                "exposing data to MITM on hostile networks.",
                where="<application>"))
        elif m.uses_cleartext_traffic is None and m.network_security_config is None:
            # default: cleartext is permitted for apps targeting < API 28
            tgt = m.target_sdk or 0
            if tgt < 28:
                out.append(Finding(
                    "cleartext-default", "medium",
                    "Cleartext traffic permitted by default",
                    f"targetSdkVersion={tgt or 'unset'} (<28) and no "
                    "networkSecurityConfig, so cleartext HTTP is allowed by "
                    "default. Add a network-security config that disables it.",
                    where="<application>"))
        return out

    def _check_permissions(self, m: Manifest) -> list[Finding]:
        out = []
        for perm in sorted(set(m.permissions)):
            short = _strip_android_prefix(perm)
            meta = PERMISSION_CATALOG.get(short)
            if not meta:
                continue
            level = meta["level"]
            if short in HIGH_RISK_PERMISSIONS:
                sev = "critical" if level == "signature" else "high"
                out.append(Finding(
                    "perm-high-risk", sev,
                    f"High-risk permission: {short}",
                    f"{perm} ({level}, group {meta['group']}) is frequently "
                    "abused by spyware/banking trojans; confirm it is required.",
                    where="<uses-permission>"))
            elif level == "signature":
                out.append(Finding(
                    "perm-signature", "high",
                    f"Signature/system permission requested: {short}",
                    f"{perm} is normally reserved for system apps and will be "
                    "denied to a regular 3rd-party install.",
                    where="<uses-permission>"))
            elif level == "dangerous":
                out.append(Finding(
                    "perm-dangerous", "low",
                    f"Dangerous permission: {short}",
                    f"{perm} (group {meta['group']}) gates user data and "
                    "requires a runtime grant.",
                    where="<uses-permission>"))
        return out

    def _check_components(self, m: Manifest) -> list[Finding]:
        out = []
        for c in m.components:
            if not c.exported:
                continue
            unprotected = not c.permission
            sev = "high" if unprotected else "medium"
            if c.kind == "provider" and unprotected:
                sev = "critical"
            prot = "without a permission guard" if unprotected else \
                f"guarded by permission '{c.permission}'"
            out.append(Finding(
                "exported-component", sev,
                f"Exported {c.kind}: {c.name or '(unnamed)'}",
                f"This {c.kind} is reachable by other apps ({prot})"
                + (" via an intent-filter" if c.has_intent_filter else "")
                + ". Set android:exported=\"false\" or add a permission if it is "
                  "not meant to be a public entry point.",
                where=f"<{c.kind}>"))
        return out

    # -- secret scanning --------------------------------------------------
    def scan_secrets(self, text: str, where: str) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for rule in SECRET_RULES:
            for mobj in rule.regex.finditer(text):
                token = mobj.group(mobj.lastindex or 0)
                if not token:
                    continue
                low = token.lower()
                if low in SECRET_STOPWORDS or low.endswith(("/string", "/layout")):
                    continue
                if rule.id in ("base64-blob", "generic-secret"):
                    # entropy gate to suppress noise
                    cand = token
                    if rule.id == "base64-blob":
                        try:
                            base64.b64decode(cand + "=" * (-len(cand) % 4))
                        except Exception:
                            continue
                    if shannon_entropy(cand) < self.secret_entropy_threshold:
                        continue
                key = (rule.id, token[:24])
                if key in seen:
                    continue
                seen.add(key)
                out.append(Finding(
                    f"secret-{rule.id}", rule.severity,
                    f"Hard-coded secret: {rule.description}",
                    f"Matched `{_redact(token)}` (entropy "
                    f"{shannon_entropy(token):.2f}).",
                    where=where))
        return out

    def scan_blob_secrets(self, blob: bytes, where: str) -> list[Finding]:
        joined = "\n".join(_printable_strings(blob))
        return self.scan_secrets(joined, where)


def _redact(token: str) -> str:
    if len(token) <= 10:
        return token[:2] + "***"
    return token[:6] + "***" + token[-4:]


# ---------------------------------------------------------------------------
# Top-level analyze() entry point
# ---------------------------------------------------------------------------
@dataclass
class Report:
    target: str
    manifest: Manifest
    findings: list[Finding]

    def as_dict(self) -> dict:
        return {
            "tool": TOOL_NAME, "version": TOOL_VERSION, "target": self.target,
            "package": self.manifest.package,
            "min_sdk": self.manifest.min_sdk,
            "target_sdk": self.manifest.target_sdk,
            "debuggable": self.manifest.debuggable,
            "allow_backup": self.manifest.allow_backup,
            "permissions": sorted(set(self.manifest.permissions)),
            "components": [
                {"kind": c.kind, "name": c.name, "exported": c.exported,
                 "intent_filter": c.has_intent_filter, "permission": c.permission}
                for c in self.manifest.components
            ],
            "findings": [f.as_dict() for f in self.findings],
            "summary": summarize(self.findings),
        }


def summarize(findings: list[Finding]) -> dict[str, int]:
    out = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    out["total"] = len(findings)
    return out


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9),
                                           f.id, f.where))


def manifest_from_bytes(data: bytes) -> Manifest:
    if is_binary_axml(data):
        return parse_manifest_from_elements(decode_binary_axml_full(data))
    text = data.decode("utf-8", "replace")
    return parse_manifest_text(text)


def analyze_apk(path: str, scan_dex: bool = True,
                entropy: float = 4.0) -> Report:
    """Analyze a real .apk (ZIP) file."""
    engine = Engine(secret_entropy_threshold=entropy)
    findings: list[Finding] = []
    manifest = Manifest()
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        if "AndroidManifest.xml" in names:
            data = zf.read("AndroidManifest.xml")
            manifest = manifest_from_bytes(data)
            findings += engine.analyze_manifest(manifest)
            # also string-scan the (possibly binary) manifest
            findings += engine.scan_blob_secrets(data, "AndroidManifest.xml")
        if scan_dex:
            for n in names:
                if n.endswith(".dex") or n == "resources.arsc" or \
                        n.startswith("res/") and n.endswith((".xml", ".json")):
                    try:
                        blob = zf.read(n)
                    except KeyError:
                        continue
                    findings += engine.scan_blob_secrets(blob, n)
    return Report(path, manifest, sort_findings(findings))


def analyze_manifest_file(path: str, entropy: float = 4.0) -> Report:
    """Analyze a standalone AndroidManifest.xml (binary or text)."""
    engine = Engine(secret_entropy_threshold=entropy)
    with open(path, "rb") as fh:
        data = fh.read()
    manifest = manifest_from_bytes(data)
    findings = engine.analyze_manifest(manifest)
    findings += engine.scan_blob_secrets(data, path)
    return Report(path, manifest, sort_findings(findings))


def analyze(path: str, scan_dex: bool = True, entropy: float = 4.0) -> Report:
    """Dispatch on file type: .apk (zip) vs a raw manifest."""
    if zipfile.is_zipfile(path):
        return analyze_apk(path, scan_dex=scan_dex, entropy=entropy)
    return analyze_manifest_file(path, entropy=entropy)
