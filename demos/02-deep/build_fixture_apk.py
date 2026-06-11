"""Build a real .apk fixture (a ZIP) containing a *binary* AndroidManifest.xml
(compiled AXML) and a fake classes.dex blob with embedded secrets.

This produces ``leakybank.apk`` next to this script so the deep test can prove
the AXML decoder and DEX string scanner work end to end. Standard library only.
"""

from __future__ import annotations

import os
import struct
import zipfile


# --- minimal AXML encoder ---------------------------------------------------
# We emit a compiled AndroidManifest.xml with a string pool, a resource map and
# a sequence of START/END element chunks. Only what apkpeek's decoder reads.
_RES_STRING_POOL = 0x0001
_RES_XML_TYPE = 0x0003
_RES_XML_START = 0x0102
_RES_XML_END = 0x0103
_RES_XML_RESMAP = 0x0180

ATTR_RES_IDS = {
    "name": 0x01010003,
    "exported": 0x0101001a,
    "debuggable": 0x0101001d,
    "allowBackup": 0x01010280,
    "usesCleartextTraffic": 0x0101048c,
    "targetSdkVersion": 0x01010271,
    "minSdkVersion": 0x0101020c,
    "permission": 0x01010006,
}


def _enc_string(s: str) -> bytes:
    # UTF-16 encoding path (flags bit8 = 0)
    body = s.encode("utf-16-le")
    return struct.pack("<H", len(s)) + body + b"\x00\x00"


def _string_pool(strings: list[str]) -> bytes:
    offsets = []
    data = b""
    for s in strings:
        offsets.append(len(data))
        data += _enc_string(s)
    string_count = len(strings)
    header_size = 28
    strings_start = header_size + 4 * string_count
    size = strings_start + len(data)
    if size % 4:
        pad = 4 - (size % 4)
        data += b"\x00" * pad
        size += pad
    chunk = struct.pack("<HHI", _RES_STRING_POOL, header_size, size)
    chunk += struct.pack("<IIIII", string_count, 0, 0, strings_start, 0)
    for o in offsets:
        chunk += struct.pack("<I", o)
    chunk += data
    return chunk


def _resmap(res_ids: list[int]) -> bytes:
    header_size = 8
    size = header_size + 4 * len(res_ids)
    chunk = struct.pack("<HHI", _RES_XML_RESMAP, header_size, size)
    for r in res_ids:
        chunk += struct.pack("<I", r)
    return chunk


TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOL = 0x12


def _start_element(sp: dict[str, int], name: str,
                   attrs: list[tuple[str, object]]) -> bytes:
    header_size = 16
    attr_blocks = b""
    for aname, val in attrs:
        a_ns = -1
        a_name = sp[aname]
        if isinstance(val, bool):
            raw = -1
            typed = (TYPE_INT_BOOL << 24) | 0x08
            data = 0xFFFFFFFF if val else 0
        elif isinstance(val, int):
            raw = -1
            typed = (TYPE_INT_DEC << 24) | 0x08
            data = val
        else:
            raw = sp[val]
            typed = (TYPE_STRING << 24) | 0x08
            data = sp[val]
        attr_blocks += struct.pack("<iiiiI", a_ns, a_name, raw, typed, data)
    body = struct.pack("<ii", -1, sp[name])           # ns, name
    body += struct.pack("<HHH", 20, 20, len(attrs))    # attr_start, size, count
    body += struct.pack("<HHH", 0, 0, 0)               # id/class/style index
    body += attr_blocks
    size = 8 + 8 + len(body)   # ResChunk_header(8) + line/comment(8) + node body
    return struct.pack("<HHI", _RES_XML_START, header_size, size) + \
        struct.pack("<ii", 0, -1) + body


def _end_element(sp: dict[str, int], name: str) -> bytes:
    header_size = 16
    size = 8 + header_size
    return struct.pack("<HHI", _RES_XML_END, header_size, size) + \
        struct.pack("<ii", 0, -1) + struct.pack("<ii", -1, sp[name])


def build_axml() -> bytes:
    # order: android-attr names first so resmap aligns with their indices
    attr_names = ["name", "exported", "debuggable", "allowBackup",
                  "usesCleartextTraffic", "targetSdkVersion", "minSdkVersion",
                  "permission"]
    other = [
        "package",
        "manifest", "uses-sdk", "uses-permission", "application",
        "activity", "service", "provider",
        "com.example.leakybank",
        "android.permission.READ_SMS", "android.permission.SEND_SMS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ".MainActivity", ".PaymentService", ".AccountProvider",
        "AIzaEXAMPLE0EXAMPLE0EXAMPLE0EXAMPLE0EXA",  # google api key in value
    ]
    strings = attr_names + other
    sp = {s: i for i, s in enumerate(strings)}
    res_ids = [ATTR_RES_IDS[a] for a in attr_names]

    body = b""
    body += _start_element(sp, "manifest",
                           [("package", "com.example.leakybank")])
    body += _start_element(sp, "uses-sdk",
                           [("minSdkVersion", 19), ("targetSdkVersion", 22)])
    body += _end_element(sp, "uses-sdk")
    for perm in ("android.permission.READ_SMS", "android.permission.SEND_SMS",
                 "android.permission.BIND_ACCESSIBILITY_SERVICE"):
        body += _start_element(sp, "uses-permission", [("name", perm)])
        body += _end_element(sp, "uses-permission")
    body += _start_element(sp, "application",
                           [("debuggable", True), ("allowBackup", True),
                            ("usesCleartextTraffic", True)])
    body += _start_element(sp, "activity",
                           [("name", ".MainActivity"), ("exported", True)])
    body += _end_element(sp, "activity")
    body += _start_element(sp, "service",
                           [("name", ".PaymentService"), ("exported", True)])
    body += _end_element(sp, "service")
    body += _start_element(sp, "provider",
                           [("name", ".AccountProvider"), ("exported", True)])
    body += _end_element(sp, "provider")
    body += _end_element(sp, "application")
    body += _end_element(sp, "manifest")

    pool = _string_pool(strings)
    rmap = _resmap(res_ids)
    inner = pool + rmap + body
    header_size = 8
    total = header_size + len(inner)
    return struct.pack("<HHI", _RES_XML_TYPE, header_size, total) + inner


# NOTE: these are obvious non-secrets (low-entropy "EXAMPLE" placeholders).
# The Stripe-shaped sample is assembled from fragments at build time so the
# full provider-prefixed token never appears verbatim in version control,
# while the bytes written into the DEX still exercise the scanner's regex.
_PH = b"EXAMPLE0" * 3 + b"00"                       # 26-char low-entropy body
_STRIPE = b"sk_" + b"live_" + _PH                   # tool matches sk_live_<24+>
_GHP = b"ghp_" + b"EXAMPLE0" * 4 + b"EXAM"          # 36-char body
_SLACK = b"xoxb-" + b"EXAMPLE0-EXAMPLE0-EXAMPLETOKEN0"

FAKE_DEX = (
    b"dex\n035\x00" + b"\x00" * 32 +
    b"\nString table:\n"
    b"https://api.leakybank.example/v1\n"
    b"stripe_secret=" + _STRIPE + b"\n"
    b"github " + _GHP + b"\n"
    b"slack " + _SLACK + b"\n"
    b"-----BEGIN RSA PRIVATE KEY-----EXAMPLE-----END RSA PRIVATE KEY-----\n"
)


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "leakybank.apk")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", build_axml())
        zf.writestr("classes.dex", FAKE_DEX)
        zf.writestr("resources.arsc", b"AIzaEXAMPLE0EXAMPLE0EXAMPLE0EXAMPLE0EXA")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
