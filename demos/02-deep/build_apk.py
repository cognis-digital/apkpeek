"""Build a real (zip-format) demo .apk from the files in this directory.

Usage:  python demos/02-deep/build_apk.py  ->  demos/02-deep/bankspy-demo.apk
Then:   python -m apkpeek scan demos/02-deep/bankspy-demo.apk
"""
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))


def build(out_path: str | None = None) -> str:
    out_path = out_path or os.path.join(HERE, "bankspy-demo.apk")
    manifest = open(os.path.join(HERE, "AndroidManifest.xml"), encoding="utf-8").read()
    nsc = open(os.path.join(HERE, "network_security_config.xml"), encoding="utf-8").read()
    secrets = open(os.path.join(HERE, "secrets.json"), encoding="utf-8").read()
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("res/xml/network_security_config.xml", nsc)
        z.writestr("assets/secrets.json", secrets)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
        z.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 16)
    return out_path


if __name__ == "__main__":
    print("built", build())
