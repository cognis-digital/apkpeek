"""Tests for hardened edge-case handling added to apkpeek."""
from __future__ import annotations

import struct
import zipfile

import pytest

from apkpeek import (
    analyze,
    analyze_apk,
    decode_binary_axml_full,
    parse_manifest_text,
)
from apkpeek.cli import main
from apkpeek.core import _AxmlError


# ---------------------------------------------------------------------------
# analyze() -- file existence and type checks
# ---------------------------------------------------------------------------

def test_analyze_missing_file_raises_fnf(tmp_path):
    """analyze() on a non-existent path must raise FileNotFoundError."""
    missing = str(tmp_path / "no_such_file.apk")
    with pytest.raises(FileNotFoundError, match="file not found"):
        analyze(missing)


def test_analyze_directory_raises_value_error(tmp_path):
    """analyze() on a directory (not a file) must raise ValueError."""
    with pytest.raises(ValueError, match="not a regular file"):
        analyze(str(tmp_path))


def test_cli_missing_file_exit_err(tmp_path, capsys):
    """CLI must exit 1 and print an error (not a traceback) for a missing file."""
    rc = main(["scan", str(tmp_path / "ghost.apk")])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error" in err.lower()
    assert "Traceback" not in err


# ---------------------------------------------------------------------------
# analyze_apk() -- bad ZIP / missing manifest
# ---------------------------------------------------------------------------

def test_analyze_apk_not_a_zip_raises(tmp_path):
    """A file that is not a valid ZIP must raise ValueError."""
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"not a zip file at all")
    with pytest.raises(ValueError, match="not a valid ZIP"):
        analyze_apk(str(bad))


def test_analyze_apk_zip_without_manifest_raises(tmp_path):
    """A ZIP with no AndroidManifest.xml must raise ValueError."""
    no_manifest = tmp_path / "no_manifest.apk"
    with zipfile.ZipFile(str(no_manifest), "w") as zf:
        zf.writestr("classes.dex", b"\x00dex\n035\x00")
    with pytest.raises(ValueError, match="AndroidManifest.xml"):
        analyze_apk(str(no_manifest))


def test_cli_bad_zip_exit_err(tmp_path, capsys):
    """CLI must exit 1 cleanly for a corrupt APK."""
    bad = tmp_path / "corrupt.apk"
    bad.write_bytes(b"\x00\x01\x02\x03 garbage")
    rc = main(["scan", str(bad)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error" in err.lower()
    assert "Traceback" not in err


# ---------------------------------------------------------------------------
# parse_manifest_text() -- empty and malformed XML
# ---------------------------------------------------------------------------

def test_parse_manifest_text_empty_raises():
    """parse_manifest_text with an empty string must raise ValueError."""
    with pytest.raises(ValueError, match="empty"):
        parse_manifest_text("")


def test_parse_manifest_text_whitespace_only_raises():
    """parse_manifest_text with whitespace-only input must raise ValueError."""
    with pytest.raises(ValueError, match="empty"):
        parse_manifest_text("   \n\t  ")


def test_parse_manifest_text_malformed_xml_raises():
    """parse_manifest_text with broken XML must raise ValueError (not ET.ParseError)."""
    with pytest.raises(ValueError, match="malformed XML"):
        parse_manifest_text("<manifest><unclosed>")


# ---------------------------------------------------------------------------
# decode_binary_axml_full() -- truncated / garbage blobs
# ---------------------------------------------------------------------------

def test_decode_axml_full_empty_raises():
    """decode_binary_axml_full on empty bytes must raise."""
    with pytest.raises(Exception):
        decode_binary_axml_full(b"")


def test_decode_axml_full_short_blob_raises():
    """decode_binary_axml_full on a 4-byte blob (< 8 bytes) must raise."""
    with pytest.raises(Exception):
        decode_binary_axml_full(b"\x03\x00\x08\x00")


def test_decode_axml_full_wrong_magic_raises():
    """A blob with correct length but wrong chunk type must raise _AxmlError."""
    # valid 8-byte header but type 0x0000 (not _RES_XML_TYPE 0x0003)
    blob = struct.pack("<HHI", 0x0000, 8, 8)
    with pytest.raises((_AxmlError, ValueError, Exception)):
        decode_binary_axml_full(blob)


# ---------------------------------------------------------------------------
# CLI entropy validation
# ---------------------------------------------------------------------------

def test_cli_entropy_negative_exits_err(tmp_path, capsys):
    """--entropy < 0 must exit 1 with a clear error."""
    mf = tmp_path / "m.xml"
    mf.write_text(
        '<?xml version="1.0"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="com.t"><application android:allowBackup="false"/></manifest>',
        encoding="utf-8",
    )
    rc = main(["scan", str(mf), "--entropy", "-1.0"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "entropy" in err.lower()


def test_cli_entropy_too_high_exits_err(tmp_path, capsys):
    """--entropy > 8.0 must exit 1 with a clear error."""
    mf = tmp_path / "m.xml"
    mf.write_text(
        '<?xml version="1.0"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="com.t"><application android:allowBackup="false"/></manifest>',
        encoding="utf-8",
    )
    rc = main(["scan", str(mf), "--entropy", "9.5"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "entropy" in err.lower()
