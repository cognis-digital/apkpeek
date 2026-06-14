"""Smoke test for apkpeek - import, identity, CLI module. Standard library only."""
import importlib

import pytest


def test_package_imports():
    assert importlib.import_module("apkpeek") is not None


def test_identity_metadata():
    m = importlib.import_module("apkpeek")
    if hasattr(m, "TOOL_NAME"):
        assert m.TOOL_NAME
    if hasattr(m, "TOOL_VERSION"):
        assert isinstance(m.TOOL_VERSION, str) and m.TOOL_VERSION


def test_cli_module_loads():
    try:
        cli = importlib.import_module("apkpeek.cli")
    except ModuleNotFoundError:
        pytest.skip("no cli module")
    assert hasattr(cli, "main")
