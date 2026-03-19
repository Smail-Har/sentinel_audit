"""Tests for the inventory parser."""

from __future__ import annotations

import tempfile

import pytest

from sentinel_audit.core.exceptions import InventoryError
from sentinel_audit.inventory import load_inventory


def _write_inventory(content: str) -> str:
    """Write inventory content to a temp file and return the path."""
    tmpfile = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    tmpfile.write(content)
    tmpfile.close()
    return tmpfile.name


def test_load_valid_inventory() -> None:
    content = """
defaults:
  ssh_user: auditor
  ssh_port: 22

targets:
  - host: 192.168.1.10
    label: web-server
  - host: 192.168.1.20
    label: db-server
    ssh_user: admin
"""
    targets = load_inventory(_write_inventory(content))
    assert len(targets) == 2
    assert targets[0].host == "192.168.1.10"
    assert targets[0].ssh_user == "auditor"
    assert targets[1].ssh_user == "admin"  # Override


def test_missing_host_raises() -> None:
    content = """
targets:
  - label: no-host-here
"""
    with pytest.raises(InventoryError, match="missing required 'host'"):
        load_inventory(_write_inventory(content))


def test_empty_targets_raises() -> None:
    content = """
targets: []
"""
    with pytest.raises(InventoryError, match="no targets"):
        load_inventory(_write_inventory(content))


def test_missing_file_raises() -> None:
    with pytest.raises(InventoryError, match="not found"):
        load_inventory("/nonexistent/file.yaml")


def test_defaults_merge_correctly() -> None:
    content = """
defaults:
  ssh_key: ~/.ssh/id_ed25519
  ssh_port: 2222

targets:
  - host: 10.0.0.1
    ssh_port: 22
"""
    targets = load_inventory(_write_inventory(content))
    assert targets[0].ssh_port == 22  # Override
    assert targets[0].ssh_key is not None
    assert "id_ed25519" in targets[0].ssh_key
