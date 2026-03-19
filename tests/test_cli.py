"""Tests for CLI argument parsing."""

from __future__ import annotations

from sentinel_audit.cli import build_parser


def test_audit_command_with_target() -> None:
    parser = build_parser()
    args = parser.parse_args(["audit", "--target", "192.168.1.1"])
    assert args.command == "audit"
    assert args.target == "192.168.1.1"
    assert args.inventory is None


def test_audit_command_with_inventory() -> None:
    parser = build_parser()
    args = parser.parse_args(["audit", "--inventory", "hosts.yaml"])
    assert args.command == "audit"
    assert args.inventory == "hosts.yaml"
    assert args.target is None


def test_modules_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["modules"])
    assert args.command == "modules"


def test_default_mode_is_remote() -> None:
    parser = build_parser()
    args = parser.parse_args(["audit", "--target", "host"])
    assert args.mode == "remote"


def test_format_default_is_all() -> None:
    parser = build_parser()
    args = parser.parse_args(["audit", "--target", "host"])
    assert args.format == "all"
