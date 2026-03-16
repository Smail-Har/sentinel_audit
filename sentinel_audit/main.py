"""Entrypoint for running SentinelAudit as a module."""

from __future__ import annotations

import sys

from sentinel_audit.cli import main


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
