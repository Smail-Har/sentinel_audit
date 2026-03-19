"""
sentinel_audit/inventory.py
────────────────────────────
Parse a YAML inventory file into a list of InventoryTarget objects.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

from sentinel_audit.core.exceptions import InventoryError
from sentinel_audit.core.models import InventoryTarget

logger = logging.getLogger(__name__)


def load_inventory(path: str | Path) -> list[InventoryTarget]:
    """Load and validate the inventory file.

    Args:
        path: Path to the YAML inventory file.

    Returns:
        List of InventoryTarget objects.

    Raises:
        InventoryError: If the file is invalid or unreadable.
    """
    filepath = Path(path)
    if not filepath.is_file():
        raise InventoryError(f"Inventory file not found: {filepath}")

    try:
        with open(filepath, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise InventoryError(f"Invalid YAML in inventory file: {exc}") from exc

    if not isinstance(data, dict):
        raise InventoryError("Inventory file must be a YAML mapping.")

    defaults: dict[str, Any] = data.get("defaults", {})
    targets_raw: list[dict[str, Any]] = data.get("targets", [])

    if not targets_raw:
        raise InventoryError("Inventory file contains no targets.")

    targets: list[InventoryTarget] = []
    for idx, raw in enumerate(targets_raw):
        if not isinstance(raw, dict) or "host" not in raw:
            raise InventoryError(f"Target #{idx + 1} is missing required 'host' field.")

        # Merge defaults with target-specific overrides
        ssh_key = raw.get("ssh_key", defaults.get("ssh_key"))
        if ssh_key:
            ssh_key = os.path.expanduser(ssh_key)

        target = InventoryTarget(
            host=raw["host"],
            label=raw.get("label", raw["host"]),
            ssh_user=raw.get("ssh_user", defaults.get("ssh_user", "root")),
            ssh_key=ssh_key,
            ssh_password=raw.get("ssh_password", defaults.get("ssh_password")),
            ssh_port=raw.get("ssh_port", defaults.get("ssh_port", 22)),
            modules=raw.get("modules", defaults.get("modules", [])),
            exclude_modules=raw.get("exclude_modules", defaults.get("exclude_modules", [])),
        )
        targets.append(target)

    logger.info("Loaded %d target(s) from inventory %s", len(targets), filepath)
    return targets
