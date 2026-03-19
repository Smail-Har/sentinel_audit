"""Command-line interface for SentinelAudit."""

from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence

from sentinel_audit.core.constants import ALL_REPORT_FORMATS, VALID_FORMATS
from sentinel_audit.core.models import AuditResult, InventoryTarget
from sentinel_audit.inventory import load_inventory
from sentinel_audit.orchestrator import (
    ALL_MODULE_NAMES,
    audit_single_target,
)
from sentinel_audit.reporting.consolidated_report import ConsolidatedReportGenerator

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Build the SentinelAudit CLI parser."""
    parser = argparse.ArgumentParser(
        prog="sentinel-audit",
        description="SentinelAudit — Linux server security audit tool",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logs (DEBUG)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser("audit", help="Run a security audit")

    # Target selection: either --target or --inventory
    target_group = audit_parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target", help="Single target host (IP or hostname)")
    target_group.add_argument("--inventory", help="Path to YAML inventory file for multi-target audit")

    audit_parser.add_argument(
        "--mode",
        choices=["local", "remote"],
        default="remote",
        help="Execution mode (default: remote)",
    )
    audit_parser.add_argument("--ssh-user", default="root", help="SSH username (default: root)")
    audit_parser.add_argument("--ssh-key", help="Path to SSH private key")
    audit_parser.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")
    audit_parser.add_argument("--label", help="Human-readable label for the target")
    audit_parser.add_argument(
        "--output",
        default="reports",
        help="Output directory for reports (default: reports)",
    )
    audit_parser.add_argument(
        "--include",
        default="",
        help=f"Comma-separated modules to run (available: {', '.join(ALL_MODULE_NAMES)})",
    )
    audit_parser.add_argument("--exclude", default="", help="Comma-separated modules to exclude")
    audit_parser.add_argument(
        "--format",
        default="all",
        help="Report formats: json,md,html,pdf,console,all (comma-separated)",
    )

    # List available modules
    subparsers.add_parser("modules", help="List available audit modules")

    return parser


# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────


def configure_logging(level: str = "INFO") -> None:
    """Configure root logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────


def _parse_csv(value: str) -> list[str]:
    if not value.strip():
        return []
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def _resolve_formats(value: str) -> list[str]:
    requested = _parse_csv(value) or ["all"]
    selected = [f for f in requested if f in VALID_FORMATS]
    if not selected or "all" in selected:
        return list(ALL_REPORT_FORMATS)
    return selected


# ─────────────────────────────────────────────
# Command handlers
# ─────────────────────────────────────────────


def handle_audit_command(args: argparse.Namespace) -> int:
    """Execute full audit workflow."""
    formats = _resolve_formats(args.format)

    if args.inventory:
        return _handle_inventory_audit(args, formats)
    return _handle_single_audit(args, formats)


def _handle_single_audit(args: argparse.Namespace, formats: list[str]) -> int:
    """Audit a single target from CLI flags."""
    target = InventoryTarget(
        host=args.target,
        label=args.label or args.target,
        ssh_user=args.ssh_user,
        ssh_key=args.ssh_key,
        ssh_port=args.ssh_port,
        modules=_parse_csv(args.include),
        exclude_modules=_parse_csv(args.exclude),
    )

    # Override to local executor if requested
    if args.mode == "local":
        target = InventoryTarget(
            host="localhost",
            label=args.label or "localhost",
            ssh_user=target.ssh_user,
            ssh_key=target.ssh_key,
            ssh_port=target.ssh_port,
            modules=target.modules,
            exclude_modules=target.exclude_modules,
        )

    result = audit_single_target(target, args.output, formats)

    if result.audit_errors:
        logger.warning("Completed with %d error(s)", len(result.audit_errors))
    return 0


def _handle_inventory_audit(args: argparse.Namespace, formats: list[str]) -> int:
    """Audit multiple targets from a YAML inventory file."""
    targets = load_inventory(args.inventory)
    results: list[AuditResult] = []

    for target in targets:
        logger.info("─── Starting audit: %s (%s) ───", target.label, target.host)
        result = audit_single_target(target, args.output, formats)
        results.append(result)

    # Generate consolidated report if multiple targets
    if len(results) > 1:
        try:
            ConsolidatedReportGenerator().generate(
                results,
                f"{args.output}/consolidated_report.html",
            )
        except Exception as exc:
            logger.exception("Failed to generate consolidated report: %s", exc)

    failed = sum(1 for r in results if r.audit_errors)
    if failed:
        logger.warning("Audit completed: %d/%d target(s) had errors", failed, len(results))
    else:
        logger.info("Audit completed successfully for all %d target(s)", len(results))

    return 0


def handle_modules_command() -> int:
    """List available audit modules."""
    for _name in ALL_MODULE_NAMES:
        pass
    return 0


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    resolved_level = "DEBUG" if getattr(args, "verbose", False) else (args.log_level or "INFO")
    configure_logging(resolved_level)

    if args.command == "audit":
        return handle_audit_command(args)
    if args.command == "modules":
        return handle_modules_command()

    parser.print_help()
    return 1
