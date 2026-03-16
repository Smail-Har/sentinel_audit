"""Command-line interface for SentinelAudit."""

from __future__ import annotations

import argparse
import datetime
import logging
from pathlib import Path
from typing import Callable, Sequence

from sentinel_audit.audit.compliance_audit import ComplianceAuditor
from sentinel_audit.audit.container_audit import ContainerAuditor
from sentinel_audit.audit.cron_audit import CronAuditor
from sentinel_audit.audit.filesystem_audit import FilesystemAuditor
from sentinel_audit.audit.firewall_audit import FirewallAuditor
from sentinel_audit.audit.kernel_audit import KernelAuditor
from sentinel_audit.audit.lynis_adapter import LynisAdapterAuditor
from sentinel_audit.audit.network_audit import NetworkAuditor
from sentinel_audit.audit.packages_audit import PackagesAuditor
from sentinel_audit.audit.permissions_audit import PermissionsAuditor
from sentinel_audit.audit.process_audit import ProcessAuditor
from sentinel_audit.audit.services_audit import ServicesAuditor
from sentinel_audit.audit.ssh_audit import SSHAuditor
from sentinel_audit.audit.system_info import SystemInfoAuditor
from sentinel_audit.audit.users_audit import UsersAuditor
from sentinel_audit.core.executor import BaseExecutor, LocalExecutor, RemoteExecutor
from sentinel_audit.core.models import AuditResult
from sentinel_audit.core.scoring import compute_score
from sentinel_audit.core.ssh_client import SSHClient
from sentinel_audit.reporting.console_report import ConsoleReportGenerator
from sentinel_audit.reporting.html_report import HtmlReportGenerator
from sentinel_audit.reporting.json_report import JsonReportGenerator
from sentinel_audit.reporting.markdown_report import MarkdownReportGenerator

logger = logging.getLogger(__name__)

AuditorFactory = Callable[[BaseExecutor, AuditResult], object]

AUDITOR_REGISTRY: dict[str, AuditorFactory] = {
    "system_info": SystemInfoAuditor,
    "ssh": SSHAuditor,
    "firewall": FirewallAuditor,
    "users": UsersAuditor,
    "permissions": PermissionsAuditor,
    "services": ServicesAuditor,
    "packages": PackagesAuditor,
    "kernel": KernelAuditor,
    "cron": CronAuditor,
    "network": NetworkAuditor,
    "process": ProcessAuditor,
    "filesystem": FilesystemAuditor,
    "container": ContainerAuditor,
    "compliance": ComplianceAuditor,
    "lynis": LynisAdapterAuditor,
}


def build_parser() -> argparse.ArgumentParser:
    """Build the SentinelAudit CLI parser."""
    parser = argparse.ArgumentParser(
        prog="sentinel_audit",
        description="SentinelAudit - Linux server security audit tool",
    )
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Logging verbosity")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logs (DEBUG)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser("audit", help="Run a system security audit")
    audit_parser.add_argument("--target", required=True, help="Target host (localhost or remote host)")
    audit_parser.add_argument("--mode", choices=["local", "remote"], default="local", help="Execution mode")
    audit_parser.add_argument("--ssh-user", default="root", help="SSH username for remote target")
    audit_parser.add_argument("--ssh-key", help="SSH private key path for remote target")
    audit_parser.add_argument("--ssh-password", help="SSH password (optional)")
    audit_parser.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    audit_parser.add_argument(
        "--output",
        default="reports",
        help="Output directory for generated reports (default: reports)",
    )
    audit_parser.add_argument("--include", default="", help="Comma-separated modules to include (e.g. ssh,permissions,users)")
    audit_parser.add_argument("--exclude", default="", help="Comma-separated modules to exclude")
    audit_parser.add_argument(
        "--format",
        default="all",
        help="Report formats: json,md,html,console,all or comma-separated list",
    )

    return parser


def configure_logging(level: str = "INFO") -> None:
    """Configure root logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def build_executor(args: argparse.Namespace) -> tuple[BaseExecutor, SSHClient | None]:
    """Build a local or remote executor based on CLI options."""
    if args.mode == "local":
        logger.info("Using local executor for target %s", args.target)
        return LocalExecutor(), None

    logger.info(
        "Using remote executor for target %s (ssh user=%s, port=%s)",
        args.target,
        args.ssh_user,
        args.ssh_port,
    )
    ssh_client = SSHClient(
        host=args.target,
        username=args.ssh_user,
        port=args.ssh_port,
        key_path=args.ssh_key,
        password=args.ssh_password,
    )
    ssh_client.connect()
    return RemoteExecutor(ssh_client), ssh_client


def _parse_csv_items(value: str) -> list[str]:
    if not value.strip():
        return []
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def _resolve_modules(include: str, exclude: str) -> list[str]:
    include_items = _parse_csv_items(include)
    exclude_items = set(_parse_csv_items(exclude))

    if include_items:
        selected = [name for name in include_items if name in AUDITOR_REGISTRY]
    else:
        selected = list(AUDITOR_REGISTRY.keys())

    selected = [name for name in selected if name not in exclude_items]
    return selected


def _resolve_formats(value: str) -> list[str]:
    requested = _parse_csv_items(value)
    if not requested:
        requested = ["all"]

    valid = {"json", "md", "html", "console", "all"}
    selected = [item for item in requested if item in valid]
    if not selected:
        return ["json", "md", "html", "console"]

    if "all" in selected:
        return ["json", "md", "html", "console"]
    return selected


def run_audits(executor: BaseExecutor, result: AuditResult, module_names: Sequence[str]) -> None:
    """Run selected audit modules sequentially while preserving execution on errors."""
    auditors = [AUDITOR_REGISTRY[name](executor, result) for name in module_names if name in AUDITOR_REGISTRY]

    for auditor in auditors:
        try:
            logger.info("Running module: %s", auditor.name)
            auditor.run()
        except Exception as exc:  # noqa: BLE001
            message = f"[{auditor.name}] Unhandled error: {exc}"
            logger.exception(message)
            result.audit_errors.append(message)


def generate_reports(result: AuditResult, output_dir: str, formats: Sequence[str]) -> None:
    """Generate selected reports and keep execution resilient to reporter failures."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    safe_target = result.target.replace("/", "_").replace(":", "_")
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = f"audit_{safe_target}_{timestamp}"

    if "json" in formats:
        try:
            JsonReportGenerator().generate(result, str(output_path / f"{base_name}.json"))
        except Exception as exc:  # noqa: BLE001
            message = f"[report-json] Failed to generate JSON report: {exc}"
            logger.exception(message)
            result.audit_errors.append(message)

    if "md" in formats:
        try:
            MarkdownReportGenerator().generate(result, str(output_path / f"{base_name}.md"))
        except Exception as exc:  # noqa: BLE001
            message = f"[report-md] Failed to generate Markdown report: {exc}"
            logger.exception(message)
            result.audit_errors.append(message)

    if "html" in formats:
        try:
            HtmlReportGenerator().generate(result, str(output_path / f"{base_name}.html"))
        except Exception as exc:  # noqa: BLE001
            message = f"[report-html] Failed to generate HTML report: {exc}"
            logger.exception(message)
            result.audit_errors.append(message)

    if "console" in formats:
        try:
            summary = ConsoleReportGenerator().generate(result)
            print(summary)
        except Exception as exc:  # noqa: BLE001
            message = f"[report-console] Failed to generate console summary: {exc}"
            logger.exception(message)
            result.audit_errors.append(message)


def handle_audit_command(args: argparse.Namespace) -> int:
    """Execute full audit workflow for the `audit` command."""
    result = AuditResult(target=args.target)
    ssh_client: SSHClient | None = None

    try:
        selected_modules = _resolve_modules(args.include, args.exclude)
        if not selected_modules:
            raise ValueError("No audit module selected. Check --include/--exclude options.")

        selected_formats = _resolve_formats(args.format)

        executor, ssh_client = build_executor(args)
        run_audits(executor, result, selected_modules)
        result.finished_at = datetime.datetime.utcnow()

        compute_score(result)
        generate_reports(result, args.output, selected_formats)

        logger.info(
            "Audit finished for %s: score=%s, findings=%s",
            result.target,
            result.score.score,
            len(result.findings),
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        logger.exception("Audit execution failed: %s", exc)
        print(f"Audit failed: {exc}")
        return 1
    finally:
        if ssh_client is not None:
            ssh_client.disconnect()


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    resolved_level = "DEBUG" if getattr(args, "verbose", False) else (args.log_level or "INFO")
    configure_logging(resolved_level)

    if args.command == "audit":
        return handle_audit_command(args)

    parser.print_help()
    return 1
