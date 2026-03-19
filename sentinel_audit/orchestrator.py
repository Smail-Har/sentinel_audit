"""
sentinel_audit/orchestrator.py
───────────────────────────────
High-level pipeline: connect → audit → score → report.
Handles single-target and multi-target runs.
"""

from __future__ import annotations

import datetime
import logging
from collections.abc import Sequence
from pathlib import Path

from sentinel_audit.audit.compliance_audit import ComplianceAuditor
from sentinel_audit.audit.container_audit import ContainerAuditor
from sentinel_audit.audit.cron_audit import CronAuditor
from sentinel_audit.audit.filesystem_audit import FilesystemAuditor
from sentinel_audit.audit.firewall_audit import FirewallAuditor
from sentinel_audit.audit.kernel_audit import KernelAuditor
from sentinel_audit.audit.network_audit import NetworkAuditor
from sentinel_audit.audit.packages_audit import PackagesAuditor
from sentinel_audit.audit.permissions_audit import PermissionsAuditor
from sentinel_audit.audit.services_audit import ServicesAuditor
from sentinel_audit.audit.ssh_audit import SSHAuditor
from sentinel_audit.audit.system_info import SystemInfoAuditor
from sentinel_audit.audit.users_audit import UsersAuditor
from sentinel_audit.core.executor import BaseExecutor, LocalExecutor, RemoteExecutor
from sentinel_audit.core.models import AuditResult, InventoryTarget
from sentinel_audit.core.scoring import compute_score
from sentinel_audit.core.ssh_client import SSHClient
from sentinel_audit.reporting.console_report import ConsoleReportGenerator
from sentinel_audit.reporting.html_report import HtmlReportGenerator
from sentinel_audit.reporting.json_report import JsonReportGenerator
from sentinel_audit.reporting.markdown_report import MarkdownReportGenerator

logger = logging.getLogger(__name__)

# Complete auditor registry
AUDITOR_REGISTRY: dict[str, type] = {
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
    "filesystem": FilesystemAuditor,
    "container": ContainerAuditor,
    "compliance": ComplianceAuditor,
}

ALL_MODULE_NAMES: list[str] = list(AUDITOR_REGISTRY.keys())


def resolve_modules(
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
) -> list[str]:
    """Resolve which modules to run based on include/exclude lists."""
    if include:
        selected = [n for n in include if n in AUDITOR_REGISTRY]
    else:
        selected = list(ALL_MODULE_NAMES)

    if exclude:
        exclude_set = set(exclude)
        selected = [n for n in selected if n not in exclude_set]

    # system_info always runs first
    if "system_info" in AUDITOR_REGISTRY and "system_info" not in selected:
        selected.insert(0, "system_info")
    elif "system_info" in selected and selected[0] != "system_info":
        selected.remove("system_info")
        selected.insert(0, "system_info")

    return selected


def run_audit(
    executor: BaseExecutor,
    result: AuditResult,
    module_names: Sequence[str],
) -> None:
    """Run selected audit modules sequentially.  Errors are captured, not raised."""
    for name in module_names:
        if name not in AUDITOR_REGISTRY:
            logger.warning("Unknown module: %s — skipping", name)
            continue

        auditor = AUDITOR_REGISTRY[name](executor, result)
        try:
            logger.info("Running module: %s", auditor.name)
            auditor.run()
        except Exception as exc:
            message = f"[{auditor.name}] Unhandled error: {exc}"
            logger.exception(message)
            result.audit_errors.append(message)


def generate_reports(
    result: AuditResult,
    output_dir: str,
    formats: Sequence[str],
) -> list[str]:
    """Generate selected reports.  Returns list of generated file paths."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    safe_target = result.target.replace("/", "_").replace(":", "_").replace(" ", "_")
    timestamp = result.started_at.strftime("%Y%m%d_%H%M%S")
    base_name = f"audit_{safe_target}_{timestamp}"
    generated: list[str] = []

    if "json" in formats:
        try:
            path = str(output_path / f"{base_name}.json")
            JsonReportGenerator().generate(result, path)
            generated.append(path)
        except Exception as exc:
            logger.exception("[report-json] Failed: %s", exc)
            result.audit_errors.append(f"[report-json] {exc}")

    if "md" in formats:
        try:
            path = str(output_path / f"{base_name}.md")
            MarkdownReportGenerator().generate(result, path)
            generated.append(path)
        except Exception as exc:
            logger.exception("[report-md] Failed: %s", exc)
            result.audit_errors.append(f"[report-md] {exc}")

    if "html" in formats:
        try:
            path = str(output_path / f"{base_name}.html")
            HtmlReportGenerator().generate(result, path)
            generated.append(path)
        except Exception as exc:
            logger.exception("[report-html] Failed: %s", exc)
            result.audit_errors.append(f"[report-html] {exc}")

    if "pdf" in formats:
        try:
            from sentinel_audit.reporting.pdf_report import PdfReportGenerator

            path = str(output_path / f"{base_name}.pdf")
            PdfReportGenerator().generate(result, path)
            generated.append(path)
        except ImportError:
            logger.warning("weasyprint not installed — PDF report skipped")
            result.audit_errors.append(
                "[report-pdf] weasyprint not installed. Install with: pip install 'sentinel-audit[pdf]'"
            )
        except Exception as exc:
            logger.exception("[report-pdf] Failed: %s", exc)
            result.audit_errors.append(f"[report-pdf] {exc}")

    if "console" in formats:
        try:
            ConsoleReportGenerator().generate(result)
        except Exception as exc:
            logger.exception("[report-console] Failed: %s", exc)
            result.audit_errors.append(f"[report-console] {exc}")

    return generated


def audit_single_target(
    target: InventoryTarget,
    output_dir: str,
    formats: Sequence[str],
) -> AuditResult:
    """Run a complete audit on one target and return the result."""
    result = AuditResult(target=target.host, label=target.label)
    ssh_client: SSHClient | None = None

    try:
        modules = resolve_modules(
            include=target.modules or None,
            exclude=target.exclude_modules or None,
        )
        logger.info(
            "Auditing %s (%s) — modules: %s",
            target.host,
            target.label,
            ", ".join(modules),
        )

        # Build executor
        if target.host in ("localhost", "127.0.0.1", "::1"):
            executor: BaseExecutor = LocalExecutor()
        else:
            ssh_client = SSHClient(
                host=target.host,
                username=target.ssh_user,
                port=target.ssh_port,
                key_path=target.ssh_key,
                password=target.ssh_password,
            )
            ssh_client.connect()
            executor = RemoteExecutor(ssh_client)

        run_audit(executor, result, modules)
        result.finished_at = datetime.datetime.now(datetime.UTC)
        compute_score(result)
        generate_reports(result, output_dir, formats)

        logger.info(
            "Audit complete for %s: score=%d/100 (%s), findings=%d",
            target.host,
            result.score.score,
            result.score.grade,
            len(result.findings),
        )
    except Exception as exc:
        logger.exception("Audit failed for %s: %s", target.host, exc)
        result.audit_errors.append(f"Fatal error: {exc}")
    finally:
        if ssh_client is not None:
            ssh_client.disconnect()

    return result
