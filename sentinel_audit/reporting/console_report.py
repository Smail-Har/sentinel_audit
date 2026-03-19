"""Console summary reporter for SentinelAudit using rich."""

from __future__ import annotations

import logging

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinel_audit.core.constants import Severity
from sentinel_audit.core.models import AuditResult
from sentinel_audit.reporting.base import (
    collect_recommendations,
    top_priority_findings,
)

logger = logging.getLogger(__name__)

_SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold bright_red",
    "MEDIUM": "bold yellow",
    "LOW": "green",
    "INFO": "dim",
}


class ConsoleReportGenerator:
    """Generate a rich console report printed to the terminal."""

    def generate(self, result: AuditResult, *, quiet: bool = False) -> str:
        """Print a rich summary to stderr and return a plain-text version."""
        console = Console(stderr=True)

        # ── Header panel ──
        si = result.system_info
        score = result.score
        grade_colour = "green" if score.score >= 70 else ("yellow" if score.score >= 40 else "red")

        header = Text.assemble(
            ("Score: ", "bold"),
            (f"{score.score}/100 ", f"bold {grade_colour}"),
            (f"({score.grade})", grade_colour),
            (" — ", "dim"),
            (score.risk_summary, "italic"),
        )
        panel_title = f"[bold]SentinelAudit[/bold] — {result.label or result.target}"
        console.print(Panel(header, title=panel_title, border_style="blue"))

        if not quiet:
            # ── System info ──
            console.print(
                f"  [bold]Host:[/bold] {si.hostname}  |  "
                f"[bold]OS:[/bold] {si.os_name} {si.os_version}  |  "
                f"[bold]Kernel:[/bold] {si.kernel_version}"
            )
            if result.duration_seconds is not None:
                console.print(f"  [bold]Duration:[/bold] {result.duration_seconds:.1f}s")
            console.print()

            # ── Severity table ──
            table = Table(title="Findings by Severity", show_lines=False, padding=(0, 2))
            table.add_column("Severity", style="bold")
            table.add_column("Count", justify="right")
            for sev in Severity:
                count = score.breakdown.get(sev.value, 0)
                style = _SEVERITY_STYLE.get(sev.value, "")
                table.add_row(Text(sev.value, style=style), str(count))
            console.print(table)
            console.print()

            # ── Top priority findings ──
            top = top_priority_findings(result, limit=10)
            if top:
                console.print("[bold]Top Priority Findings:[/bold]")
                for f in top:
                    style = _SEVERITY_STYLE.get(f.severity.value, "")
                    console.print(f"  [{style}][{f.severity.value}][/{style}] {f.id} — {f.title}")
                console.print()

            # ── Recommendations ──
            recs = collect_recommendations(result)
            if recs:
                console.print("[bold]Top Recommendations:[/bold]")
                for i, rec in enumerate(recs[:10], 1):
                    console.print(f"  {i}. {rec}")
                console.print()

        # Return a plain-text fallback for logging / piping
        lines = [
            f"SentinelAudit | {result.label or result.target}",
            f"Score: {score.score}/100 ({score.grade}) — {score.risk_summary}",
            f"Findings: {len(result.findings)} total",
        ]
        logger.info("Console report generated for %s", result.target)
        return "\n".join(lines)
