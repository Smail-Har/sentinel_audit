"""PDF report generator for SentinelAudit (requires weasyprint)."""

from __future__ import annotations

import logging
from pathlib import Path

from sentinel_audit.core.models import AuditResult
from sentinel_audit.reporting.html_report import HtmlReportGenerator

logger = logging.getLogger(__name__)


class PdfReportGenerator:
    """Generate a PDF report by rendering HTML through WeasyPrint."""

    def generate(self, result: AuditResult, output_path: str) -> None:
        try:
            from weasyprint import HTML  # type: ignore[import-untyped]
        except ImportError:
            msg = (
                "weasyprint is required for PDF output. "
                "Install it with: pip install 'sentinel-audit[pdf]'"
            )
            raise ImportError(msg)

        html_content = HtmlReportGenerator().generate(result)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=html_content).write_pdf(str(path))
        logger.info("PDF report written to %s", path)
