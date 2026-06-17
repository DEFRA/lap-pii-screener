from __future__ import annotations

import io

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from models.report import Report
from reporting.constants import SEVERITY_COLOURS


def render_console(report: Report) -> str:
    """Render the report as a Rich-formatted string for terminal display."""
    buf = io.StringIO()
    console = Console(file=buf, highlight=False, width=120)

    # ── Header ────────────────────────────────────────────────────────────
    console.print(
        Panel(
            f"[bold]Sensitive Code Scanner[/bold]\n"
            f"Project : [cyan]{report.project_name}[/cyan]\n"
            f"Path    : [dim]{report.target_path}[/dim]\n"
            f"Scanned : {report.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"Scanners: {', '.join(report.scanners_run)}\n"
            f"Tier    : {report.tier_used}",
            title="Scan Report",
            border_style="blue",
        )
    )

    # ── Summary ───────────────────────────────────────────────────────────
    summary = report.summary
    summary_table = Table(box=box.ROUNDED, show_header=True)
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")

    summary_table.add_row("[bold red]CRITICAL[/bold red]", str(summary.critical))
    summary_table.add_row("[bold dark_orange]HIGH[/bold dark_orange]", str(summary.high))
    summary_table.add_row("[bold yellow]MEDIUM[/bold yellow]", str(summary.medium))
    summary_table.add_row("[bold cyan]LOW[/bold cyan]", str(summary.low))
    summary_table.add_row("[dim]INFO[/dim]", str(summary.info))
    summary_table.add_row("[bold]TOTAL[/bold]", f"[bold]{summary.total}[/bold]")
    if summary.files_scanned:
        summary_table.add_row("[dim]Files scanned[/dim]", f"[dim]{summary.files_scanned}[/dim]")
    if summary.files_skipped:
        summary_table.add_row("[dim]Files skipped[/dim]", f"[dim]{summary.files_skipped}[/dim]")
    if summary.lines_scanned:
        summary_table.add_row("[dim]Lines scanned[/dim]", f"[dim]{summary.lines_scanned:,}[/dim]")
    if summary.lines_skipped:
        summary_table.add_row("[dim]Lines skipped[/dim]", f"[dim]{summary.lines_skipped:,}[/dim]")

    console.print(summary_table)

    if not report.findings:
        console.print("\n[bold green]No findings — codebase looks clean![/bold green]")
        return buf.getvalue()

    # ── Findings table ────────────────────────────────────────────────────
    findings_table = Table(
        title="Findings",
        box=box.SIMPLE_HEAD,
        show_lines=False,
        expand=True,
    )
    findings_table.add_column("ID", style="dim", width=18)
    findings_table.add_column("Sev", width=9)
    findings_table.add_column("File", no_wrap=False)
    findings_table.add_column("Line", justify="right", width=6)
    findings_table.add_column("Rule", style="dim", no_wrap=True)
    findings_table.add_column("Category", no_wrap=True)
    findings_table.add_column("Match", no_wrap=True)
    findings_table.add_column("Regulations", no_wrap=True)
    findings_table.add_column("Scanners")

    for f in report.findings:
        colour = SEVERITY_COLOURS.get(f.severity, "")
        sev_label = f"[{colour}]{f.severity.upper()}[/{colour}]" if colour else f.severity.upper()
        findings_table.add_row(
            f.id,
            sev_label,
            f.file,
            str(f.line),
            f.rule_id,
            f.category,
            f.match,
            " ".join(f"[dim]{r}[/dim]" for r in f.regulations) if f.regulations else "",
            ", ".join(f.scanners),
        )

    console.print(findings_table)
    return buf.getvalue()
