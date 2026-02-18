import json
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .models import ScanResult, ScanSummary, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def print_banner(console: Console) -> None:
    banner = (
        "[bold cyan]ShellHunter[/bold cyan] v" + __version__ + "\n"
        "[dim]Webshell & Backdoor Detection Tool[/dim]"
    )
    console.print(Panel(banner, border_style="cyan", expand=False))


def print_results(console: Console, summary: ScanSummary, verbose: bool = False) -> None:
    if not summary.results:
        console.print("\n[green]No suspicious files detected.[/green]")
        return

    console.print(f"\n[bold]Found {summary.total_findings} findings in {len(summary.results)} files:[/bold]\n")

    for result in summary.results:
        _print_file_result(console, result, verbose)


def _print_file_result(console: Console, result: ScanResult, verbose: bool) -> None:
    max_severity = max((f.severity for f in result.findings), default=Severity.LOW)
    color = SEVERITY_COLORS.get(max_severity, "white")

    deleted_tag = "  [bold red][DELETED][/bold red]" if result.deleted else ""
    header = f"[{color}]{result.file_path}[/{color}]  [dim]Risk Score: {result.risk_score}/100[/dim]{deleted_tag}"
    console.print(header)

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Rule", style="dim", width=9)
    table.add_column("Severity", width=10)
    table.add_column("Description")
    if verbose:
        table.add_column("Line", justify="right", width=6)
        table.add_column("Snippet", max_width=50)

    for finding in result.findings:
        sev_color = SEVERITY_COLORS.get(finding.severity, "white")
        row = [
            finding.rule_id,
            f"[{sev_color}]{finding.severity.name}[/{sev_color}]",
            finding.description,
        ]
        if verbose:
            row.append(str(finding.line_number) if finding.line_number else "-")
            row.append(finding.snippet[:50] if finding.snippet else "-")
        table.add_row(*row)

    console.print(table)
    console.print()


def print_summary(console: Console, summary: ScanSummary) -> None:
    table = Table(title="Scan Summary", show_header=False, border_style="dim")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Files scanned", str(summary.total_files))
    table.add_row("Total findings", str(summary.total_findings))
    table.add_row(
        "Critical",
        f"[bold red]{summary.severity_counts.get('CRITICAL', 0)}[/bold red]",
    )
    table.add_row(
        "High",
        f"[red]{summary.severity_counts.get('HIGH', 0)}[/red]",
    )
    table.add_row(
        "Medium",
        f"[yellow]{summary.severity_counts.get('MEDIUM', 0)}[/yellow]",
    )
    table.add_row(
        "Low",
        f"[cyan]{summary.severity_counts.get('LOW', 0)}[/cyan]",
    )
    table.add_row("Scan duration", f"{summary.duration_seconds:.2f}s")
    deleted_count = sum(1 for r in summary.results if r.deleted)
    if deleted_count:
        table.add_row("Files deleted", f"[bold red]{deleted_count}[/bold red]")
    if summary.errors:
        table.add_row("Errors", f"[red]{summary.errors}[/red]")

    console.print()
    console.print(table)


def export_json(summary: ScanSummary, output_path: str) -> None:
    data = {
        "version": __version__,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total_files": summary.total_files,
        "total_findings": summary.total_findings,
        "severity_counts": summary.severity_counts,
        "duration_seconds": round(summary.duration_seconds, 2),
        "errors": summary.errors,
        "results": [
            {
                "file": r.file_path,
                "risk_score": r.risk_score,
                "deleted": r.deleted,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "type": f.detection_type.value,
                        "severity": f.severity.name,
                        "score": f.score,
                        "description": f.description,
                        "line_number": f.line_number,
                        "snippet": f.snippet,
                    }
                    for f in r.findings
                ],
            }
            for r in summary.results
        ],
    }
    with open(output_path, "w") as fp:
        json.dump(data, fp, indent=2)
