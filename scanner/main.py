import argparse
import logging
import sys
import time

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from . import __version__
from .analyzer import ShellHunterAnalyzer
from .models import Severity
from .reporter import export_json, print_banner, print_results, print_summary
from .utils import DEFAULT_EXTENSIONS

# stderr for progress/status, stdout for results (pipeable)
stderr_console = Console(stderr=True)
stdout_console = Console()

SEVERITY_MAP = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="shellhunter",
        description="Detect webshells, backdoors, and malicious scripts on Linux servers.",
    )
    parser.add_argument(
        "--path",
        nargs="+",
        default=["."],
        help="Paths to scan (default: current directory)",
    )
    parser.add_argument(
        "--ext",
        nargs="+",
        default=None,
        help=f"File extensions to scan (default: {' '.join(sorted(DEFAULT_EXTENSIONS))})",
    )
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        help="Enable additional heuristic checks",
    )
    parser.add_argument(
        "--json-output",
        metavar="FILE",
        help="Export results to JSON file",
    )
    parser.add_argument(
        "--severity-level",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity to report (default: low)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed findings with line numbers and snippets",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Auto-delete files with CRITICAL or HIGH findings (use with caution)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    print_banner(stderr_console)

    if args.delete:
        stderr_console.print(
            "[bold red]WARNING: --delete mode is active. "
            "Files with CRITICAL or HIGH findings will be permanently deleted![/bold red]"
        )

    extensions = set(args.ext) if args.ext else None
    severity_level = SEVERITY_MAP[args.severity_level]

    analyzer = ShellHunterAnalyzer(
        paths=args.path,
        extensions=extensions,
        deep_scan=args.deep_scan,
        severity_level=severity_level,
        delete_mode=args.delete,
    )

    start = time.monotonic()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=stderr_console,
        transient=True,
    ) as progress:
        task_id = progress.add_task("Scanning...", total=None)

        def on_progress(fpath: str, idx: int, total: int) -> None:
            if progress.tasks[0].total is None:
                progress.update(task_id, total=total)
            progress.update(task_id, completed=idx + 1, description=f"Scanning {fpath[-60:]}")

        try:
            summary = analyzer.scan(progress_callback=on_progress)
        except KeyboardInterrupt:
            stderr_console.print("\n[yellow]Scan interrupted.[/yellow]")
            sys.exit(130)

    summary.duration_seconds = time.monotonic() - start

    # Output results
    print_results(stdout_console, summary, verbose=args.verbose)
    print_summary(stdout_console, summary)

    if args.json_output:
        export_json(summary, args.json_output)
        stderr_console.print(f"\n[green]Results exported to {args.json_output}[/green]")

    # Exit code: 1 if critical or high findings
    has_serious = (
        summary.severity_counts.get("CRITICAL", 0) > 0
        or summary.severity_counts.get("HIGH", 0) > 0
    )
    sys.exit(1 if has_serious else 0)


if __name__ == "__main__":
    main()
