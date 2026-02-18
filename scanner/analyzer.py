import logging
import os
from typing import Callable

from .heuristic import HeuristicAnalyzer
from .models import ScanResult, ScanSummary, Severity
from .signature import SignatureScanner
from .utils import MetadataAnalyzer, discover_files, read_file_safe

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int, int], None]


class ShellHunterAnalyzer:
    """Orchestrator: discovery -> metadata -> signature -> heuristic."""

    def __init__(
        self,
        paths: list[str],
        extensions: set[str] | None = None,
        deep_scan: bool = False,
        severity_level: Severity = Severity.LOW,
        delete_mode: bool = False,
    ):
        self.paths = paths
        self.extensions = extensions
        self.deep_scan = deep_scan
        self.severity_level = severity_level
        self.delete_mode = delete_mode
        self.signature_scanner = SignatureScanner()
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.metadata_analyzer = MetadataAnalyzer()

    def scan(
        self,
        progress_callback: ProgressCallback | None = None,
    ) -> ScanSummary:
        # Discover files
        all_files: list[str] = []
        for path in self.paths:
            all_files.extend(discover_files(path, self.extensions))

        summary = ScanSummary(total_files=len(all_files))
        total = len(all_files)

        for idx, fpath in enumerate(all_files):
            if progress_callback:
                progress_callback(fpath, idx, total)

            result = self._scan_file(fpath)

            # Filter by severity level
            result.findings = [
                f for f in result.findings
                if f.severity >= self.severity_level
            ]

            if result.findings or result.error:
                result.compute_risk_score()
                if result.findings:
                    summary.results.append(result)

                    # Auto-delete if delete_mode and finding is CRITICAL/HIGH
                    if self.delete_mode and any(
                        f.severity in (Severity.CRITICAL, Severity.HIGH)
                        for f in result.findings
                    ):
                        try:
                            os.remove(fpath)
                            logger.warning("DELETED: %s (risk score: %d)", fpath, result.risk_score)
                            result.deleted = True
                        except OSError as e:
                            logger.error("Failed to delete %s: %s", fpath, e)

                if result.error:
                    summary.errors += 1

        # Sort results by risk_score descending
        summary.results.sort(key=lambda r: r.risk_score, reverse=True)

        # Compute summary stats
        for result in summary.results:
            for finding in result.findings:
                summary.total_findings += 1
                sev_name = finding.severity.name
                summary.severity_counts[sev_name] = (
                    summary.severity_counts.get(sev_name, 0) + 1
                )

        return summary

    def _scan_file(self, path: str) -> ScanResult:
        result = ScanResult(file_path=path)

        content = read_file_safe(path)
        if content is None:
            result.error = "Could not read file"
            return result

        try:
            # Metadata analysis
            result.findings.extend(self.metadata_analyzer.analyze(path))

            # Signature scanning
            result.findings.extend(self.signature_scanner.scan(content))

            # Heuristic analysis
            result.findings.extend(
                self.heuristic_analyzer.analyze(content, deep_scan=self.deep_scan, file_path=path)
            )
        except Exception as e:
            logger.debug("Error analyzing %s: %s", path, e)
            result.error = str(e)

        return result
