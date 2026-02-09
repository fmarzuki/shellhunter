from dataclasses import dataclass, field
from enum import Enum, IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class DetectionType(Enum):
    SIGNATURE = "signature"
    HEURISTIC = "heuristic"
    METADATA = "metadata"


@dataclass
class Finding:
    rule_id: str
    detection_type: DetectionType
    description: str
    severity: Severity
    score: int
    line_number: int = 0
    snippet: str = ""


@dataclass
class ScanResult:
    file_path: str
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    error: str | None = None

    def compute_risk_score(self) -> None:
        raw = sum(f.score for f in self.findings)
        self.risk_score = max(0, min(100, raw))


@dataclass
class ScanSummary:
    total_files: int = 0
    total_findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
    })
    duration_seconds: float = 0.0
    results: list[ScanResult] = field(default_factory=list)
    errors: int = 0
