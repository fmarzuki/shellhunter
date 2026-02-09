import math
import re
from collections import Counter

from .models import DetectionType, Finding, Severity

HEURISTIC_CAP = 2 * 1024 * 1024  # 2MB

# Patterns for heuristic analysis
_VAR_NAME_RE = re.compile(rb'\$([a-zA-Z_]\w{20,})')
_COMMENT_RE = re.compile(rb'(//.*?$|/\*.*?\*/|#.*?$)', re.MULTILINE | re.DOTALL)
_ENCODING_FUNCS_RE = re.compile(
    rb'\b(base64_decode|base64_encode|gzinflate|gzuncompress|str_rot13|rawurldecode|urldecode|gzdecode|convert_uudecode)\s*\(',
    re.IGNORECASE,
)
_FUNCTION_CALL_RE = re.compile(rb'\b[a-zA-Z_]\w*\s*\(')


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class HeuristicAnalyzer:
    """Heuristic analysis for obfuscation and suspicious patterns."""

    def analyze(self, content: bytes, deep_scan: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        # Cap analysis content for performance
        data = content[:HEURISTIC_CAP]

        # HEU-001: High Shannon entropy
        entropy = _shannon_entropy(data)
        if entropy > 5.5:
            findings.append(Finding(
                rule_id="HEU-001",
                detection_type=DetectionType.HEURISTIC,
                description=f"High Shannon entropy ({entropy:.2f}) - possible obfuscation",
                severity=Severity.MEDIUM,
                score=20,
            ))

        # HEU-002: Extremely long lines
        lines = data.split(b'\n')
        for i, line in enumerate(lines, 1):
            if len(line) > 5000:
                findings.append(Finding(
                    rule_id="HEU-002",
                    detection_type=DetectionType.HEURISTIC,
                    description=f"Line {i} exceeds 5000 characters ({len(line)} chars) - possible obfuscated payload",
                    severity=Severity.MEDIUM,
                    score=15,
                    line_number=i,
                ))
                break  # One finding per file

        # HEU-003: Many long variable names (obfuscation indicator)
        long_vars = _VAR_NAME_RE.findall(data)
        if len(long_vars) >= 5:
            findings.append(Finding(
                rule_id="HEU-003",
                detection_type=DetectionType.HEURISTIC,
                description=f"Found {len(long_vars)} variable names >20 chars - possible obfuscation",
                severity=Severity.MEDIUM,
                score=15,
            ))

        # HEU-004: Low comment ratio in large files
        if len(lines) >= 50:
            comments = _COMMENT_RE.findall(data)
            comment_ratio = len(comments) / len(lines)
            if comment_ratio < 0.01:
                findings.append(Finding(
                    rule_id="HEU-004",
                    detection_type=DetectionType.HEURISTIC,
                    description=f"Very low comment ratio ({comment_ratio:.1%}) in {len(lines)}-line file",
                    severity=Severity.LOW,
                    score=10,
                ))

        # HEU-005: Multiple encoding function calls
        encoding_calls = _ENCODING_FUNCS_RE.findall(data)
        if len(encoding_calls) >= 3:
            findings.append(Finding(
                rule_id="HEU-005",
                detection_type=DetectionType.HEURISTIC,
                description=f"Found {len(encoding_calls)} encoding/decoding function calls",
                severity=Severity.HIGH,
                score=25,
            ))

        # HEU-006: Small file with high function call density (deep-scan only)
        if deep_scan and len(data) < 4096:
            func_calls = _FUNCTION_CALL_RE.findall(data)
            if len(data) > 0:
                density = len(func_calls) / (len(data) / 1024)
                if density > 15:  # >15 calls per KB
                    findings.append(Finding(
                        rule_id="HEU-006",
                        detection_type=DetectionType.HEURISTIC,
                        description=f"Small file ({len(data)}B) with high function density ({density:.1f}/KB)",
                        severity=Severity.MEDIUM,
                        score=15,
                    ))

        return findings
