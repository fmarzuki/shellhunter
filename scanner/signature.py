import re

from .models import DetectionType, Finding, Severity

# All patterns compiled as bytes at module load time.
# Each rule: (rule_id, compiled_pattern, description, severity, score)
SIGNATURE_RULES: list[tuple[str, re.Pattern[bytes], str, Severity, int]] = [
    # SIG-001: eval($_POST/$_GET/$_REQUEST)
    (
        "SIG-001",
        re.compile(rb'eval\s*\(\s*\$_(POST|GET|REQUEST)\b', re.IGNORECASE),
        "eval() with user input ($_POST/$_GET/$_REQUEST)",
        Severity.CRITICAL,
        40,
    ),
    # SIG-002: system/exec/passthru/shell_exec with variable
    (
        "SIG-002",
        re.compile(rb'\b(system|exec|passthru|shell_exec)\s*\(\s*\$', re.IGNORECASE),
        "Command execution function with variable argument",
        Severity.CRITICAL,
        35,
    ),
    # SIG-003: eval(base64_decode(...))
    (
        "SIG-003",
        re.compile(rb'eval\s*\(\s*base64_decode\s*\(', re.IGNORECASE),
        "eval(base64_decode(...)) - encoded payload execution",
        Severity.CRITICAL,
        40,
    ),
    # SIG-004: gzinflate/str_rot13 chain
    (
        "SIG-004",
        re.compile(rb'(gzinflate|gzuncompress|str_rot13)\s*\(\s*(gzinflate|gzuncompress|str_rot13|base64_decode)\s*\(', re.IGNORECASE),
        "Chained encoding/compression functions (obfuscation)",
        Severity.HIGH,
        30,
    ),
    # SIG-005: preg_replace with /e modifier
    (
        "SIG-005",
        re.compile(rb'preg_replace\s*\(\s*["\'][^"\']*?/[a-z]*e[a-z]*["\']', re.IGNORECASE),
        "preg_replace() with /e modifier (code execution)",
        Severity.HIGH,
        30,
    ),
    # SIG-006: fopen+fwrite combo
    (
        "SIG-006",
        re.compile(rb'fopen\s*\(.+?["\']w["\'].*?\).*?fwrite\s*\(', re.IGNORECASE | re.DOTALL),
        "File write operation (fopen+fwrite) - potential dropper",
        Severity.HIGH,
        25,
    ),
    # SIG-007: assert($_POST/GET/REQUEST)
    (
        "SIG-007",
        re.compile(rb'assert\s*\(\s*\$_(POST|GET|REQUEST)\b', re.IGNORECASE),
        "assert() with user input - code execution via assert",
        Severity.CRITICAL,
        35,
    ),
    # SIG-008: base64_decode on variable
    (
        "SIG-008",
        re.compile(rb'base64_decode\s*\(\s*\$', re.IGNORECASE),
        "base64_decode() on variable - potential obfuscated payload",
        Severity.MEDIUM,
        15,
    ),
    # SIG-009: chmod 777 in code
    (
        "SIG-009",
        re.compile(rb'chmod\s*\(\s*[^,]+,\s*0?777\s*\)', re.IGNORECASE),
        "chmod 777 in code - insecure permission change",
        Severity.MEDIUM,
        15,
    ),
    # SIG-010: Long hex-escaped strings (>60 hex chars)
    (
        "SIG-010",
        re.compile(rb'(\\x[0-9a-fA-F]{2}){30,}'),
        "Long hex-escaped string (likely obfuscated payload)",
        Severity.MEDIUM,
        20,
    ),
    # SIG-011: create_function()
    (
        "SIG-011",
        re.compile(rb'create_function\s*\(', re.IGNORECASE),
        "create_function() - dynamic function creation",
        Severity.HIGH,
        25,
    ),
    # SIG-012: Bash reverse shell (/dev/tcp)
    (
        "SIG-012",
        re.compile(rb'/dev/tcp/\S+/\d+'),
        "Bash reverse shell pattern (/dev/tcp)",
        Severity.CRITICAL,
        45,
    ),
    # SIG-013: Netcat reverse shell
    (
        "SIG-013",
        re.compile(rb'\bnc\b.*?\s-[a-z]*e\s', re.IGNORECASE),
        "Netcat reverse shell (nc -e)",
        Severity.CRITICAL,
        45,
    ),
    # SIG-014: Python reverse shell (socket+subprocess)
    (
        "SIG-014",
        re.compile(rb'import\s+socket.*?import\s+subprocess', re.IGNORECASE | re.DOTALL),
        "Python reverse shell pattern (socket+subprocess)",
        Severity.HIGH,
        30,
    ),
    # SIG-015: curl pipe to bash
    (
        "SIG-015",
        re.compile(rb'curl\s+[^\|]+\|\s*(ba)?sh\b', re.IGNORECASE),
        "curl piped to shell (remote code execution)",
        Severity.HIGH,
        30,
    ),
    # SIG-016: eval($variable) on non-superglobal variable
    (
        "SIG-016",
        re.compile(rb'eval\s*\(\s*\$(?!_(POST|GET|REQUEST|COOKIE|SERVER|FILES|ENV|SESSION)\b)', re.IGNORECASE),
        "eval() with non-superglobal variable - possible obfuscated execution",
        Severity.HIGH,
        30,
    ),
    # SIG-017: Dynamic function name construction (base64_decode split)
    (
        "SIG-017",
        re.compile(rb"""\$\w+\s*=\s*["']base["'].*\$\w+\s*=\s*["']64_decode["']""", re.IGNORECASE | re.DOTALL),
        "Dynamic function name construction (base64_decode split across variables)",
        Severity.HIGH,
        30,
    ),
    # SIG-018: error_reporting(0) + set_time_limit(0) combo
    (
        "SIG-018",
        re.compile(rb'error_reporting\s*\(\s*0\s*\).*set_time_limit\s*\(\s*0\s*\)', re.IGNORECASE | re.DOTALL),
        "Classic webshell header: error_reporting(0) + set_time_limit(0)",
        Severity.MEDIUM,
        20,
    ),
    # SIG-019: Variable function call $var($arg)
    (
        "SIG-019",
        re.compile(rb'\$\w+\s*\(\s*\$\w+\s*\)'),
        "Variable function call pattern - possible indirect code execution",
        Severity.HIGH,
        30,
    ),
    # SIG-020: Variable concatenation to build function name
    (
        "SIG-020",
        re.compile(rb'\$[a-zA-Z_]\w*\s*=\s*[\'"][a-z_]{2,}[\'"];\s*\$[a-zA-Z_]\w*\s*\.=', re.IGNORECASE),
        "Variable concatenation to build function name (obfuscation)",
        Severity.CRITICAL,
        40,
    ),
    # SIG-021: Assign dangerous function to variable, then call
    (
        "SIG-021",
        re.compile(rb'\$[a-zA-Z_]\w*\s*=\s*[\'\"](system|exec|passthru|shell_exec|eval|assert|popen)[\'\"]\s*;\s*\$[a-zA-Z_]\w*\s*\(', re.IGNORECASE),
        "Dangerous function assigned to variable then called",
        Severity.CRITICAL,
        40,
    ),
    # SIG-022: Variable variable function execution
    (
        "SIG-022",
        re.compile(rb'\$\$[a-zA-Z_]\w*\s*\(|\$\{\s*\$[a-zA-Z_]\w*\s*\}\s*\('),
        "Variable variable function execution ($$fn() or ${$fn}())",
        Severity.HIGH,
        30,
    ),
    # SIG-023: Session/Cookie variable as callable
    (
        "SIG-023",
        re.compile(rb'\$_(SESSION|COOKIE)\s*\[\s*[\'\"]\w+[\'\"]\s*\]\s*\(\s*\$', re.IGNORECASE),
        "Session/Cookie variable used as callable - backdoor pattern",
        Severity.CRITICAL,
        40,
    ),
    # SIG-024: XOR decode loop
    (
        "SIG-024",
        re.compile(rb'chr\s*\(\s*ord\s*\([^)]+\)\s*\^\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})\s*\)', re.IGNORECASE),
        "XOR decode loop (chr/ord with XOR) - obfuscation",
        Severity.HIGH,
        30,
    ),
    # SIG-025: Multi-layer encoding (gzip + base64/rot13)
    (
        "SIG-025",
        re.compile(rb'(gzuncompress|gzinflate|gzdecode)\s*\(\s*(base64_decode|str_rot13|urldecode)\s*\(', re.IGNORECASE),
        "Multi-layer encoding: gzip+base64/rot13 (double-wrapped payload)",
        Severity.CRITICAL,
        45,
    ),
    # SIG-026: fsockopen reverse shell
    (
        "SIG-026",
        re.compile(rb'(fsockopen|pfsockopen)\s*\(\s*[\'"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\'"]', re.IGNORECASE),
        "fsockopen to hardcoded IP - PHP reverse shell pattern",
        Severity.CRITICAL,
        45,
    ),
    # SIG-027: include/require via superglobal
    (
        "SIG-027",
        re.compile(rb'(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', re.IGNORECASE),
        "include/require with user-controlled path (Remote File Inclusion)",
        Severity.CRITICAL,
        40,
    ),
    # SIG-028: strrev to hide function name
    (
        "SIG-028",
        re.compile(rb'strrev\s*\(\s*[\'\"](noitcnuf|metsys|lave|tressa|tuptuo_reffub)[\'\"]\s*\)', re.IGNORECASE),
        "strrev() used to hide dangerous function name",
        Severity.HIGH,
        30,
    ),
    # SIG-029: GIF89a PHP polyglot header
    (
        "SIG-029",
        re.compile(rb'GIF8[79]a.{0,20}<\?(?:php)?', re.DOTALL),
        "GIF89a/GIF87a header with embedded PHP (polyglot file)",
        Severity.CRITICAL,
        45,
    ),
    # SIG-030: Extended known webshell signatures
    (
        "SIG-030",
        re.compile(rb'IndoXploit|c99shell|r57shell|b374k|WSO\s|FilesMan|0byt3m1n1|alfa\.team|ALFA_DATA|edoced_46esab|Sh3llm1x|pwnshell', re.IGNORECASE),
        "Known webshell identifier string",
        Severity.CRITICAL,
        45,
    ),
    # SIG-031: ini_set to disable PHP security
    (
        "SIG-031",
        re.compile(rb'ini_set\s*\(\s*[\'\"](disable_functions|open_basedir)[\'\"]\s*,\s*[\'\"][\'\"]', re.IGNORECASE),
        "ini_set() used to clear disable_functions or open_basedir",
        Severity.HIGH,
        30,
    ),
    # SIG-032: array_map with dangerous function string
    (
        "SIG-032",
        re.compile(rb'array_map\s*\(\s*[\'\"](assert|exec|system|eval|passthru)[\'\"]\s*,', re.IGNORECASE),
        "array_map() with dangerous callback string",
        Severity.CRITICAL,
        40,
    ),
]

SNIPPET_MAX_LEN = 200


class SignatureScanner:
    """Scan file content against compiled signature rules."""

    def scan(self, content: bytes) -> list[Finding]:
        findings: list[Finding] = []
        for rule_id, pattern, description, severity, score in SIGNATURE_RULES:
            match = pattern.search(content)
            if match:
                line_number = content[:match.start()].count(b'\n') + 1
                snippet = match.group(0)[:SNIPPET_MAX_LEN]
                try:
                    snippet_str = snippet.decode("utf-8", errors="replace")
                except Exception:
                    snippet_str = repr(snippet)
                findings.append(Finding(
                    rule_id=rule_id,
                    detection_type=DetectionType.SIGNATURE,
                    description=description,
                    severity=severity,
                    score=score,
                    line_number=line_number,
                    snippet=snippet_str,
                ))
        return findings
