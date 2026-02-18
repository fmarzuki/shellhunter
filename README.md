# ShellHunter

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-fmarzuki-FFDD00?style=flat&logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/fmarzuki)

CLI tool for detecting webshells, backdoors, and malicious shell scripts on Linux servers. Designed for security audits on servers running WordPress, OJS, Laravel, etc.

> **Note:** By default, ShellHunter is read-only and safe to run in production. The `--delete` flag enables destructive mode — use with caution.

## Installation

```bash
# Clone repository
git clone <repo-url> shellhunter
cd shellhunter

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install -e .
```

Requires Python 3.10+

## Usage

### Basic scan

```bash
# Scan current directory
shellhunter

# Scan a specific path
shellhunter --path /var/www/html

# Scan multiple paths
shellhunter --path /var/www /home/user/public_html
```

### All options

```
shellhunter [OPTIONS]

--path PATH [PATH ...]     Paths to scan (default: current directory)
--ext EXT [EXT ...]        File extensions to scan (default: .php .phtml .php5 .php7 .sh .py .pl)
--deep-scan                Enable additional heuristic checks (function density analysis)
--json-output FILE         Export results to a JSON file
--severity-level LEVEL     Minimum severity to report: low, medium, high, critical (default: medium)
--exclude DIR [DIR ...]    Additional directory names to exclude (adds to built-in list)
--no-default-excludes      Disable built-in directory exclusions (vendor, node_modules, .git, etc.)
--delete                   Auto-delete files with CRITICAL or HIGH findings (use with caution)
-v, --verbose              Show detailed findings with line numbers and snippets
--version                  Show version
```

**Built-in excluded directories** (skipped by default): `vendor`, `node_modules`, `.git`, `.svn`, `.hg`, `bower_components`, `.tox`, `__pycache__`, `.venv`, `venv`

### Examples

```bash
# Scan with detailed output
shellhunter --path /var/www/html --verbose

# Only show HIGH and CRITICAL findings
shellhunter --path /var/www/html --severity-level high

# Export results to JSON
shellhunter --path /var/www/html --json-output report.json

# Deep scan with all heuristics
shellhunter --path /var/www/html --deep-scan --verbose

# Scan only PHP files
shellhunter --path /var/www/html --ext .php .phtml

# CI/CD pipeline usage
shellhunter --path /var/www/html --severity-level high --json-output report.json
# Exit code 1 if CRITICAL/HIGH findings exist, 0 if clean

# Include LOW severity findings (hidden by default)
shellhunter --path /var/www/html --severity-level low

# Exclude additional directories beyond the built-in defaults
shellhunter --path /var/www/html --exclude uploads cache tmp

# Scan vendor dirs too (disable built-in exclusions)
shellhunter --path /var/www/html --no-default-excludes

# Delete detected malicious files (irreversible — confirm before use)
shellhunter --path /var/www/html --delete --verbose
```

## Detection Rules

### Signatures (32 rules)

| Rule | Description | Severity |
|------|-------------|----------|
| SIG-001 | `eval($_POST/$_GET/$_REQUEST)` | CRITICAL |
| SIG-002 | `system/exec/passthru/shell_exec` with variable argument | CRITICAL |
| SIG-003 | `eval(base64_decode(...))` | CRITICAL |
| SIG-004 | Chained `gzinflate/str_rot13/base64_decode` | HIGH |
| SIG-005 | `preg_replace` with `/e` modifier | HIGH |
| SIG-006 | `fopen` + `fwrite` combo (dropper pattern) | HIGH |
| SIG-007 | `assert($_POST/$_GET/$_REQUEST)` | CRITICAL |
| SIG-008 | `base64_decode` on variable | MEDIUM |
| SIG-009 | `chmod 777` in code | MEDIUM |
| SIG-010 | Long hex-escaped string (>30 sequences) | MEDIUM |
| SIG-011 | `create_function()` | HIGH |
| SIG-012 | Bash reverse shell (`/dev/tcp`) | CRITICAL |
| SIG-013 | Netcat reverse shell (`nc -e`) | CRITICAL |
| SIG-014 | Python reverse shell (`socket` + `subprocess`) | HIGH |
| SIG-015 | `curl` piped to shell | HIGH |
| SIG-016 | `eval($variable)` on non-superglobal variable | HIGH |
| SIG-017 | Dynamic function name construction (`base64_decode` split across variables) | HIGH |
| SIG-018 | `error_reporting(0)` + `set_time_limit(0)` combo | MEDIUM |
| SIG-019 | Variable function call `$var($arg)` | HIGH |
| SIG-020 | Variable concatenation to build function name (`$a='sys'; $a.='tem'`) | CRITICAL |
| SIG-021 | Dangerous function assigned to variable then called (`$fn='system'; $fn(...)`) | CRITICAL |
| SIG-022 | Variable variable function execution (`$$fn()`, `${$fn}()`) | HIGH |
| SIG-023 | Session/Cookie variable used as callable (`$_SESSION['x']($cmd)`) | CRITICAL |
| SIG-024 | XOR decode loop (`chr(ord($s[$i]) ^ 0x42)`) | HIGH |
| SIG-025 | Multi-layer encoding: gzip + base64/rot13 (`gzinflate(base64_decode(...))`) | CRITICAL |
| SIG-026 | `fsockopen` to hardcoded IP (PHP reverse shell) | CRITICAL |
| SIG-027 | `include`/`require` with user-controlled path (Remote File Inclusion) | CRITICAL |
| SIG-028 | `strrev()` used to hide function names (`strrev('metsys')`) | HIGH |
| SIG-029 | GIF89a/GIF87a header with embedded PHP (polyglot file) | CRITICAL |
| SIG-030 | Known webshell string identifiers (c99shell, r57shell, b374k, WSO, IndoXploit, etc.) | CRITICAL |
| SIG-031 | `ini_set()` used to clear `disable_functions` or `open_basedir` | HIGH |
| SIG-032 | `array_map()` with dangerous callback string (`array_map('system', $_GET)`) | CRITICAL |

### Heuristics (9 rules)

| Rule | Description | Severity |
|------|-------------|----------|
| HEU-001 | Shannon entropy > 5.5 | MEDIUM |
| HEU-002 | Line exceeds 5000 characters | MEDIUM |
| HEU-003 | 5+ variable names longer than 20 characters | MEDIUM |
| HEU-004 | Comment ratio < 0.5% in files with 100+ lines | LOW |
| HEU-005 | 3+ encoding/decoding function calls | HIGH |
| HEU-006 | Small file (<4KB) with high function call density (deep-scan only) | MEDIUM |
| HEU-007 | 100+ string concatenation assignments (`.="`) — payload assembly | HIGH |
| HEU-008 | PHP code (`<?php`, `eval(`) found in non-PHP files (`.txt`, `.csv`, `.xml`, `.svg`) | HIGH |
| HEU-009 | Double or disguised file extension (e.g., `shell.php.pdf`, `image.jpg.php`) | HIGH |

### Metadata (4 rules)

| Rule | Description | Severity |
|------|-------------|----------|
| META-001 | File has 777 permissions | HIGH |
| META-002 | File is world-writable | MEDIUM |
| META-003 | Recently modified file in an old directory (possible implant) | MEDIUM |
| META-004 | Script file smaller than 200 bytes (possible one-liner shell) | MEDIUM |

## Scoring

- Each finding carries a score based on severity (CRITICAL: 35–45, HIGH: 25–30, MEDIUM: 15–20, LOW: 5–10)
- Risk score per file = sum of finding scores, capped at 0–100
- Results are sorted by risk score (highest first)

## --delete Mode

When `--delete` is passed, ShellHunter will permanently remove any file that has at least one CRITICAL or HIGH finding after scanning.

- A bold warning is printed before the scan begins
- Deleted files are logged and marked `[DELETED]` in the output
- The summary table shows a "Files deleted" count
- JSON output includes a `"deleted": true` field per result

**This action is irreversible.** Always run without `--delete` first to review findings before enabling auto-deletion.

## Security

- **Read-only by default** — never executes or modifies target files unless `--delete` is explicitly passed
- Pattern matching on raw bytes — no `eval()` or code execution internally
- File reads capped at 10MB; heuristic analysis capped at 2MB
- Symlink loop protection via inode tracking
- Graceful error handling: log and continue, no crashes
