# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Run the tool
shellhunter --path /var/www/html
shellhunter --path . --deep-scan --verbose
shellhunter --path . --severity-level high --json-output report.json

# Run directly (without installing)
python -m scanner.main --path .
```

There is no test suite currently. There are no lint or type-check configurations defined.

## Architecture

`ShellHunterAnalyzer` in `scanner/analyzer.py` is the orchestrator. For each discovered file, it runs three analysis passes in sequence:

1. **Metadata** (`scanner/utils.py` → `MetadataAnalyzer`): File permissions, timestamps, and size anomalies. Produces META-001 through META-004 findings.

2. **Signature** (`scanner/signature.py` → `SignatureScanner`): Regex matching against `SIGNATURE_RULES` (a list of compiled byte-patterns). All patterns are compiled at module import time against raw bytes. Produces SIG-001 through SIG-032 findings.

3. **Heuristic** (`scanner/heuristic.py` → `HeuristicAnalyzer`): Statistical and structural analysis — Shannon entropy, line length, variable name length, comment ratio, encoding call count, string concatenation density, and file extension checks. Some checks (HEU-006) only run with `--deep-scan`. Produces HEU-001 through HEU-009 findings.

### Data flow

```
CLI args → ShellHunterAnalyzer
  → discover_files() (utils.py) — walks dirs, filters by extension, tracks inodes
  → per-file: MetadataAnalyzer + SignatureScanner + HeuristicAnalyzer
  → findings filtered by --severity-level
  → risk_score computed (sum of finding scores, capped 0–100)
  → ScanSummary sorted by risk_score desc
  → reporter.py: print to stdout / export JSON
```

### Key conventions

- All file content is read as **bytes** (`rb` mode). Signature patterns are compiled as `bytes` patterns (`rb'...'`). This avoids encoding issues.
- Progress and status output go to **stderr**; scan results go to **stdout** (pipeable).
- Exit code `1` if any CRITICAL or HIGH findings exist; `0` otherwise. Suitable for CI/CD use.
- Files over 10MB are skipped; heuristic analysis is capped at 2MB.
- `--delete` mode removes files with CRITICAL or HIGH findings. This is irreversible — always run without `--delete` first.

### Adding new detection rules

- **New signature**: Add a tuple to `SIGNATURE_RULES` in `scanner/signature.py`. Follow the `(rule_id, compiled_bytes_pattern, description, Severity, score)` format. Score ranges: CRITICAL 35–45, HIGH 25–30, MEDIUM 15–20, LOW 5–10.
- **New heuristic**: Add a check in `HeuristicAnalyzer.analyze()` in `scanner/heuristic.py`. Use `deep_scan` flag to gate expensive checks.
- **New metadata check**: Add to `MetadataAnalyzer.analyze()` in `scanner/utils.py`.
