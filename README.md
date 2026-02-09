# ShellHunter

CLI tool untuk mendeteksi webshell, backdoor, dan malicious shell script pada server Linux. Dirancang untuk security audit pada server yang menjalankan WordPress, OJS, Laravel, dll. Bersifat **read-only** dan aman dijalankan di production.

## Instalasi

```bash
# Clone repository
git clone <repo-url> shellhunter
cd shellhunter

# Buat virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install -e .
```

Requirement: Python 3.10+

## Penggunaan

### Scan dasar

```bash
# Scan direktori saat ini
shellhunter

# Scan path tertentu
shellhunter --path /var/www/html

# Scan beberapa path sekaligus
shellhunter --path /var/www /home/user/public_html
```

### Opsi lengkap

```
shellhunter [OPTIONS]

--path PATH [PATH ...]     Path yang akan di-scan (default: direktori saat ini)
--ext EXT [EXT ...]        Ekstensi file yang di-scan (default: .php .phtml .php5 .php7 .sh .py .pl)
--deep-scan                Aktifkan heuristic tambahan (function density analysis)
--json-output FILE         Export hasil ke file JSON
--severity-level LEVEL     Minimum severity yang ditampilkan: low, medium, high, critical (default: low)
-v, --verbose              Tampilkan detail temuan (line number dan snippet)
--version                  Tampilkan versi
```

### Contoh penggunaan

```bash
# Scan dengan output detail
shellhunter --path /var/www/html --verbose

# Hanya tampilkan temuan HIGH dan CRITICAL
shellhunter --path /var/www/html --severity-level high

# Export hasil ke JSON
shellhunter --path /var/www/html --json-output report.json

# Deep scan dengan semua heuristic
shellhunter --path /var/www/html --deep-scan --verbose

# Scan hanya file PHP
shellhunter --path /var/www/html --ext .php .phtml

# Kombinasi untuk CI/CD pipeline
shellhunter --path /var/www/html --severity-level high --json-output report.json
# Exit code 1 jika ada temuan CRITICAL/HIGH, 0 jika bersih
```

## Deteksi

### Signature (15 rules)

| Rule | Deskripsi | Severity |
|------|-----------|----------|
| SIG-001 | `eval($_POST/$_GET/$_REQUEST)` | CRITICAL |
| SIG-002 | `system/exec/passthru/shell_exec` dengan variabel | CRITICAL |
| SIG-003 | `eval(base64_decode(...))` | CRITICAL |
| SIG-004 | Chain `gzinflate/str_rot13/base64_decode` | HIGH |
| SIG-005 | `preg_replace` dengan modifier `/e` | HIGH |
| SIG-006 | Kombinasi `fopen` + `fwrite` | HIGH |
| SIG-007 | `assert($_POST/$_GET/$_REQUEST)` | CRITICAL |
| SIG-008 | `base64_decode` pada variabel | MEDIUM |
| SIG-009 | `chmod 777` dalam kode | MEDIUM |
| SIG-010 | String hex-escaped panjang | MEDIUM |
| SIG-011 | `create_function()` | HIGH |
| SIG-012 | Bash reverse shell (`/dev/tcp`) | CRITICAL |
| SIG-013 | Netcat reverse shell (`nc -e`) | CRITICAL |
| SIG-014 | Python reverse shell (`socket` + `subprocess`) | HIGH |
| SIG-015 | `curl` pipe ke `bash` | HIGH |

### Heuristic (6 rules)

| Rule | Deskripsi | Severity |
|------|-----------|----------|
| HEU-001 | Shannon entropy > 5.5 | MEDIUM |
| HEU-002 | Baris > 5000 karakter | MEDIUM |
| HEU-003 | 5+ nama variabel > 20 karakter | MEDIUM |
| HEU-004 | Rasio komentar < 1% pada file 50+ baris | LOW |
| HEU-005 | 3+ panggilan fungsi encoding | HIGH |
| HEU-006 | File kecil (<4KB) dengan density fungsi tinggi (deep-scan) | MEDIUM |

### Metadata (3 rules)

| Rule | Deskripsi | Severity |
|------|-----------|----------|
| META-001 | Permission 777 | HIGH |
| META-002 | World-writable | MEDIUM |
| META-003 | File baru di direktori lama | MEDIUM |

## Scoring

- Setiap temuan memiliki skor berdasarkan severity (CRITICAL: 35-45, HIGH: 25-30, MEDIUM: 15-20, LOW: 5-10)
- Risk score per file = total skor temuan, capped 0-100
- Hasil diurutkan berdasarkan risk score tertinggi

## Keamanan

- **Read-only** — tidak pernah mengeksekusi atau memodifikasi file target
- Pattern matching pada raw bytes, tidak ada `eval()` atau eksekusi kode
- File read dibatasi 10MB, analisis heuristic dibatasi 2MB
- Symlink loop protection dengan inode tracking
- Error handling: log and continue, tidak crash
