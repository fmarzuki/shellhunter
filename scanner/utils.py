import logging
import os
import stat
import time
from pathlib import Path

from .models import DetectionType, Finding, Severity

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

DEFAULT_PATHS = ["/var/www", "/home", "/public_html"]
DEFAULT_EXTENSIONS = {".php", ".phtml", ".php5", ".php7", ".sh", ".py", ".pl"}


def discover_files(
    root: str,
    extensions: set[str] | None = None,
) -> list[str]:
    """Walk directory tree collecting files by extension. Symlink-loop safe."""
    if extensions is None:
        extensions = DEFAULT_EXTENSIONS
    found: list[str] = []
    seen_inodes: set[tuple[int, int]] = set()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        try:
            dir_stat = os.stat(dirpath)
            inode_key = (dir_stat.st_dev, dir_stat.st_ino)
            if inode_key in seen_inodes:
                dirnames.clear()
                continue
            seen_inodes.add(inode_key)
        except OSError:
            dirnames.clear()
            continue

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            _, ext = os.path.splitext(fname)
            if ext.lower() in extensions:
                found.append(fpath)
    return found


def read_file_safe(path: str) -> bytes | None:
    """Read file up to MAX_FILE_SIZE. Returns None on error."""
    try:
        size = os.path.getsize(path)
        if size > MAX_FILE_SIZE:
            logger.warning("Skipping %s: exceeds 10MB limit (%d bytes)", path, size)
            return None
        with open(path, "rb") as f:
            return f.read(MAX_FILE_SIZE)
    except OSError as e:
        logger.debug("Cannot read %s: %s", path, e)
        return None


class MetadataAnalyzer:
    """Analyze file metadata for suspicious attributes."""

    def analyze(self, path: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            st = os.stat(path)
        except OSError:
            return findings

        mode = st.st_mode

        # META-001: 777 permissions
        if stat.S_ISREG(mode) and (mode & 0o777) == 0o777:
            findings.append(Finding(
                rule_id="META-001",
                detection_type=DetectionType.METADATA,
                description="File has 777 permissions (world-readable/writable/executable)",
                severity=Severity.HIGH,
                score=25,
            ))

        # META-002: World-writable
        elif stat.S_ISREG(mode) and (mode & stat.S_IWOTH):
            findings.append(Finding(
                rule_id="META-002",
                detection_type=DetectionType.METADATA,
                description="File is world-writable",
                severity=Severity.MEDIUM,
                score=15,
            ))

        # META-003: Timestamp anomaly - file much newer than its parent directory
        try:
            parent_dir = os.path.dirname(path)
            parent_st = os.stat(parent_dir)
            file_age = time.time() - st.st_mtime
            dir_age = time.time() - parent_st.st_mtime
            # Flag if file is < 7 days old but directory is > 90 days old
            if file_age < 7 * 86400 and dir_age > 90 * 86400:
                findings.append(Finding(
                    rule_id="META-003",
                    detection_type=DetectionType.METADATA,
                    description="Recently modified file in old directory (possible implant)",
                    severity=Severity.MEDIUM,
                    score=15,
                ))
        except OSError:
            pass

        return findings
