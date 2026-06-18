"""
config_loader.py — shared helpers for reading suppress files and building ScanConfig.

suppress.txt format
───────────────────
Lines before any [section] header are global (applied to every scanner).
Lines under a [scanner-name] header apply only to that scanner.
Blank lines and lines starting with # are ignored.

Example:

    # Global — applied to all scanners
    CWE-798

    [presidio]
    pii_email
    pii_phone

    [gitleaks]
    aws-access-token
    generic-api-key

    [semgrep]
    python.lang.security.audit.formatted-sql-query

    [sonarqube]
    secrets:S6706
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models.finding import Finding


def parse_suppress_file(path: Path) -> tuple[set[str], dict[str, list[str]]]:
    """
    Parse a suppress.txt file.

    Returns:
        global_rules:      rule IDs that apply to every scanner
        per_scanner_rules: {scanner_name: [rule_ids]}
    """
    global_rules: set[str] = set()
    per_scanner: dict[str, list[str]] = {}
    current_section: str | None = None

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip().lower()
            if current_section not in per_scanner:
                per_scanner[current_section] = []
        elif current_section is None:
            global_rules.add(line)
        else:
            per_scanner[current_section].append(line)

    return global_rules, per_scanner


def suppress_findings(
    findings: list["Finding"],
    rules: set[str],
) -> list["Finding"]:
    """Return a filtered copy of *findings* with any finding whose rule_id or
    reference matches an entry in *rules* removed.

    Matching is exact on ``rule_id`` or prefix-based on references so that a
    rule like ``CWE-798`` suppresses ``CWE-798: Hard-coded credentials``.
    """
    if not rules:
        return findings

    def _is_suppressed(f: "Finding") -> bool:
        if f.rule_id in rules:
            return True
        for ref in f.references:
            for rule in rules:
                if ref == rule or ref.startswith(rule + ":") or ref.startswith(rule + " "):
                    return True
        return False

    return [f for f in findings if not _is_suppressed(f)]
