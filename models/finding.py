from __future__ import annotations

import hashlib
from typing import Optional

from pydantic import BaseModel, Field


# Folders excluded from all scanners by default
_DEFAULT_EXCLUDE: list[str] = [
    ".git", ".vs", ".vscode", ".idea", ".fleet",
    "node_modules", ".npm",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", "venv", ".venv", "env",
    "dist", "build", "target", "out", "bin", "obj",
    ".gradle", ".mvn",
]


class ScanConfig(BaseModel):
    path: str
    scanners: list[str] = Field(default_factory=lambda: ["gitleaks", "semgrep", "presidio"])
    project_name: str = "project"
    include_git_history: bool = False
    sonar_host_url: str = ""
    sonar_token: str = ""
    sonar_project_key: str = ""
    exclude_paths: list[str] = Field(default_factory=lambda: list(_DEFAULT_EXCLUDE))
    exclude_files: list[str] = Field(default_factory=list)  # specific relative file paths
    exclude_patterns: list[str] = Field(default_factory=list)  # glob patterns, e.g. "**/*.min.js"
    suppress_by_scanner: dict[str, list[str]] = Field(default_factory=dict)  # {scanner: [rule_ids]}
    suppress_global: list[str] = Field(default_factory=list)  # applied across all scanners
    show_secrets: bool = False
    skip_comments: bool = False


class Finding(BaseModel):
    id: str
    # All scanners that contributed to this finding (merged duplicates keep both)
    scanners: list[str] = Field(default_factory=list)
    category: str
    severity: str  # critical | high | medium | low | info
    confidence: float = 0.70  # 0.0–1.0; set per scanner, boosted when multiple scanners agree
    file: str
    line: int
    match: str  # redacted: first 4 chars + ****
    rule_id: str
    message: str = ""
    remediation_description: str = ""
    fix_steps: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    regulations: list[str] = Field(default_factory=list)  # e.g. ["UK-GDPR-PD", "PSR-2017"]

    @staticmethod
    def make_id(file: str, line: int, rule_id: str) -> str:
        raw = f"{file}:{line}:{rule_id}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def redact(value: str) -> str:
        """Show first 4 characters then **** to aid identification without exposing secrets."""
        if not value:
            return "****"
        visible = value[:4] if len(value) >= 4 else value
        return f"{visible}****"
