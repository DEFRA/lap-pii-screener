"""ReviewSession and ReviewItem — persistent obfuscation review state.

Decision values
---------------
``pending``  — not yet reviewed.
``approved`` — user chose to obfuscate this finding.
``skipped``  — user chose to leave this finding as-is.
``manual``   — not automatically obfuscatable (archive / binary / decoded payload);
               requires manual remediation.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field

from models.finding import Finding
from obfuscation.strategies import get_replacement

Decision = Literal["pending", "approved", "skipped", "manual"]

# File extensions where in-place text replacement is not safe/possible
_NON_OBFUSCATABLE_EXTENSIONS: set[str] = {
    ".zip", ".gz", ".bz2", ".tar", ".tgz",
    ".docx", ".doc", ".xlsx", ".xls", ".pdf",
    ".rtf", ".eml", ".msg",
    ".orc", ".parquet", ".avro",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg",
    ".exe", ".dll", ".so", ".dylib", ".bin",
}


class ReviewItem(BaseModel):
    """One finding as it appears in the review session."""

    finding_id: str
    file: str
    line: int
    rule_id: str
    category: str
    severity: str
    scanners: list[str]
    # Redacted display string (e.g. "john****") shown in the TUI
    match_display: str
    # Raw matched text used by the engine to locate and replace the value.
    # None when the raw text was not captured (redacted scan or binary file).
    raw_match: Optional[str] = None
    # Placeholder token that will replace raw_match in the source file
    replacement: str
    # False for binary/archive/decoded-payload findings
    obfuscatable: bool = True
    # Human-readable explanation shown in the TUI / HTML report
    non_obfuscatable_reason: str = ""
    decision: Decision = "pending"
    # Optional auditor note recorded when decision == "skipped"
    skip_reason: str = ""
    # Confidence score copied from the originating Finding (0.0–1.0)
    confidence: float = 0.70
    # Obfuscation strategy: "redaction" (default) or "faker"
    obfuscation_strategy: str = "redaction"


class ReviewSession(BaseModel):
    """Full obfuscation review session for one scan run."""

    scan_id: str
    target_path: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    applied_at: Optional[datetime] = None
    items: list[ReviewItem] = Field(default_factory=list)

    # ── Convenience filters ───────────────────────────────────────────────────

    def pending(self) -> list[ReviewItem]:
        return [i for i in self.items if i.decision == "pending"]

    def approved(self) -> list[ReviewItem]:
        return [i for i in self.items if i.decision == "approved"]

    def skipped(self) -> list[ReviewItem]:
        return [i for i in self.items if i.decision == "skipped"]

    def manual(self) -> list[ReviewItem]:
        return [i for i in self.items if i.decision == "manual"]

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {"total": len(self.items), "pending": 0, "approved": 0, "skipped": 0, "manual": 0}
        for item in self.items:
            if item.decision in counts:
                counts[item.decision] += 1
        return counts

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: Path) -> Path:
        """Save the session to *path*.

        Falls back to ``~/.sensitive-scanner/sessions/<scan_id>.json`` if the
        target path is not writable.
        """
        path = Path(path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
            return path
        except PermissionError:
            fallback = (
                Path.home() / ".sensitive-scanner" / "sessions"
                / f"{self.scan_id}.json"
            )
            fallback.parent.mkdir(parents=True, exist_ok=True)
            fallback.write_text(self.model_dump_json(indent=2), encoding="utf-8")
            print(
                f"[warning] Could not write session to {path}\n"
                f"          Saved to fallback: {fallback}",
                file=sys.stderr,
            )
            return fallback

    @classmethod
    def load(cls, path: Path) -> "ReviewSession":
        """Load a previously saved session from *path*."""
        data = Path(path).read_text(encoding="utf-8")
        return cls.model_validate_json(data)

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_findings(
        cls,
        findings: list[Finding],
        scan_id: str,
        target_path: str,
        obfuscation_strategy: str = "redaction",
    ) -> "ReviewSession":
        """Create a new ReviewSession from a list of scan findings.

        Findings whose file extension is binary/archive, or whose raw match
        text was not captured, are automatically marked ``'manual'``.

        Args:
            findings: List of findings to review.
            scan_id: Scan ID for this session.
            target_path: Path to the scanned target.
            obfuscation_strategy: Strategy to use ("redaction" or "faker").
        """
        items: list[ReviewItem] = []
        for f in findings:
            ext = Path(f.file).suffix.lower()
            raw = f.match  # populated as raw text when show_secrets=True

            # Determine obfuscatability
            if ext in _NON_OBFUSCATABLE_EXTENSIONS:
                obfuscatable = False
                reason = f"Binary/archive file ({ext}) — replace manually"
            elif not raw or raw.endswith("****"):
                # match is still in redacted form — raw text not available
                obfuscatable = False
                reason = "Raw match not captured — re-run with show_secrets=True"
            else:
                obfuscatable = True
                reason = ""

            match_display = (
                Finding.redact(raw)
                if (raw and not raw.endswith("****"))
                else (raw or "")
            )

            # Generate replacement based on strategy
            if obfuscation_strategy == "faker":
                from obfuscation.faker_strategies import get_faker_replacement
                replacement = get_faker_replacement(f.category)
            else:
                from obfuscation.strategies import get_replacement
                replacement = get_replacement(f.category)

            items.append(ReviewItem(
                finding_id=f.id,
                file=f.file,
                line=f.line,
                rule_id=f.rule_id,
                category=f.category,
                severity=f.severity,
                confidence=f.confidence,
                scanners=f.scanners,
                match_display=match_display,
                raw_match=raw if obfuscatable else None,
                replacement=replacement,
                obfuscatable=obfuscatable,
                non_obfuscatable_reason=reason,
                decision="manual" if not obfuscatable else "pending",
                obfuscation_strategy=obfuscation_strategy,
            ))

        return cls(
            scan_id=scan_id,
            target_path=target_path,
            items=items,
        )
