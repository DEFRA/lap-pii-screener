from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from models.finding import Finding


class ScanSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    lines_scanned: int = 0
    lines_skipped: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_scanner: dict[str, int] = Field(default_factory=dict)


class Report(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    target_path: str
    project_name: str
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    tier_used: int = 1  # 1=native binaries, 2=container, 3=cloud
    scanners_run: list[str] = Field(default_factory=list)
    scanner_durations: dict[str, float] = Field(default_factory=dict)  # scanner -> seconds
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)

    def build_summary(self) -> None:
        s = ScanSummary()
        s.total = len(self.findings)
        for f in self.findings:
            match f.severity:
                case "critical":
                    s.critical += 1
                case "high":
                    s.high += 1
                case "medium":
                    s.medium += 1
                case "low":
                    s.low += 1
                case _:
                    s.info += 1
            s.by_category[f.category] = s.by_category.get(f.category, 0) + 1
            for scanner in f.scanners:
                s.by_scanner[scanner] = s.by_scanner.get(scanner, 0) + 1
        self.summary = s
