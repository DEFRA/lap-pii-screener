from __future__ import annotations

import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from models.finding import Finding, ScanConfig
from models.report import Report
from remediation.engine import RemediationEngine
from scanners.base import AbstractScanner
from scanners.gitleaks_scanner import GitleaksScanner
from scanners.pii_scanner import PIIScanner
from scanners.semgrep_scanner import SemgrepScanner
from scanners.sonarqube_scanner import SonarQubeScanner

_REPORT_CACHE = Path.home() / ".sensitive-scanner" / "last_report.json"

# Severity rank used for deduplication and report sorting (lower = more severe)
_SEV_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_ALL_SCANNERS: dict[str, AbstractScanner] = {
    "gitleaks": GitleaksScanner(),
    "semgrep": SemgrepScanner(),
    "sonarqube": SonarQubeScanner(),
    "presidio": PIIScanner(),
}


async def detect_available_scanners(requested: list[str]) -> tuple[list[AbstractScanner], int]:
    """
    From the requested scanner names, return only those that are available
    in the current environment, plus the active tier number (1–3).
    """
    available: list[AbstractScanner] = []
    tier = 1

    checks = {name: scanner for name, scanner in _ALL_SCANNERS.items() if name in requested}
    results = await asyncio.gather(
        *(s.is_available() for s in checks.values()), return_exceptions=False
    )

    for (name, scanner), ok in zip(checks.items(), results):
        if ok:
            available.append(scanner)
            if name == "sonarqube":
                tier = 3 if "sonarcloud.io" in str(scanner) else 2

    return available, tier


def _apply_suppression_per_scanner(
    scanners: list[AbstractScanner],
    all_results: list[list[Finding]],
    config: ScanConfig,
) -> list[list[Finding]]:
    """Apply per-scanner and global rule suppression to raw scan results."""
    global_rules: set[str] = set(config.suppress_global)
    filtered: list[list[Finding]] = []
    for scanner, results in zip(scanners, all_results):
        rules = global_rules | set(config.suppress_by_scanner.get(scanner.name, []))
        if rules:
            results = [
                f for f in results
                if f.rule_id not in rules
                and not any(
                    ref == r or ref.startswith(r + ":") or ref.startswith(r + " ")
                    for ref in f.references for r in rules
                )
            ]
        filtered.append(results)
    return filtered


def _build_report(
    config: ScanConfig,
    findings: list[Finding],
    scan_start: float,
    tier: int,
    scanner_names: list[str],
    scanner_durations: dict[str, float],
    scanners: list[AbstractScanner],
) -> Report:
    """Assemble a Report from scan results and populate summary fields."""
    import time
    report = Report(
        scan_id=str(uuid.uuid4())[:8],
        target_path=config.path,
        project_name=config.project_name,
        scanned_at=datetime.now(timezone.utc),
        duration_seconds=round(time.monotonic() - scan_start, 2),
        tier_used=tier,
        scanners_run=scanner_names,
        scanner_durations=scanner_durations,
        findings=findings,
    )
    report.build_summary()
    pii_scanner = next((s for s in scanners if s.name == "presidio"), None)
    if pii_scanner is not None:
        report.summary.files_scanned = getattr(pii_scanner, "_files_scanned", 0)
        report.summary.files_skipped = getattr(pii_scanner, "_files_skipped", 0)
        report.summary.lines_scanned = getattr(pii_scanner, "_lines_scanned", 0)
        report.summary.lines_skipped = getattr(pii_scanner, "_lines_skipped", 0)
    return report


async def run_scan(config: ScanConfig) -> Report:
    """
    Orchestrate all requested scanners in parallel, deduplicate, attach
    remediation, build and cache a Report.
    """
    import time
    _scan_start = time.monotonic()
    requested = config.scanners or ["gitleaks", "semgrep", "presidio"]
    scanners, tier = await detect_available_scanners(requested)

    if not scanners:
        print("[orchestrator] No scanners available.", file=sys.stderr)
        scanners = [_ALL_SCANNERS["presidio"]]  # presidio scanner always works

    scanner_names = [s.name for s in scanners]
    print(f"[orchestrator] Running scanners: {scanner_names} (Tier {tier})", file=sys.stderr)

    # Run all scanners in parallel, each timed individually
    _scanner_durations: dict[str, float] = {}

    async def _timed(scanner: AbstractScanner) -> list[Finding]:
        t0 = time.monotonic()
        results = await scanner.scan(config)
        elapsed = round(time.monotonic() - t0, 1)
        _scanner_durations[scanner.name] = elapsed
        print(f"[orchestrator] {scanner.name}: {len(results)} finding(s) in {elapsed}s", file=sys.stderr)
        return results

    all_results: list[list[Finding]] = await asyncio.gather(
        *(_timed(s) for s in scanners), return_exceptions=False
    )

    filtered_results = _apply_suppression_per_scanner(scanners, all_results, config)

    # Flatten and deduplicate
    raw: list[Finding] = [f for batch in filtered_results for f in batch]
    findings = _deduplicate(raw)
    findings = _filter_inline_suppressions(findings, config.path)

    report = _build_report(config, findings, _scan_start, tier, scanner_names, _scanner_durations, scanners)
    _cache_report(report)
    return report


def _filter_inline_suppressions(findings: list[Finding], scan_root: str) -> list[Finding]:
    """
    Remove findings whose source line contains a noscan marker (case-insensitive).

    Supported forms (any comment style, any language):
        noscan              — suppress all findings on this line
        noscan: rule_id     — suppress only the named rule on this line

    Examples:
        password = "abc123"  # noscan
        api_key = get_key()  # noscan: hardcoded_password
        const token = "x";   // noscan
    """
    root = Path(scan_root)
    _file_lines: dict[str, list[str]] = {}

    def _lines(rel: str) -> list[str]:
        if rel not in _file_lines:
            try:
                _file_lines[rel] = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                _file_lines[rel] = []
        return _file_lines[rel]

    kept = []
    for f in findings:
        lines = _lines(f.file)
        line_text = lines[f.line - 1].lower() if 0 < f.line <= len(lines) else ""
        if "noscan" in line_text:
            # Check for rule-specific form: noscan: rule_id
            colon_pos = line_text.find("noscan:")
            if colon_pos != -1:
                # Only suppress if the rule_id matches
                target_rule = line_text[colon_pos + 7:].split()[0].rstrip(".,;*/") if line_text[colon_pos + 7:].split() else ""
                if target_rule and target_rule != f.rule_id.lower():
                    kept.append(f)  # different rule — keep it
                    continue
            continue  # bare noscan or matched rule — suppress
        kept.append(f)
    return kept


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Three-pass deduplication:

    Pass 1 — (file, line, rule_id): same rule fired by multiple scanners on the
             same line — merge scanner lists.
    Pass 2 — (file, line, match): different rules, identical match string on the
             same line — keep higher severity, merge scanners.
    Pass 3 — (file, line, category): same line, same category, different match
             text or rule (e.g. `pii_person_name` vs `presidio_person_name`) —
             keep higher severity, merge scanners.
    """
    def _merge(existing: Finding, incoming: Finding) -> Finding:
        """Return the higher-severity finding with merged scanner list and boosted confidence."""
        winner = incoming if _SEV_RANK.get(incoming.severity, 5) < _SEV_RANK.get(existing.severity, 5) else existing
        merged_scanners = list(dict.fromkeys(existing.scanners + incoming.scanners))
        # Each additional agreeing scanner adds 8% confidence, capped at 99%
        multi_boost = 0.08 * (len(merged_scanners) - 1)
        merged_confidence = min(0.99, max(existing.confidence, incoming.confidence) + multi_boost)
        return winner.model_copy(update={"scanners": merged_scanners, "confidence": round(merged_confidence, 4)})

    # ── Pass 1: merge by (file, line, rule_id) ─────────────────────────────
    seen: dict[str, Finding] = {}
    for f in findings:
        key = Finding.make_id(f.file, f.line, f.rule_id)
        if key in seen:
            seen[key] = _merge(seen[key], f)
        else:
            seen[key] = f

    # ── Pass 2: merge by (file, line, match) — same value, different rule ──
    by_match: dict[tuple[str, int, str], Finding] = {}
    for f in seen.values():
        loc_key = (f.file, f.line, f.match)
        if loc_key in by_match:
            by_match[loc_key] = _merge(by_match[loc_key], f)
        else:
            by_match[loc_key] = f

    # ── Pass 3: merge by (file, line, category) — same line, same category, different match/rule ──
    by_line: dict[tuple[str, int, str], Finding] = {}
    for f in by_match.values():
        line_key = (f.file, f.line, f.category)
        if line_key in by_line:
            by_line[line_key] = _merge(by_line[line_key], f)
        else:
            by_line[line_key] = f

    return sorted(by_line.values(), key=_severity_order)


def _severity_order(f: Finding) -> tuple[int, str]:
    return (_SEV_RANK.get(f.severity, 5), f.file)


def _cache_report(report: Report) -> None:
    _REPORT_CACHE.parent.mkdir(parents=True, exist_ok=True)
    _REPORT_CACHE.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def load_cached_report() -> Optional[Report]:
    if not _REPORT_CACHE.exists():
        return None
    try:
        data = json.loads(_REPORT_CACHE.read_text(encoding="utf-8"))
        return Report.model_validate(data)
    except Exception as exc:
        print(f"[orchestrator] Could not load cached report: {exc}", file=sys.stderr)
        return None
