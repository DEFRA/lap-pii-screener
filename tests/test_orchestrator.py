"""Tests for scanners.orchestrator — suppression, deduplication, inline noscan, caching."""
from __future__ import annotations

from pathlib import Path

import pytest

from models.finding import Finding, ScanConfig
from models.report import Report
from scanners.base import AbstractScanner
from scanners import orchestrator
from scanners.orchestrator import (
    _apply_suppression_per_scanner,
    _build_report,
    _cache_report,
    _deduplicate,
    _filter_inline_suppressions,
    _line_suppresses_finding,
    _severity_order,
    detect_available_scanners,
    load_cached_report,
    run_scan,
)


def _finding(
    *,
    rule_id: str = "rule-a",
    category: str = "generic_secret",
    severity: str = "high",
    file: str = "app/config.py",
    line: int = 10,
    match: str = "sk_live_abcd",
    scanners: list[str] | None = None,
    references: list[str] | None = None,
    confidence: float = 0.70,
) -> Finding:
    return Finding(
        id=Finding.make_id(file, line, rule_id),
        rule_id=rule_id,
        category=category,
        severity=severity,
        file=file,
        line=line,
        match=match,
        scanners=scanners or ["gitleaks"],
        references=references or [],
        confidence=confidence,
    )


class _StubScanner(AbstractScanner):
    """Configurable in-memory scanner for orchestrator tests."""

    def __init__(self, name: str, *, available: bool = True, findings: list[Finding] | None = None) -> None:
        self._name = name
        self._available = available
        self._findings = findings or []

    @property
    def name(self) -> str:
        return self._name

    async def is_available(self) -> bool:
        return self._available

    async def scan(self, config: ScanConfig) -> list[Finding]:
        return list(self._findings)


# --------------------------------------------------------------------------- #
# detect_available_scanners                                                    #
# --------------------------------------------------------------------------- #


class TestDetectAvailableScanners:
    @pytest.mark.asyncio
    async def test_returns_only_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = {
            "gitleaks": _StubScanner("gitleaks", available=True),
            "semgrep": _StubScanner("semgrep", available=False),
            "presidio": _StubScanner("presidio", available=True),
        }
        monkeypatch.setattr(orchestrator, "_ALL_SCANNERS", stubs)

        available, tier = await detect_available_scanners(["gitleaks", "semgrep", "presidio"])

        names = {s.name for s in available}
        assert names == {"gitleaks", "presidio"}
        assert tier == 1

    @pytest.mark.asyncio
    async def test_ignores_unrequested(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = {
            "gitleaks": _StubScanner("gitleaks", available=True),
            "presidio": _StubScanner("presidio", available=True),
        }
        monkeypatch.setattr(orchestrator, "_ALL_SCANNERS", stubs)

        available, _ = await detect_available_scanners(["gitleaks"])

        assert [s.name for s in available] == ["gitleaks"]

    @pytest.mark.asyncio
    async def test_sonarqube_local_is_tier_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = {"sonarqube": _StubScanner("sonarqube", available=True)}
        monkeypatch.setattr(orchestrator, "_ALL_SCANNERS", stubs)

        _, tier = await detect_available_scanners(["sonarqube"])

        assert tier == 2


# --------------------------------------------------------------------------- #
# _apply_suppression_per_scanner                                               #
# --------------------------------------------------------------------------- #


class TestApplySuppressionPerScanner:
    def test_no_rules_returns_unchanged(self) -> None:
        scanner = _StubScanner("gitleaks")
        results = [[_finding(rule_id="r1"), _finding(rule_id="r2")]]
        config = ScanConfig(path="/p")

        out = _apply_suppression_per_scanner([scanner], results, config)

        assert out == results

    def test_global_rule_suppressed(self) -> None:
        scanner = _StubScanner("gitleaks")
        results = [[_finding(rule_id="drop-me"), _finding(rule_id="keep-me")]]
        config = ScanConfig(path="/p", suppress_global=["drop-me"])

        out = _apply_suppression_per_scanner([scanner], results, config)

        assert [f.rule_id for f in out[0]] == ["keep-me"]

    def test_per_scanner_rule_suppressed(self) -> None:
        scanner = _StubScanner("gitleaks")
        results = [[_finding(rule_id="gl-only")]]
        config = ScanConfig(path="/p", suppress_by_scanner={"gitleaks": ["gl-only"]})

        out = _apply_suppression_per_scanner([scanner], results, config)

        assert out[0] == []

    def test_suppression_via_reference_prefix(self) -> None:
        scanner = _StubScanner("semgrep")
        results = [[_finding(rule_id="x", references=["CWE-89: SQL injection"])]]
        config = ScanConfig(path="/p", suppress_global=["CWE-89"])

        out = _apply_suppression_per_scanner([scanner], results, config)

        assert out[0] == []


# --------------------------------------------------------------------------- #
# _deduplicate                                                                 #
# --------------------------------------------------------------------------- #


class TestDeduplicate:
    def test_pass1_same_rule_merges_scanners(self) -> None:
        a = _finding(rule_id="r1", scanners=["gitleaks"])
        b = _finding(rule_id="r1", scanners=["semgrep"])

        out = _deduplicate([a, b])

        assert len(out) == 1
        assert set(out[0].scanners) == {"gitleaks", "semgrep"}

    def test_pass2_same_match_keeps_higher_severity(self) -> None:
        a = _finding(rule_id="r1", severity="low", match="abcd", scanners=["gitleaks"])
        b = _finding(rule_id="r2", severity="critical", match="abcd", scanners=["semgrep"])

        out = _deduplicate([a, b])

        assert len(out) == 1
        assert out[0].severity == "critical"
        assert set(out[0].scanners) == {"gitleaks", "semgrep"}

    def test_pass3_same_category_merges(self) -> None:
        a = _finding(rule_id="pii_person_name", category="pii_person_name", match="John", severity="medium")
        b = _finding(rule_id="presidio_person", category="pii_person_name", match="Smith", severity="high")

        out = _deduplicate([a, b])

        assert len(out) == 1
        assert out[0].severity == "high"

    def test_confidence_boost_on_merge(self) -> None:
        a = _finding(rule_id="r1", scanners=["gitleaks"], confidence=0.70)
        b = _finding(rule_id="r1", scanners=["semgrep"], confidence=0.70)

        out = _deduplicate([a, b])

        assert out[0].confidence == pytest.approx(0.78)

    def test_distinct_findings_preserved_and_sorted(self) -> None:
        low = _finding(rule_id="r-low", severity="low", line=1)
        crit = _finding(rule_id="r-crit", severity="critical", line=2)

        out = _deduplicate([low, crit])

        assert [f.severity for f in out] == ["critical", "low"]


# --------------------------------------------------------------------------- #
# _severity_order                                                              #
# --------------------------------------------------------------------------- #


class TestSeverityOrder:
    def test_known_severity_rank(self) -> None:
        assert _severity_order(_finding(severity="critical", file="a"))[0] == 0
        assert _severity_order(_finding(severity="info", file="a"))[0] == 4

    def test_unknown_severity_defaults_to_5(self) -> None:
        assert _severity_order(_finding(severity="bogus", file="a"))[0] == 5


# --------------------------------------------------------------------------- #
# _line_suppresses_finding                                                     #
# --------------------------------------------------------------------------- #


class TestLineSuppressesFinding:
    def test_no_marker(self) -> None:
        assert _line_suppresses_finding('password = "x"', "rule") is False

    def test_bare_noscan_suppresses(self) -> None:
        assert _line_suppresses_finding('password = "x"  # noscan', "rule") is True

    def test_rule_specific_match(self) -> None:
        assert _line_suppresses_finding("api = k()  # noscan: hardcoded_password", "hardcoded_password") is True

    def test_rule_specific_non_match_keeps(self) -> None:
        assert _line_suppresses_finding("api = k()  # noscan: other_rule", "hardcoded_password") is False


# --------------------------------------------------------------------------- #
# _filter_inline_suppressions                                                  #
# --------------------------------------------------------------------------- #


class TestFilterInlineSuppressions:
    def test_suppresses_marked_line(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text('secret = "abcd"  # noscan\nkeep = "efgh"\n', encoding="utf-8")
        findings = [
            _finding(file="app.py", line=1),
            _finding(file="app.py", line=2),
        ]

        out = _filter_inline_suppressions(findings, str(tmp_path))

        assert [f.line for f in out] == [2]

    def test_missing_file_keeps_finding(self, tmp_path: Path) -> None:
        findings = [_finding(file="ghost.py", line=1)]

        out = _filter_inline_suppressions(findings, str(tmp_path))

        assert out == findings

    def test_line_out_of_range_keeps_finding(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("only one line\n", encoding="utf-8")
        findings = [_finding(file="app.py", line=99)]

        out = _filter_inline_suppressions(findings, str(tmp_path))

        assert out == findings


# --------------------------------------------------------------------------- #
# _build_report                                                                #
# --------------------------------------------------------------------------- #


class TestBuildReport:
    def test_populates_core_fields(self) -> None:
        config = ScanConfig(path="/project", project_name="proj")
        findings = [_finding(severity="high")]

        report = _build_report(config, findings, scan_start=0.0, tier=2,
                               scanner_names=["gitleaks"], scanner_durations={"gitleaks": 1.0},
                               scanners=[_StubScanner("gitleaks")])

        assert report.target_path == "/project"
        assert report.tier_used == 2
        assert report.scanners_run == ["gitleaks"]
        assert report.summary.total == 1

    def test_pulls_pii_scanner_stats(self) -> None:
        pii = _StubScanner("presidio")
        pii._files_scanned = 7  # type: ignore[attr-defined]
        pii._lines_scanned = 42  # type: ignore[attr-defined]
        config = ScanConfig(path="/p")

        report = _build_report(config, [], scan_start=0.0, tier=1,
                               scanner_names=["presidio"], scanner_durations={},
                               scanners=[pii])

        assert report.summary.files_scanned == 7
        assert report.summary.lines_scanned == 42


# --------------------------------------------------------------------------- #
# caching                                                                      #
# --------------------------------------------------------------------------- #


class TestCaching:
    def test_cache_and_load_roundtrip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cache_file = tmp_path / "last_report.json"
        monkeypatch.setattr(orchestrator, "_REPORT_CACHE", cache_file)
        report = Report(target_path="/p", project_name="proj", scanners_run=["gitleaks"],
                        findings=[_finding()])
        report.build_summary()

        _cache_report(report)
        loaded = load_cached_report()

        assert loaded is not None
        assert loaded.target_path == "/p"
        assert len(loaded.findings) == 1

    def test_load_missing_returns_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(orchestrator, "_REPORT_CACHE", tmp_path / "nope.json")

        assert load_cached_report() is None

    def test_load_corrupt_returns_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        monkeypatch.setattr(orchestrator, "_REPORT_CACHE", bad)

        assert load_cached_report() is None


# --------------------------------------------------------------------------- #
# run_scan (integration with stub scanners)                                    #
# --------------------------------------------------------------------------- #


class TestRunScan:
    @pytest.mark.asyncio
    async def test_runs_and_caches(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        stub = _StubScanner("gitleaks", available=True, findings=[_finding(file="x.py", line=1)])
        monkeypatch.setattr(orchestrator, "_ALL_SCANNERS", {"gitleaks": stub})
        monkeypatch.setattr(orchestrator, "_REPORT_CACHE", tmp_path / "rep.json")

        report = await run_scan(ScanConfig(path=str(tmp_path), scanners=["gitleaks"]))

        assert report.summary.total == 1
        assert (tmp_path / "rep.json").exists()

    @pytest.mark.asyncio
    async def test_falls_back_to_presidio_when_none_available(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        unavailable = _StubScanner("gitleaks", available=False)
        presidio = _StubScanner("presidio", available=False, findings=[])
        monkeypatch.setattr(
            orchestrator, "_ALL_SCANNERS",
            {"gitleaks": unavailable, "presidio": presidio},
        )
        monkeypatch.setattr(orchestrator, "_REPORT_CACHE", tmp_path / "rep.json")

        report = await run_scan(ScanConfig(path=str(tmp_path), scanners=["gitleaks"]))

        assert "presidio" in report.scanners_run
