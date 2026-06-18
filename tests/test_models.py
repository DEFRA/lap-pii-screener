"""Tests for models.finding and models.report."""
from __future__ import annotations

from models.finding import Finding, ScanConfig, _DEFAULT_EXCLUDE
from models.report import Report, ScanSummary


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _finding(
    *,
    severity: str = "high",
    category: str = "generic_secret",
    line: int = 10,
    scanners: list[str] | None = None,
) -> Finding:
    return Finding(
        id=Finding.make_id("file.py", line, "test-rule"),
        rule_id="test-rule",
        category=category,
        severity=severity,
        file="file.py",
        line=line,
        match="abcd****",
        scanners=scanners or ["presidio"],
    )


# --------------------------------------------------------------------------- #
# ScanConfig                                                                   #
# --------------------------------------------------------------------------- #


class TestScanConfig:
    def test_default_scanners(self) -> None:
        config = ScanConfig(path="/tmp/repo")

        assert "gitleaks" in config.scanners
        assert "presidio" in config.scanners

    def test_default_project_name(self) -> None:
        assert ScanConfig(path="/tmp/repo").project_name == "project"

    def test_default_flags_are_false(self) -> None:
        config = ScanConfig(path="/tmp/repo")

        assert config.include_git_history is False
        assert config.show_secrets is False
        assert config.skip_comments is False

    def test_default_exclude_paths_populated(self) -> None:
        config = ScanConfig(path="/tmp/repo")

        assert ".git" in config.exclude_paths
        assert "node_modules" in config.exclude_paths
        assert ".venv" in config.exclude_paths

    def test_custom_values(self) -> None:
        config = ScanConfig(
            path="/tmp/repo",
            scanners=["presidio"],
            project_name="my-project",
            show_secrets=True,
            skip_comments=True,
        )

        assert config.scanners == ["presidio"]
        assert config.project_name == "my-project"
        assert config.show_secrets is True
        assert config.skip_comments is True

    def test_default_exclude_constant_has_expected_entries(self) -> None:
        assert "node_modules" in _DEFAULT_EXCLUDE
        assert ".venv" in _DEFAULT_EXCLUDE
        assert "__pycache__" in _DEFAULT_EXCLUDE
        assert "dist" in _DEFAULT_EXCLUDE

    def test_suppress_fields_default_empty(self) -> None:
        config = ScanConfig(path="/tmp/repo")

        assert config.suppress_global == []
        assert config.suppress_by_scanner == {}
        assert config.exclude_files == []
        assert config.exclude_patterns == []


# --------------------------------------------------------------------------- #
# Finding                                                                      #
# --------------------------------------------------------------------------- #


class TestFinding:
    def test_make_id_is_deterministic(self) -> None:
        id1 = Finding.make_id("file.py", 10, "rule")
        id2 = Finding.make_id("file.py", 10, "rule")

        assert id1 == id2

    def test_make_id_is_sixteen_chars(self) -> None:
        assert len(Finding.make_id("file.py", 1, "rule")) == 16

    def test_make_id_differs_for_different_file(self) -> None:
        assert Finding.make_id("a.py", 1, "rule") != Finding.make_id("b.py", 1, "rule")

    def test_make_id_differs_for_different_line(self) -> None:
        assert Finding.make_id("file.py", 1, "rule") != Finding.make_id("file.py", 2, "rule")

    def test_make_id_differs_for_different_rule(self) -> None:
        assert Finding.make_id("file.py", 1, "rule-a") != Finding.make_id("file.py", 1, "rule-b")

    def test_redact_empty_string(self) -> None:
        assert Finding.redact("") == "****"

    def test_redact_two_char_string(self) -> None:
        result = Finding.redact("ab")

        assert result == "ab****"

    def test_redact_exactly_four_chars(self) -> None:
        result = Finding.redact("abcd")

        assert result == "abcd****"

    def test_redact_long_string_shows_first_four(self) -> None:
        result = Finding.redact("sk_live_abcdef123456")

        assert result == "sk_l****"

    def test_finding_default_confidence(self) -> None:
        f = _finding()

        assert f.confidence == 0.70

    def test_finding_default_collections_empty(self) -> None:
        f = _finding()

        assert f.references == []
        assert f.fix_steps == []
        assert f.regulations == []
        assert f.message == ""
        assert f.remediation_description == ""

    def test_finding_construction_with_references(self) -> None:
        f = Finding(
            id=Finding.make_id("f.py", 1, "r"),
            rule_id="r",
            category="pii_email",
            severity="medium",
            file="f.py",
            line=1,
            match="john****",
            scanners=["presidio"],
            references=["CWE-359", "GDPR-Art-5"],
        )

        assert "CWE-359" in f.references
        assert "GDPR-Art-5" in f.references


# --------------------------------------------------------------------------- #
# Report and ScanSummary                                                       #
# --------------------------------------------------------------------------- #


class TestScanSummary:
    def test_defaults_are_zero(self) -> None:
        s = ScanSummary()

        assert s.total == 0
        assert s.critical == 0
        assert s.high == 0
        assert s.medium == 0
        assert s.low == 0
        assert s.info == 0
        assert s.files_scanned == 0
        assert s.by_category == {}
        assert s.by_scanner == {}


class TestReport:
    def test_scan_id_auto_generated(self) -> None:
        r = Report(target_path="/tmp", project_name="test")

        assert len(r.scan_id) == 8

    def test_two_reports_have_different_ids(self) -> None:
        r1 = Report(target_path="/tmp", project_name="test")
        r2 = Report(target_path="/tmp", project_name="test")

        assert r1.scan_id != r2.scan_id

    def test_build_summary_empty_findings(self) -> None:
        report = Report(target_path="/tmp", project_name="test", findings=[])
        report.build_summary()

        assert report.summary.total == 0
        assert report.summary.critical == 0

    def test_build_summary_counts_all_severity_levels(self) -> None:
        findings = [
            _finding(severity="critical"),
            _finding(severity="high", line=20),
            _finding(severity="medium", line=30),
            _finding(severity="low", line=40),
            _finding(severity="info", line=50),
        ]
        report = Report(target_path="/tmp", project_name="test", findings=findings)
        report.build_summary()
        s = report.summary

        assert s.total == 5
        assert s.critical == 1
        assert s.high == 1
        assert s.medium == 1
        assert s.low == 1
        assert s.info == 1

    def test_build_summary_unknown_severity_counted_as_info(self) -> None:
        findings = [_finding(severity="unknown")]
        report = Report(target_path="/tmp", project_name="test", findings=findings)
        report.build_summary()

        assert report.summary.info == 1

    def test_build_summary_by_category(self) -> None:
        findings = [
            _finding(category="pii_email"),
            _finding(category="pii_email", line=20),
            _finding(category="api_key_aws_access", line=30),
        ]
        report = Report(target_path="/tmp", project_name="test", findings=findings)
        report.build_summary()

        assert report.summary.by_category["pii_email"] == 2
        assert report.summary.by_category["api_key_aws_access"] == 1

    def test_build_summary_by_scanner(self) -> None:
        findings = [
            _finding(scanners=["presidio", "gitleaks"]),
            _finding(scanners=["presidio"], line=20),
        ]
        report = Report(target_path="/tmp", project_name="test", findings=findings)
        report.build_summary()

        assert report.summary.by_scanner["presidio"] == 2
        assert report.summary.by_scanner["gitleaks"] == 1

    def test_build_summary_total_matches_findings_count(self) -> None:
        findings = [_finding(line=i) for i in range(1, 8)]
        report = Report(target_path="/tmp", project_name="test", findings=findings)
        report.build_summary()

        assert report.summary.total == 7
