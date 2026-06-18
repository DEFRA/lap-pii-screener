"""Tests for reporting — json, console, html, and markdown renderers."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from models.finding import Finding
from models.report import Report, ScanSummary
from reporting.console import render_console
from reporting.constants import SEVERITY_COLOURS, TEMPLATE_DIR
from reporting.html_reporter import render_html
from reporting.json_reporter import render_json
from reporting.markdown_reporter import render_markdown


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _finding(
    *,
    severity: str = "high",
    category: str = "pii_email",
    line: int = 10,
    regulations: list[str] | None = None,
) -> Finding:
    return Finding(
        id=Finding.make_id("app/config.py", line, "pii_email"),
        rule_id="pii_email",
        category=category,
        severity=severity,
        file="app/config.py",
        line=line,
        match="john****",
        scanners=["presidio"],
        regulations=regulations or [],
    )


def _report(findings: list[Finding] | None = None) -> Report:
    report = Report(
        target_path="/project/repo",
        project_name="test-project",
        scanners_run=["presidio"],
        findings=findings or [],
    )
    report.build_summary()
    return report


# --------------------------------------------------------------------------- #
# reporting.constants                                                          #
# --------------------------------------------------------------------------- #


class TestConstants:
    def test_severity_colours_contains_all_levels(self) -> None:
        for level in ("critical", "high", "medium", "low", "info"):
            assert level in SEVERITY_COLOURS

    def test_template_dir_exists(self) -> None:
        assert TEMPLATE_DIR.is_dir()

    def test_template_dir_contains_html_template(self) -> None:
        assert (TEMPLATE_DIR / "report.html.j2").exists()

    def test_template_dir_contains_markdown_template(self) -> None:
        assert (TEMPLATE_DIR / "report.md.j2").exists()


# --------------------------------------------------------------------------- #
# render_json                                                                  #
# --------------------------------------------------------------------------- #


class TestRenderJson:
    def test_returns_valid_json(self) -> None:
        report = _report()
        output = render_json(report)

        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_contains_project_name(self) -> None:
        report = _report()
        output = render_json(report)

        assert "test-project" in output

    def test_contains_findings(self) -> None:
        report = _report([_finding()])
        output = render_json(report)

        parsed = json.loads(output)
        assert len(parsed["findings"]) == 1

    def test_empty_findings_serialised(self) -> None:
        report = _report()
        output = render_json(report)

        parsed = json.loads(output)
        assert parsed["findings"] == []

    def test_indented_output(self) -> None:
        report = _report()
        output = render_json(report)

        # Indented JSON has newlines
        assert "\n" in output


# --------------------------------------------------------------------------- #
# render_console                                                               #
# --------------------------------------------------------------------------- #


class TestRenderConsole:
    def test_no_findings_prints_clean_message(self) -> None:
        report = _report()
        output = render_console(report)

        assert "No findings" in output

    def test_contains_project_name(self) -> None:
        report = _report()
        output = render_console(report)

        assert "test-project" in output

    def test_contains_scan_report_header(self) -> None:
        report = _report()
        output = render_console(report)

        assert "Scan Report" in output

    def test_with_findings_shows_table(self) -> None:
        report = _report([_finding()])
        output = render_console(report)

        assert "pii_email" in output

    def test_all_severity_labels_appear(self) -> None:
        findings = [
            _finding(severity="critical"),
            _finding(severity="high", line=20),
            _finding(severity="medium", line=30),
            _finding(severity="low", line=40),
            _finding(severity="info", line=50),
        ]
        report = _report(findings)
        output = render_console(report)

        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert label in output

    def test_files_scanned_displayed_when_set(self) -> None:
        report = _report()
        report.summary.files_scanned = 42
        output = render_console(report)

        assert "42" in output

    def test_files_skipped_displayed_when_set(self) -> None:
        report = _report()
        report.summary.files_skipped = 3
        output = render_console(report)

        assert "3" in output

    def test_lines_scanned_displayed_when_set(self) -> None:
        report = _report()
        report.summary.lines_scanned = 1500
        output = render_console(report)

        assert "1,500" in output

    def test_lines_skipped_displayed_when_set(self) -> None:
        report = _report()
        report.summary.lines_skipped = 200
        output = render_console(report)

        assert "200" in output

    def test_regulations_shown_in_findings(self) -> None:
        report = _report([_finding(regulations=["UK-GDPR-PD"])])
        output = render_console(report)

        assert "UK-GDPR-PD" in output

    def test_returns_string(self) -> None:
        assert isinstance(render_console(_report()), str)


# --------------------------------------------------------------------------- #
# render_html                                                                  #
# --------------------------------------------------------------------------- #


class TestRenderHtml:
    def test_returns_html_string(self) -> None:
        report = _report()
        output = render_html(report)

        assert "<html" in output.lower() or "<!doctype" in output.lower() or "<body" in output.lower()

    def test_contains_project_name(self) -> None:
        report = _report()
        output = render_html(report)

        assert "test-project" in output

    def test_with_findings(self) -> None:
        report = _report([_finding()])
        output = render_html(report)

        assert "pii_email" in output

    def test_dry_run_flag_included(self) -> None:
        report = _report()
        output = render_html(report, dry_run=True)

        # The template adds a dry-run banner when dry_run=True
        assert output  # At minimum it renders without error

    def test_show_secrets_flag(self) -> None:
        report = _report([_finding()])
        output = render_html(report, show_secrets=True)

        assert output

    def test_show_confidence_flag(self) -> None:
        report = _report([_finding()])
        output = render_html(report, show_confidence=True)

        assert output


# --------------------------------------------------------------------------- #
# render_markdown                                                              #
# --------------------------------------------------------------------------- #


class TestRenderMarkdown:
    def test_returns_non_empty_string(self) -> None:
        report = _report()
        output = render_markdown(report)

        assert output
        assert isinstance(output, str)

    def test_contains_project_name(self) -> None:
        report = _report()
        output = render_markdown(report)

        assert "test-project" in output

    def test_with_findings(self) -> None:
        report = _report([_finding()])
        output = render_markdown(report)

        assert output
