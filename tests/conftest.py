"""Shared pytest fixtures and factory helpers for the test suite."""
from __future__ import annotations

import pytest

from models.finding import Finding, ScanConfig
from models.report import Report


# --------------------------------------------------------------------------- #
# Factory helpers (importable by individual test modules)                      #
# --------------------------------------------------------------------------- #


def make_finding(
    *,
    rule_id: str = "test-rule",
    category: str = "generic_secret",
    severity: str = "high",
    file: str = "app/config.py",
    line: int = 10,
    match: str = "sk_live_abcd1234",
    scanners: list[str] | None = None,
    references: list[str] | None = None,
    regulations: list[str] | None = None,
) -> Finding:
    return Finding(
        id=Finding.make_id(file, line, rule_id),
        rule_id=rule_id,
        category=category,
        severity=severity,
        file=file,
        line=line,
        match=match,
        scanners=scanners or ["presidio"],
        references=references or [],
        regulations=regulations or [],
    )


def make_report(findings: list[Finding] | None = None) -> Report:
    report = Report(
        target_path="/project/test-repo",
        project_name="test-project",
        scanners_run=["presidio"],
        findings=findings or [],
    )
    report.build_summary()
    return report


# --------------------------------------------------------------------------- #
# Module-level pytest fixtures                                                 #
# --------------------------------------------------------------------------- #


@pytest.fixture
def finding() -> Finding:
    return make_finding()


@pytest.fixture
def scan_config() -> ScanConfig:
    return ScanConfig(path="/project/repo", project_name="test-project")


@pytest.fixture
def empty_report() -> Report:
    return make_report()


@pytest.fixture
def report_with_findings() -> Report:
    findings = [
        make_finding(severity="critical", rule_id="aws-access-key", category="api_key_aws_access", line=1),
        make_finding(severity="high", rule_id="generic-api-key", line=2),
        make_finding(severity="medium", rule_id="pii_email", category="pii_email", line=3),
        make_finding(severity="low", rule_id="pii_phone", category="pii_phone", line=4),
        make_finding(severity="info", rule_id="pii_ip_address", category="pii_ip_address", line=5),
    ]
    return make_report(findings)
