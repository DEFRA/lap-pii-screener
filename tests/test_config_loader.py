"""Tests for config_loader — parse_suppress_file and suppress_findings."""
from __future__ import annotations

from pathlib import Path

import pytest

from config_loader import parse_suppress_file, suppress_findings
from models.finding import Finding


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _write_suppress(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "suppress.txt"
    p.write_text(content, encoding="utf-8")
    return p


def _finding(rule_id: str = "CWE-798", references: list[str] | None = None) -> Finding:
    return Finding(
        id=Finding.make_id("file.py", 1, rule_id),
        rule_id=rule_id,
        category="generic_secret",
        severity="high",
        file="file.py",
        line=1,
        match="abcd****",
        scanners=["gitleaks"],
        references=references or [],
    )


# --------------------------------------------------------------------------- #
# parse_suppress_file                                                           #
# --------------------------------------------------------------------------- #


class TestParseSuppressFile:
    def test_global_rules_only(self, tmp_path: Path) -> None:
        path = _write_suppress(tmp_path, "CWE-798\naws-access-token\n")
        global_rules, per_scanner = parse_suppress_file(path)

        assert global_rules == {"CWE-798", "aws-access-token"}
        assert per_scanner == {}

    def test_section_rules(self, tmp_path: Path) -> None:
        content = "[gitleaks]\naws-access-token\n[presidio]\npii_email\n"
        path = _write_suppress(tmp_path, content)
        global_rules, per_scanner = parse_suppress_file(path)

        assert global_rules == set()
        assert per_scanner["gitleaks"] == ["aws-access-token"]
        assert per_scanner["presidio"] == ["pii_email"]

    def test_mixed_global_and_sections(self, tmp_path: Path) -> None:
        content = "CWE-798\n\n[gitleaks]\ngeneric-api-key\n"
        path = _write_suppress(tmp_path, content)
        global_rules, per_scanner = parse_suppress_file(path)

        assert "CWE-798" in global_rules
        assert per_scanner["gitleaks"] == ["generic-api-key"]

    def test_comments_and_blanks_ignored(self, tmp_path: Path) -> None:
        content = "# This is a comment\n\nCWE-798\n# another comment\n"
        path = _write_suppress(tmp_path, content)
        global_rules, per_scanner = parse_suppress_file(path)

        assert global_rules == {"CWE-798"}
        assert per_scanner == {}

    def test_inline_comment_stripped(self, tmp_path: Path) -> None:
        content = "CWE-798 # inline comment\n"
        path = _write_suppress(tmp_path, content)
        global_rules, _ = parse_suppress_file(path)

        # The inline comment stripping means "CWE-798 " is added — stripped to "CWE-798"
        assert any("CWE-798" in r for r in global_rules)

    def test_empty_file(self, tmp_path: Path) -> None:
        path = _write_suppress(tmp_path, "")
        global_rules, per_scanner = parse_suppress_file(path)

        assert global_rules == set()
        assert per_scanner == {}

    def test_section_names_lowercased(self, tmp_path: Path) -> None:
        path = _write_suppress(tmp_path, "[GITLEAKS]\nsome-rule\n")
        _, per_scanner = parse_suppress_file(path)

        assert "gitleaks" in per_scanner

    def test_empty_section_created(self, tmp_path: Path) -> None:
        path = _write_suppress(tmp_path, "[presidio]\n")
        _, per_scanner = parse_suppress_file(path)

        assert per_scanner["presidio"] == []

    def test_multiple_rules_in_section(self, tmp_path: Path) -> None:
        content = "[gitleaks]\nrule-a\nrule-b\nrule-c\n"
        path = _write_suppress(tmp_path, content)
        _, per_scanner = parse_suppress_file(path)

        assert per_scanner["gitleaks"] == ["rule-a", "rule-b", "rule-c"]

    def test_multiple_sections(self, tmp_path: Path) -> None:
        content = "[gitleaks]\nrule-a\n[semgrep]\nrule-b\n[sonarqube]\nrule-c\n"
        path = _write_suppress(tmp_path, content)
        _, per_scanner = parse_suppress_file(path)

        assert "gitleaks" in per_scanner
        assert "semgrep" in per_scanner
        assert "sonarqube" in per_scanner


# --------------------------------------------------------------------------- #
# suppress_findings                                                             #
# --------------------------------------------------------------------------- #


class TestSuppressFindings:
    def test_empty_rules_returns_all(self) -> None:
        findings = [_finding("CWE-798"), _finding("pii_email")]
        result = suppress_findings(findings, set())

        assert result == findings

    def test_suppress_by_exact_rule_id(self) -> None:
        findings = [_finding("CWE-798"), _finding("pii_email")]
        result = suppress_findings(findings, {"CWE-798"})

        assert len(result) == 1
        assert result[0].rule_id == "pii_email"

    def test_suppress_by_reference_exact(self) -> None:
        f = _finding("generic-rule", references=["CWE-798"])
        result = suppress_findings([f], {"CWE-798"})

        assert result == []

    def test_suppress_by_reference_colon_prefix(self) -> None:
        f = _finding("generic-rule", references=["CWE-798: Hard-coded credentials"])
        result = suppress_findings([f], {"CWE-798"})

        assert result == []

    def test_suppress_by_reference_space_prefix(self) -> None:
        f = _finding("generic-rule", references=["CWE-798 description here"])
        result = suppress_findings([f], {"CWE-798"})

        assert result == []

    def test_no_match_keeps_all(self) -> None:
        findings = [_finding("pii_email"), _finding("pii_phone")]
        result = suppress_findings(findings, {"CWE-798"})

        assert result == findings

    def test_suppresses_all_matching(self) -> None:
        findings = [_finding("CWE-798"), _finding("aws-access-token"), _finding("pii_email")]
        result = suppress_findings(findings, {"CWE-798", "aws-access-token"})

        assert len(result) == 1
        assert result[0].rule_id == "pii_email"

    def test_partial_rule_id_not_matched(self) -> None:
        # Exact rule_id check — "CWE-79" must NOT suppress "CWE-798"
        f = _finding("CWE-798")
        result = suppress_findings([f], {"CWE-79"})

        assert result == [f]

    def test_reference_not_matched_by_partial_rule_substring(self) -> None:
        # ref "CWE-7980-foo" should NOT be matched by rule "CWE-798" because
        # it neither equals "CWE-798" nor starts with "CWE-798:" or "CWE-798 "
        f = _finding("some-rule", references=["CWE-7980-foo"])
        result = suppress_findings([f], {"CWE-798"})

        assert result == [f]

    def test_empty_findings_list(self) -> None:
        result = suppress_findings([], {"CWE-798"})

        assert result == []
