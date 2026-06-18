"""Tests for obfuscation.strategies, obfuscation.session, and obfuscation.engine."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from models.finding import Finding
from obfuscation.engine import ApplyResult, ItemResult, _backup_file, apply_session, rollback
from obfuscation.session import ReviewItem, ReviewSession
from obfuscation.strategies import _REPLACEMENTS, get_replacement


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _finding(
    *,
    rule_id: str = "pii_email",
    category: str = "pii_email",
    severity: str = "medium",
    file: str = "app/config.py",
    line: int = 10,
    match: str = "john.doe@example.com",
    scanners: list[str] | None = None,
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
    )


def _approved_item(
    *,
    finding_id: str = "abc123",
    file: str = "app/config.py",
    line: int = 1,
    raw_match: str = "secret-value",
    replacement: str = "[REDACTED]",
) -> ReviewItem:
    return ReviewItem(
        finding_id=finding_id,
        file=file,
        line=line,
        rule_id="pii_email",
        category="pii_email",
        severity="medium",
        scanners=["presidio"],
        match_display="secr****",
        raw_match=raw_match,
        replacement=replacement,
        obfuscatable=True,
        decision="approved",
    )


# =========================================================================== #
# obfuscation.strategies                                                       #
# =========================================================================== #


class TestGetReplacement:
    def test_pii_email(self) -> None:
        assert get_replacement("pii_email") == "[REDACTED_EMAIL]"

    def test_pii_phone(self) -> None:
        assert get_replacement("pii_phone") == "[REDACTED_PHONE]"

    def test_api_key_aws_access(self) -> None:
        assert get_replacement("api_key_aws_access") == "[REDACTED_AWS_ACCESS_KEY]"

    def test_hardcoded_password(self) -> None:
        assert get_replacement("hardcoded_password") == "[REDACTED_PASSWORD]"

    def test_generic_secret(self) -> None:
        assert get_replacement("generic_secret") == "[REDACTED_SECRET]"

    def test_jwt_token(self) -> None:
        assert get_replacement("jwt_token") == "[REDACTED_JWT]"

    def test_unknown_category_returns_fallback(self) -> None:
        assert get_replacement("unknown_xyz_category_99") == "[REDACTED]"

    @pytest.mark.parametrize("category", list(_REPLACEMENTS.keys()))
    def test_all_known_categories_return_bracketed_redacted(self, category: str) -> None:
        result = get_replacement(category)

        assert result.startswith("[REDACTED")
        assert result.endswith("]")


# =========================================================================== #
# obfuscation.session                                                          #
# =========================================================================== #


class TestReviewSessionFromFindings:
    def test_obfuscatable_finding_is_pending(self) -> None:
        f = _finding(match="john.doe@example.com")
        session = ReviewSession.from_findings([f], scan_id="abc123", target_path="/tmp")

        item = session.items[0]
        assert item.decision == "pending"
        assert item.obfuscatable is True
        assert item.raw_match == "john.doe@example.com"

    def test_binary_extension_is_manual(self) -> None:
        f = _finding(file="archive.zip", match="sk_live_abc")
        session = ReviewSession.from_findings([f], scan_id="abc123", target_path="/tmp")

        item = session.items[0]
        assert item.decision == "manual"
        assert item.obfuscatable is False
        assert "Binary/archive" in item.non_obfuscatable_reason

    def test_docx_extension_is_manual(self) -> None:
        f = _finding(file="report.docx", match="john@example.com")
        session = ReviewSession.from_findings([f], scan_id="abc123", target_path="/tmp")

        assert session.items[0].decision == "manual"

    def test_redacted_match_is_manual(self) -> None:
        f = _finding(match="abcd****")
        session = ReviewSession.from_findings([f], scan_id="abc123", target_path="/tmp")

        item = session.items[0]
        assert item.decision == "manual"
        assert item.obfuscatable is False
        assert "Raw match not captured" in item.non_obfuscatable_reason

    def test_empty_match_is_manual(self) -> None:
        f = _finding(match="")
        session = ReviewSession.from_findings([f], scan_id="abc123", target_path="/tmp")

        assert session.items[0].decision == "manual"

    def test_empty_findings_list(self) -> None:
        session = ReviewSession.from_findings([], scan_id="abc123", target_path="/tmp")

        assert session.items == []

    def test_replacement_token_set_from_category(self) -> None:
        f = _finding(category="pii_email", match="john@example.com")
        session = ReviewSession.from_findings([f], scan_id="abc123", target_path="/tmp")

        assert session.items[0].replacement == "[REDACTED_EMAIL]"

    def test_match_display_is_redacted_for_obfuscatable(self) -> None:
        f = _finding(match="john.doe@example.com")
        session = ReviewSession.from_findings([f], scan_id="abc123", target_path="/tmp")

        assert "****" in session.items[0].match_display

    def test_match_display_is_raw_for_non_obfuscatable(self) -> None:
        f = _finding(file="archive.zip", match="abcd****")
        session = ReviewSession.from_findings([f], scan_id="abc123", target_path="/tmp")

        assert session.items[0].match_display == "abcd****"

    def test_multiple_findings_creates_multiple_items(self) -> None:
        findings = [_finding(line=i) for i in range(1, 6)]
        session = ReviewSession.from_findings(findings, scan_id="abc123", target_path="/tmp")

        assert len(session.items) == 5

    def test_scan_id_and_target_path_set(self) -> None:
        session = ReviewSession.from_findings([], scan_id="scan-42", target_path="/repo")

        assert session.scan_id == "scan-42"
        assert session.target_path == "/repo"


class TestReviewSessionFilters:
    @pytest.fixture
    def mixed_session(self) -> ReviewSession:
        findings = [_finding(line=i) for i in range(1, 5)]
        session = ReviewSession.from_findings(findings, scan_id="abc123", target_path="/tmp")
        session.items[0].decision = "approved"
        session.items[1].decision = "skipped"
        session.items[2].decision = "manual"
        # items[3] stays "pending"
        return session

    def test_pending_filter(self, mixed_session: ReviewSession) -> None:
        result = mixed_session.pending()

        assert len(result) == 1
        assert result[0].decision == "pending"

    def test_approved_filter(self, mixed_session: ReviewSession) -> None:
        result = mixed_session.approved()

        assert len(result) == 1
        assert result[0].decision == "approved"

    def test_skipped_filter(self, mixed_session: ReviewSession) -> None:
        result = mixed_session.skipped()

        assert len(result) == 1
        assert result[0].decision == "skipped"

    def test_manual_filter(self, mixed_session: ReviewSession) -> None:
        result = mixed_session.manual()

        assert len(result) == 1
        assert result[0].decision == "manual"

    def test_counts_all_decisions(self, mixed_session: ReviewSession) -> None:
        counts = mixed_session.counts()

        assert counts["total"] == 4
        assert counts["approved"] == 1
        assert counts["skipped"] == 1
        assert counts["manual"] == 1
        assert counts["pending"] == 1


class TestReviewSessionPersistence:
    def test_save_creates_file(self, tmp_path: Path) -> None:
        session = ReviewSession.from_findings(
            [_finding(match="john@example.com")],
            scan_id="save-test-01",
            target_path="/tmp",
        )
        session_path = tmp_path / "session.json"
        result = session.save(session_path)

        assert result == session_path
        assert session_path.exists()

    def test_load_roundtrip(self, tmp_path: Path) -> None:
        findings = [_finding(match="john@example.com")]
        session = ReviewSession.from_findings(findings, scan_id="rt-test-01", target_path="/tmp")
        session_path = tmp_path / "session.json"
        session.save(session_path)

        loaded = ReviewSession.load(session_path)

        assert loaded.scan_id == "rt-test-01"
        assert len(loaded.items) == 1
        assert loaded.items[0].category == "pii_email"

    def test_save_creates_parent_directories(self, tmp_path: Path) -> None:
        session = ReviewSession.from_findings([], scan_id="dir-test", target_path="/tmp")
        deep_path = tmp_path / "a" / "b" / "c" / "session.json"
        session.save(deep_path)

        assert deep_path.exists()

    def test_save_fallback_on_permission_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        session = ReviewSession.from_findings(
            [_finding(match="john@example.com")],
            scan_id="fallback-01",
            target_path="/tmp",
        )
        fallback_home = tmp_path / "home"
        fallback_home.mkdir()

        _original_write_text = Path.write_text
        _call_count = [0]

        def _mock_write_text(path_self: Path, data: str, **kwargs: object) -> None:
            _call_count[0] += 1
            if _call_count[0] == 1:
                raise PermissionError("write denied")
            _original_write_text(path_self, data, **kwargs)

        monkeypatch.setattr(Path, "write_text", _mock_write_text)
        monkeypatch.setattr("obfuscation.session.Path.home", lambda: fallback_home)

        result = session.save(tmp_path / "primary" / "session.json")

        assert str(fallback_home) in str(result)


# =========================================================================== #
# obfuscation.engine                                                           #
# =========================================================================== #


class TestBackupFile:
    def test_backup_creates_copy(self, tmp_path: Path) -> None:
        src_file = tmp_path / "source" / "file.txt"
        src_file.parent.mkdir()
        src_file.write_text("original content", encoding="utf-8")

        backup_dir = tmp_path / "backup"
        target_root = tmp_path / "source"

        dest = _backup_file(src_file, backup_dir, target_root)

        assert dest.exists()
        assert dest.read_text(encoding="utf-8") == "original content"

    def test_backup_preserves_relative_path(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        (root / "sub").mkdir(parents=True)
        src = root / "sub" / "file.py"
        src.write_text("x = 1", encoding="utf-8")

        backup_dir = tmp_path / "backup"
        dest = _backup_file(src, backup_dir, root)

        assert dest == backup_dir / "sub" / "file.py"

    def test_backup_outside_root_uses_filename_only(self, tmp_path: Path) -> None:
        src = tmp_path / "outside.py"
        src.write_text("y = 2", encoding="utf-8")
        different_root = tmp_path / "some_other_dir"
        different_root.mkdir()

        backup_dir = tmp_path / "backup"
        dest = _backup_file(src, backup_dir, different_root)

        assert dest.name == "outside.py"


class TestApplySession:
    def test_no_approved_items_returns_empty_result(self, tmp_path: Path) -> None:
        session = ReviewSession.from_findings(
            [_finding(match="john@example.com")],
            scan_id="s1",
            target_path=str(tmp_path),
        )
        # All items remain "pending"
        result = apply_session(session, tmp_path, tmp_path / "backup")

        assert result.applied_count == 0
        assert result.failed_count == 0

    def test_file_not_found_records_failure(self, tmp_path: Path) -> None:
        session = ReviewSession(scan_id="s2", target_path=str(tmp_path))
        session.items.append(_approved_item(file="missing/file.py", line=1))

        result = apply_session(session, tmp_path, tmp_path / "backup")

        assert result.failed_count == 1
        assert "not found" in result.item_results[0].reason

    def test_applies_replacement_to_file(self, tmp_path: Path) -> None:
        target_file = tmp_path / "src" / "config.py"
        target_file.parent.mkdir()
        target_file.write_text('password = "secret-value"\n', encoding="utf-8")

        session = ReviewSession(scan_id="s3", target_path=str(tmp_path))
        session.items.append(_approved_item(
            file="src/config.py",
            line=1,
            raw_match="secret-value",
            replacement="[REDACTED_PASSWORD]",
        ))

        result = apply_session(session, tmp_path, tmp_path / "backup")

        assert result.applied_count == 1
        assert result.failed_count == 0
        content = target_file.read_text(encoding="utf-8")
        assert "[REDACTED_PASSWORD]" in content
        assert "secret-value" not in content

    def test_dry_run_does_not_modify_file(self, tmp_path: Path) -> None:
        original = 'password = "secret-value"\n'
        target_file = tmp_path / "config.py"
        target_file.write_text(original, encoding="utf-8")

        session = ReviewSession(scan_id="s4", target_path=str(tmp_path))
        session.items.append(_approved_item(file="config.py", line=1, raw_match="secret-value"))

        apply_session(session, tmp_path, tmp_path / "backup", dry_run=True)

        assert target_file.read_text(encoding="utf-8") == original

    def test_raw_match_not_on_line_records_failure(self, tmp_path: Path) -> None:
        target_file = tmp_path / "config.py"
        target_file.write_text('password = "different-value"\n', encoding="utf-8")

        session = ReviewSession(scan_id="s5", target_path=str(tmp_path))
        session.items.append(_approved_item(file="config.py", line=1, raw_match="not-present"))

        result = apply_session(session, tmp_path, tmp_path / "backup")

        assert result.failed_count == 1
        assert "not found" in result.item_results[0].reason

    def test_line_out_of_range_records_failure(self, tmp_path: Path) -> None:
        target_file = tmp_path / "config.py"
        target_file.write_text("line one\n", encoding="utf-8")

        session = ReviewSession(scan_id="s6", target_path=str(tmp_path))
        session.items.append(_approved_item(file="config.py", line=99, raw_match="secret-value"))

        result = apply_session(session, tmp_path, tmp_path / "backup")

        assert result.failed_count == 1
        assert "out of range" in result.item_results[0].reason

    def test_empty_raw_match_records_failure(self, tmp_path: Path) -> None:
        target_file = tmp_path / "config.py"
        target_file.write_text("line one\n", encoding="utf-8")

        session = ReviewSession(scan_id="s7", target_path=str(tmp_path))
        session.items.append(_approved_item(file="config.py", line=1, raw_match=""))

        result = apply_session(session, tmp_path, tmp_path / "backup")

        assert result.failed_count == 1

    def test_backup_created_for_modified_file(self, tmp_path: Path) -> None:
        target_file = tmp_path / "config.py"
        target_file.write_text('key = "secret-value"\n', encoding="utf-8")

        backup_dir = tmp_path / "backup"
        session = ReviewSession(scan_id="s8", target_path=str(tmp_path))
        session.items.append(_approved_item(file="config.py", line=1, raw_match="secret-value"))

        result = apply_session(session, tmp_path, backup_dir)

        assert len(result.backed_up) == 1

    def test_applied_at_set_after_apply(self, tmp_path: Path) -> None:
        target_file = tmp_path / "config.py"
        target_file.write_text('key = "secret-value"\n', encoding="utf-8")

        session = ReviewSession(scan_id="s9", target_path=str(tmp_path))
        session.items.append(_approved_item(file="config.py", line=1, raw_match="secret-value"))

        assert session.applied_at is None
        apply_session(session, tmp_path, tmp_path / "backup")
        assert session.applied_at is not None

    def test_applied_count_and_failed_count_properties(self) -> None:
        result = ApplyResult()
        result.item_results.append(ItemResult(
            finding_id="a", file="f.py", line=1, replacement="[R]", applied=True,
        ))
        result.item_results.append(ItemResult(
            finding_id="b", file="f.py", line=2, replacement="[R]", applied=False, reason="err",
        ))

        assert result.applied_count == 1
        assert result.failed_count == 1


class TestRollback:
    def test_rollback_restores_files(self, tmp_path: Path) -> None:
        backup_dir = tmp_path / "backup"
        (backup_dir / "src").mkdir(parents=True)
        backup_file = backup_dir / "src" / "config.py"
        backup_file.write_text("original = True\n", encoding="utf-8")

        target_root = tmp_path / "target"
        target_root.mkdir()

        count = rollback(backup_dir, target_root)

        assert count == 1
        restored = target_root / "src" / "config.py"
        assert restored.read_text(encoding="utf-8") == "original = True\n"

    def test_rollback_returns_zero_for_empty_backup(self, tmp_path: Path) -> None:
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        target_root = tmp_path / "target"
        target_root.mkdir()

        count = rollback(backup_dir, target_root)

        assert count == 0

    def test_rollback_restores_multiple_files(self, tmp_path: Path) -> None:
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        for i in range(3):
            f = backup_dir / f"file{i}.py"
            f.write_text(f"# file {i}\n", encoding="utf-8")

        target_root = tmp_path / "target"
        target_root.mkdir()

        count = rollback(backup_dir, target_root)

        assert count == 3
