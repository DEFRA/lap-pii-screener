"""Tests for obfuscation.reviewer — decision handlers, context rendering, review loop."""
from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from obfuscation import reviewer
from obfuscation.reviewer import (
    _apply_category_action,
    _auto_approve_by_severity,
    _build_info_grid,
    _clean_skip_reason,
    _decide_approve,
    _decide_approve_all,
    _decide_edit,
    _decide_skip,
    _decide_skip_all,
    _read_context,
    _render_source_context,
    run_review,
)
from obfuscation.session import ReviewItem, ReviewSession


def _item(
    *,
    finding_id: str = "f1",
    file: str = "app.py",
    line: int = 1,
    category: str = "pii_email",
    severity: str = "medium",
    raw_match: str = "secret-value",
    replacement: str = "[REDACTED]",
    obfuscatable: bool = True,
    decision: str = "pending",
    confidence: float = 0.70,
) -> ReviewItem:
    return ReviewItem(
        finding_id=finding_id,
        file=file,
        line=line,
        rule_id=category,
        category=category,
        severity=severity,
        scanners=["presidio"],
        match_display="secr****",
        raw_match=raw_match,
        replacement=replacement,
        obfuscatable=obfuscatable,
        decision=decision,  # type: ignore[arg-type]
        confidence=confidence,
    )


def _session(items: list[ReviewItem]) -> ReviewSession:
    return ReviewSession(scan_id="scan1", target_path="/project", items=items)


def _quiet_console() -> Console:
    return Console(file=io.StringIO(), force_terminal=False)


# --------------------------------------------------------------------------- #
# pure helpers                                                                 #
# --------------------------------------------------------------------------- #


class TestCleanSkipReason:
    def test_keypress_becomes_empty(self) -> None:
        assert _clean_skip_reason("a") == ""
        assert _clean_skip_reason("S") == ""

    def test_real_reason_preserved(self) -> None:
        assert _clean_skip_reason("false positive") == "false positive"


class TestReadContext:
    def test_returns_window(self, tmp_path: Path) -> None:
        f = tmp_path / "src.py"
        f.write_text("l1\nl2\nl3\nl4\nl5\n", encoding="utf-8")
        ctx = _read_context(f, 3)
        linenos = [c[0] for c in ctx]
        assert linenos == [1, 2, 3, 4, 5]
        assert any(is_target for _, _, is_target in ctx)

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert _read_context(tmp_path / "ghost.py", 1) == []


class TestApplyCategoryAction:
    def test_approves_matching_category(self) -> None:
        session = _session([
            _item(finding_id="a", category="pii_email"),
            _item(finding_id="b", category="pii_email"),
            _item(finding_id="c", category="pii_ssn"),
        ])
        count = _apply_category_action(session, "pii_email", "approved")
        assert count == 2
        assert [i.decision for i in session.items] == ["approved", "approved", "pending"]

    def test_skip_records_reason(self) -> None:
        session = _session([_item(category="pii_email")])
        _apply_category_action(session, "pii_email", "skipped", "noise")
        assert session.items[0].skip_reason == "noise"

    def test_ignores_non_obfuscatable(self) -> None:
        session = _session([_item(category="pii_email", obfuscatable=False)])
        assert _apply_category_action(session, "pii_email", "approved") == 0


class TestBuildInfoGrid:
    def test_returns_table(self) -> None:
        grid = _build_info_grid(_item(confidence=0.9), show_secrets=True)
        assert grid is not None

    def test_low_confidence_branch(self) -> None:
        grid = _build_info_grid(_item(confidence=0.4), show_secrets=False)
        assert grid is not None

    def test_non_obfuscatable_note(self) -> None:
        item = _item(obfuscatable=False)
        item.non_obfuscatable_reason = "binary file"
        grid = _build_info_grid(item, show_secrets=False)
        assert grid is not None


class TestRenderSourceContext:
    def test_renders_without_error(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\nsecret-value here\ny = 2\n", encoding="utf-8")
        item = _item(file="app.py", line=2, raw_match="secret-value")
        _render_source_context(item, tmp_path, _quiet_console())

    def test_missing_file_noop(self, tmp_path: Path) -> None:
        item = _item(file="ghost.py", line=1)
        _render_source_context(item, tmp_path, _quiet_console())


# --------------------------------------------------------------------------- #
# decision handlers                                                            #
# --------------------------------------------------------------------------- #


class TestDecisionHandlers:
    def test_approve(self) -> None:
        item = _item()
        _decide_approve(item)
        assert item.decision == "approved"

    def test_edit_sets_replacement(self) -> None:
        item = _item()
        with patch.object(reviewer.Prompt, "ask", return_value="CUSTOM"):
            _decide_edit(item, _quiet_console())
        assert item.replacement == "CUSTOM"
        assert item.decision == "approved"

    def test_edit_blank_keeps_replacement(self) -> None:
        item = _item(replacement="[ORIG]")
        with patch.object(reviewer.Prompt, "ask", return_value="   "):
            _decide_edit(item, _quiet_console())
        assert item.replacement == "[ORIG]"

    def test_skip_records_reason(self) -> None:
        item = _item()
        with patch.object(reviewer.Prompt, "ask", return_value="false positive"):
            _decide_skip(item, _quiet_console())
        assert item.decision == "skipped"
        assert item.skip_reason == "false positive"

    def test_approve_all(self) -> None:
        session = _session([_item(finding_id="a"), _item(finding_id="b")])
        _decide_approve_all(session.items[0], session, _quiet_console())
        assert all(i.decision == "approved" for i in session.items)

    def test_skip_all(self) -> None:
        session = _session([_item(finding_id="a"), _item(finding_id="b")])
        with patch.object(reviewer.Prompt, "ask", return_value="bulk skip"):
            _decide_skip_all(session.items[0], session, _quiet_console())
        assert all(i.decision == "skipped" for i in session.items)


# --------------------------------------------------------------------------- #
# _auto_approve_by_severity                                                    #
# --------------------------------------------------------------------------- #


class TestAutoApprove:
    def test_approves_at_or_above_threshold(self, tmp_path: Path) -> None:
        session = _session([
            _item(finding_id="a", severity="critical"),
            _item(finding_id="b", severity="low"),
        ])
        _auto_approve_by_severity(session, "high", tmp_path / "s.json", _quiet_console())
        assert session.items[0].decision == "approved"
        assert session.items[1].decision == "pending"

    def test_saves_session(self, tmp_path: Path) -> None:
        session = _session([_item(severity="critical")])
        sp = tmp_path / "s.json"
        _auto_approve_by_severity(session, "high", sp, _quiet_console())
        assert sp.exists()


# --------------------------------------------------------------------------- #
# run_review loop                                                              #
# --------------------------------------------------------------------------- #


class TestRunReview:
    def test_no_pending_returns_early(self, tmp_path: Path) -> None:
        session = _session([_item(decision="approved")])
        out = run_review(session, tmp_path, console=_quiet_console())
        assert out is session

    def test_approve_flow(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("secret-value\n", encoding="utf-8")
        session = _session([_item(file="app.py", line=1)])
        with patch.object(reviewer.Prompt, "ask", return_value="a"):
            out = run_review(session, tmp_path, console=_quiet_console())
        assert out.items[0].decision == "approved"

    def test_quit_saves_and_returns(self, tmp_path: Path) -> None:
        session = _session([_item(), _item(finding_id="b")])
        sp = tmp_path / "s.json"
        with patch.object(reviewer.Prompt, "ask", return_value="q"):
            out = run_review(session, tmp_path, session_path=sp, console=_quiet_console())
        assert out is session
        assert sp.exists()

    def test_invalid_then_valid_choice(self, tmp_path: Path) -> None:
        session = _session([_item()])
        with patch.object(reviewer.Prompt, "ask", side_effect=["?", "a"]):
            run_review(session, tmp_path, console=_quiet_console())
        assert session.items[0].decision == "approved"

    def test_non_obfuscatable_skipped_in_loop(self, tmp_path: Path) -> None:
        session = _session([_item(obfuscatable=False)])
        # No prompt should be needed; loop should skip it.
        out = run_review(session, tmp_path, console=_quiet_console())
        assert out.items[0].decision == "pending"

    def test_auto_approve_severity_invoked(self, tmp_path: Path) -> None:
        session = _session([_item(severity="critical")])
        out = run_review(
            session, tmp_path, auto_approve_severity="high", console=_quiet_console()
        )
        assert out.items[0].decision == "approved"
