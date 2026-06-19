"""Tests for src/cli.py (Typer CLI commands and helpers)."""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

import cli
from conftest import make_finding, make_report
from obfuscation.session import ReviewItem, ReviewSession

runner = CliRunner()


# --------------------------------------------------------------------------- #
# Helpers / fixtures                                                          #
# --------------------------------------------------------------------------- #


def _session(items: list[ReviewItem] | None = None) -> ReviewSession:
    return ReviewSession(scan_id="scan1", target_path="/p", items=items or [])


def _item(**kw) -> ReviewItem:
    base = dict(
        finding_id="abc123",
        file="src/app.py",
        line=10,
        rule_id="r1",
        category="pii_ssn",
        severity="high",
        scanners=["pii"],
        match_display="1234****",
        replacement="[REDACTED]",
    )
    base.update(kw)
    return ReviewItem(**base)


def _inject_module(monkeypatch: pytest.MonkeyPatch, name: str, **attrs) -> None:
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    monkeypatch.setitem(sys.modules, name, mod)


# --------------------------------------------------------------------------- #
# _render_and_write                                                           #
# --------------------------------------------------------------------------- #


class TestRenderAndWrite:
    def test_writes_file(self, tmp_path: Path) -> None:
        report = make_report(findings=[])
        out = tmp_path / "r.md"
        with patch.dict(cli._FORMAT_RENDERERS, {"markdown": lambda r: "MD"}):
            cli._render_and_write(report, "markdown", out)
        assert out.read_text(encoding="utf-8") == "MD"

    def test_console_to_stdout(self, capsys: pytest.CaptureFixture) -> None:
        report = make_report(findings=[])
        with patch.dict(cli._FORMAT_RENDERERS, {"console": lambda r: "CON"}):
            cli._render_and_write(report, "console", None)
        assert "CON" in capsys.readouterr().out

    def test_json_print(self, capsys: pytest.CaptureFixture) -> None:
        report = make_report(findings=[])
        with patch.dict(cli._FORMAT_RENDERERS, {"json": lambda r: "{}"}):
            cli._render_and_write(report, "json", None)
        assert "{}" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# _render_and_write_per_file                                                  #
# --------------------------------------------------------------------------- #


class TestRenderPerFile:
    def test_no_findings_returns_zero(self, tmp_path: Path) -> None:
        report = make_report(findings=[])
        assert cli._render_and_write_per_file(report, "json", tmp_path) == 0

    def test_writes_one_per_file(self, tmp_path: Path) -> None:
        f1 = make_finding(file="src/a.py")
        f2 = make_finding(file="src/b.py")
        report = make_report(findings=[f1, f2])
        with patch.dict(cli._FORMAT_RENDERERS, {"json": lambda r: "{}"}):
            n = cli._render_and_write_per_file(report, "json", tmp_path)
        assert n == 2
        assert (tmp_path / "src" / "a.py.json").exists()
        assert (tmp_path / "src" / "b.py.json").exists()


# --------------------------------------------------------------------------- #
# _validate_path                                                              #
# --------------------------------------------------------------------------- #


class TestValidatePath:
    def test_valid(self, tmp_path: Path) -> None:
        assert cli._validate_path(tmp_path) == tmp_path.resolve()

    def test_missing_exits(self, tmp_path: Path) -> None:
        with pytest.raises(typer.Exit):
            cli._validate_path(tmp_path / "nope")

    def test_file_exits(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt"
        f.write_text("x", encoding="utf-8")
        with pytest.raises(typer.Exit):
            cli._validate_path(f)


# --------------------------------------------------------------------------- #
# _load_yaml_config                                                           #
# --------------------------------------------------------------------------- #


class TestLoadYamlConfig:
    def test_no_file_returns_empty(self, tmp_path: Path) -> None:
        assert cli._load_yaml_config(None, tmp_path) == {}

    def test_reads_yaml(self, tmp_path: Path) -> None:
        cfg = tmp_path / "sensitive-scanner.yaml"
        cfg.write_text("format: markdown\n", encoding="utf-8")
        assert cli._load_yaml_config(None, tmp_path) == {"format": "markdown"}

    def test_read_error_returns_empty(self, tmp_path: Path) -> None:
        cfg = tmp_path / "c.yaml"
        cfg.write_text("x: y\n", encoding="utf-8")
        with patch.object(cli.yaml, "safe_load", side_effect=ValueError("bad")):
            assert cli._load_yaml_config(cfg, tmp_path) == {}


# --------------------------------------------------------------------------- #
# _load_suppress_config                                                       #
# --------------------------------------------------------------------------- #


class TestLoadSuppressConfig:
    def test_merges_config_by_scanner(self, tmp_path: Path) -> None:
        cfg = {"suppress_by_scanner": {"gitleaks": ["r1", "r2"]}}
        persistent, by_scanner = cli._load_suppress_config(tmp_path, cfg)
        assert by_scanner["gitleaks"] == ["r1", "r2"]
        assert persistent == set()


# --------------------------------------------------------------------------- #
# _is_pattern / _classify_exclusion                                           #
# --------------------------------------------------------------------------- #


class TestExclusionClassification:
    @pytest.mark.parametrize("s,expected", [("*.js", True), ("a/b", True), ("plain", False)])
    def test_is_pattern(self, s: str, expected: bool) -> None:
        assert cli._is_pattern(s) is expected

    def test_classify_pattern(self) -> None:
        assert cli._classify_exclusion("**/*.min.js") == ("pattern", "**/*.min.js")

    def test_classify_file(self) -> None:
        assert cli._classify_exclusion("config.py") == ("file", "config.py")

    def test_classify_dir(self) -> None:
        assert cli._classify_exclusion("coverage") == ("dir", "coverage")


# --------------------------------------------------------------------------- #
# _excludes_from_config                                                       #
# --------------------------------------------------------------------------- #


class TestExcludesFromConfig:
    def test_full(self) -> None:
        cfg = {"exclude": {"directories": ["d"], "patterns": ["*.x"], "files": ["f.py"]}}
        dirs, patterns, files = cli._excludes_from_config(cfg)
        assert dirs == ["d"]
        assert patterns == ["*.x"]
        assert files == ["f.py"]

    def test_empty(self) -> None:
        assert cli._excludes_from_config({}) == ([], [], [])


# --------------------------------------------------------------------------- #
# _report_artifact_excludes                                                   #
# --------------------------------------------------------------------------- #


class TestReportArtifactExcludes:
    def test_finds_report_files(self, tmp_path: Path) -> None:
        (tmp_path / "report.html").write_text("x", encoding="utf-8")
        (tmp_path / "scan_report.json").write_text("x", encoding="utf-8")
        (tmp_path / "other.py").write_text("x", encoding="utf-8")
        out = cli._report_artifact_excludes(tmp_path)
        assert "report.html" in out
        assert "scan_report.json" in out
        assert "other.py" not in out


# --------------------------------------------------------------------------- #
# _collect_exclusion_lists                                                    #
# --------------------------------------------------------------------------- #


class TestCollectExclusionLists:
    def test_scannerignore_and_exclude_flag(self, tmp_path: Path) -> None:
        (tmp_path / ".scannerignore").write_text("coverage  # comment\n*.min.js\n", encoding="utf-8")
        dirs, patterns, files = cli._collect_exclusion_lists(tmp_path, {}, "docs,test.py", None)
        assert "coverage" in dirs
        assert "*.min.js" in patterns
        assert "docs" in dirs
        assert "test.py" in files

    def test_output_excluded(self, tmp_path: Path) -> None:
        out = tmp_path / "sub" / "out.html"
        dirs, patterns, files = cli._collect_exclusion_lists(tmp_path, {}, None, out)
        assert str(Path("sub/out.html")) in files


# --------------------------------------------------------------------------- #
# _parse_scanner_list / _join_suppress_value / _cfg_default                   #
# --------------------------------------------------------------------------- #


class TestSmallHelpers:
    def test_parse_list(self) -> None:
        assert cli._parse_scanner_list(["Gitleaks", "PII"]) == ["gitleaks", "pii"]

    def test_parse_string(self) -> None:
        assert cli._parse_scanner_list("gitleaks, pii") == ["gitleaks", "pii"]

    def test_join_list(self) -> None:
        assert cli._join_suppress_value(["a", "b"]) == "a,b"

    def test_join_string(self) -> None:
        assert cli._join_suppress_value("a,b") == "a,b"

    def test_cfg_default_uses_cfg_when_unset(self) -> None:
        assert cli._cfg_default(None, True, "fromcfg") == "fromcfg"

    def test_cfg_default_keeps_cli(self) -> None:
        assert cli._cfg_default("cli", False, "cfg") == "cli"


# --------------------------------------------------------------------------- #
# _print_scan_summary / _apply_cli_suppression                               #
# --------------------------------------------------------------------------- #


class TestSummaryAndSuppression:
    def test_print_summary(self, capsys: pytest.CaptureFixture) -> None:
        report = make_report(findings=[make_finding(severity="critical")])
        cli._print_scan_summary(report)
        assert "Scan complete" in capsys.readouterr().out

    def test_apply_suppression_noop(self) -> None:
        report = make_report(findings=[make_finding()])
        before = len(report.findings)
        cli._apply_cli_suppression(report, None, set())
        assert len(report.findings) == before

    def test_apply_suppression_filters(self) -> None:
        f = make_finding(rule_id="drop-me")
        report = make_report(findings=[f])
        with patch.object(cli, "suppress_findings", return_value=[]) as m:
            cli._apply_cli_suppression(report, "drop-me", set())
        m.assert_called_once()
        assert report.findings == []


# --------------------------------------------------------------------------- #
# _emit_html_with_session                                                     #
# --------------------------------------------------------------------------- #


class TestEmitHtmlWithSession:
    def test_missing_session_exits(self, tmp_path: Path) -> None:
        report = make_report(findings=[])
        with pytest.raises(typer.Exit):
            cli._emit_html_with_session(report, None, tmp_path / "nope.json", False)

    def test_success_writes(self, tmp_path: Path) -> None:
        report = make_report(findings=[])
        sess_file = tmp_path / "s.json"
        _session().save(sess_file)
        out = tmp_path / "r.html"
        with patch.object(cli, "render_html", return_value="<html>"):
            cli._emit_html_with_session(report, out, sess_file, True)
        assert out.read_text(encoding="utf-8") == "<html>"

    def test_success_no_output_prints(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        report = make_report(findings=[])
        sess_file = tmp_path / "s.json"
        _session().save(sess_file)
        with patch.object(cli, "render_html", return_value="<html-stdout>"):
            cli._emit_html_with_session(report, None, sess_file, False)
        assert "<html-stdout>" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# _emit_scan_report                                                           #
# --------------------------------------------------------------------------- #


class TestEmitScanReport:
    def test_per_file(self, tmp_path: Path) -> None:
        report = make_report(findings=[make_finding(file="a.py")])
        with patch.object(cli, "_render_and_write_per_file", return_value=1) as m:
            cli._emit_scan_report(report, "json", None, True, tmp_path, None, False)
        m.assert_called_once()

    def test_per_file_no_findings(self, tmp_path: Path) -> None:
        report = make_report(findings=[])
        with patch.object(cli, "_render_and_write_per_file", return_value=0):
            cli._emit_scan_report(report, "json", None, True, tmp_path, None, False)

    def test_html_with_session(self, tmp_path: Path) -> None:
        report = make_report(findings=[])
        with patch.object(cli, "_emit_html_with_session") as m:
            cli._emit_scan_report(report, "html", None, False, None, tmp_path / "s.json", False)
        m.assert_called_once()

    def test_plain(self) -> None:
        report = make_report(findings=[])
        with patch.object(cli, "_render_and_write") as m:
            cli._emit_scan_report(report, "json", None, False, None, None, False)
        m.assert_called_once()


# --------------------------------------------------------------------------- #
# _apply_fail_on                                                              #
# --------------------------------------------------------------------------- #


class TestApplyFailOn:
    def test_no_fail_on(self) -> None:
        cli._apply_fail_on(make_report(findings=[make_finding(severity="critical")]), None)

    def test_below_threshold_ok(self) -> None:
        report = make_report(findings=[make_finding(severity="low")])
        cli._apply_fail_on(report, "critical")  # no raise

    def test_at_threshold_exits(self) -> None:
        report = make_report(findings=[make_finding(severity="high")])
        with pytest.raises(typer.Exit) as exc:
            cli._apply_fail_on(report, "high")
        assert exc.value.exit_code == 2


# --------------------------------------------------------------------------- #
# status helpers                                                             #
# --------------------------------------------------------------------------- #


class TestStatusHelpers:
    def test_binary_lines(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import binary_manager
        monkeypatch.setattr(binary_manager, "is_installed", lambda n: n == "gitleaks")
        lines = cli._status_binary_lines()
        assert any("gitleaks" in ln for ln in lines)

    def test_semgrep_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda t: "/usr/bin/semgrep")
        assert "semgrep" in cli._status_semgrep_line()

    def test_semgrep_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda t: None)
        assert "not found" in cli._status_semgrep_line()

    def test_sonarqube_native_with_scanner(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_sonar_scanner", lambda: "/sc")
        lines = cli._status_sonarqube_lines("/sq", "/java")
        assert any("SonarQube (native)" in ln for ln in lines)

    def test_sonarqube_no_java(self) -> None:
        lines = cli._status_sonarqube_lines("/sq", None)
        assert any("Java not on PATH" in ln for ln in lines)

    def test_sonarqube_not_installed(self) -> None:
        lines = cli._status_sonarqube_lines(None, None)
        assert any("not installed" in ln for ln in lines)

    def test_spacy_not_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "spacy", None)
        assert "not installed" in cli._status_spacy_line()

    def test_spacy_loaded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _inject_module(monkeypatch, "spacy", load=lambda n: object())
        assert "loaded" in cli._status_spacy_line()

    def test_spacy_model_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _load(n):  # noqa: ANN001, ANN202
            raise OSError("missing")

        _inject_module(monkeypatch, "spacy", load=_load)
        assert "model missing" in cli._status_spacy_line()

    def test_presidio_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _inject_module(monkeypatch, "presidio_analyzer", AnalyzerEngine=object)
        assert "installed" in cli._status_presidio_line()

    def test_presidio_not_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "presidio_analyzer", None)
        assert "not installed" in cli._status_presidio_line()

    def test_nlp_lines(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli, "_status_spacy_line", lambda: "spacy")
        monkeypatch.setattr(cli, "_status_presidio_line", lambda: "presidio")
        assert cli._status_nlp_lines() == ["spacy", "presidio"]

    def test_compute_tier_3(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SONAR_TOKEN", "t")
        monkeypatch.setenv("SONAR_HOST_URL", "https://sonarcloud.io")
        assert cli._compute_tier(None, None, None) == 3

    def test_compute_tier_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SONAR_TOKEN", raising=False)
        assert cli._compute_tier("/sq", "/java", None) == 2

    def test_compute_tier_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SONAR_TOKEN", raising=False)
        assert cli._compute_tier(None, None, None) == 1


# --------------------------------------------------------------------------- #
# setup helpers — gitleaks / semgrep                                          #
# --------------------------------------------------------------------------- #


class TestSetupGitleaks:
    def test_already_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import binary_manager
        monkeypatch.setattr(binary_manager, "is_installed", lambda n: True)
        results: list = []
        cli._run_gitleaks_setup(False, results)
        assert results[0][0] == "Gitleaks"

    def test_check_not_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import binary_manager
        monkeypatch.setattr(binary_manager, "is_installed", lambda n: False)
        results: list = []
        cli._run_gitleaks_setup(True, results)
        assert "not downloaded" in results[0][2]

    def test_download_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import binary_manager
        monkeypatch.setattr(binary_manager, "is_installed", lambda n: False)
        monkeypatch.setattr(binary_manager, "ensure_binary", AsyncMock(return_value=Path("/bin/gitleaks")))
        results: list = []
        cli._run_gitleaks_setup(False, results)
        assert "downloaded" in results[0][2]

    def test_download_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import binary_manager
        monkeypatch.setattr(binary_manager, "is_installed", lambda n: False)
        monkeypatch.setattr(binary_manager, "ensure_binary", AsyncMock(return_value=None))
        results: list = []
        cli._run_gitleaks_setup(False, results)
        assert "no binary" in results[0][2]

    def test_download_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import binary_manager
        monkeypatch.setattr(binary_manager, "is_installed", lambda n: False)
        monkeypatch.setattr(binary_manager, "ensure_binary", AsyncMock(side_effect=RuntimeError("boom")))
        results: list = []
        cli._run_gitleaks_setup(False, results)
        assert "failed" in results[0][2]


class TestSetupSemgrep:
    def test_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda t: "/usr/bin/semgrep")
        results: list = []
        cli._run_semgrep_setup(False, results)
        assert results[0][1] == cli._SR_OK

    def test_check_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda t: None)
        results: list = []
        cli._run_semgrep_setup(True, results)
        assert "pip install" in results[0][2]

    def test_pip_install_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda t: None)
        monkeypatch.setattr("subprocess.run", lambda *a, **k: MagicMock(returncode=0))
        results: list = []
        cli._run_semgrep_setup(False, results)
        assert "installed" in results[0][2]

    def test_pip_install_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda t: None)
        monkeypatch.setattr("subprocess.run", lambda *a, **k: MagicMock(returncode=1, stderr="bad\nerror"))
        results: list = []
        cli._run_semgrep_setup(False, results)
        assert results[0][1] == cli._SR_FAIL


# --------------------------------------------------------------------------- #
# setup helpers — spacy                                                        #
# --------------------------------------------------------------------------- #


class TestSetupSpacy:
    def test_report_existing_not_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "spacy", None)
        results: list = []
        cli._spacy_report_existing(results)
        assert "optional" in results[0][2]

    def test_report_existing_ready(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _inject_module(monkeypatch, "spacy", load=lambda n: object())
        results: list = []
        cli._spacy_report_existing(results)
        assert "ready" in results[0][2]

    def test_report_existing_model_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _load(n):  # noqa: ANN001, ANN202
            raise OSError()

        _inject_module(monkeypatch, "spacy", load=_load)
        results: list = []
        cli._spacy_report_existing(results)
        assert "model missing" in results[0][2]

    def test_ensure_installed_already(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _inject_module(monkeypatch, "spacy", load=lambda n: object())
        assert cli._ensure_spacy_installed(False, []) is True

    def test_ensure_installed_check_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "spacy", None)
        results: list = []
        assert cli._ensure_spacy_installed(True, results) is False
        assert "not installed" in results[0][2]

    def test_ensure_installed_pip_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "spacy", None)
        monkeypatch.setattr("subprocess.run", lambda *a, **k: MagicMock(returncode=0))
        assert cli._ensure_spacy_installed(False, []) is True

    def test_ensure_installed_pip_fail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "spacy", None)
        monkeypatch.setattr("subprocess.run", lambda *a, **k: MagicMock(returncode=1))
        results: list = []
        assert cli._ensure_spacy_installed(False, results) is False

    def test_ensure_installed_pip_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "spacy", None)
        monkeypatch.setattr("subprocess.run", MagicMock(side_effect=OSError("x")))
        results: list = []
        assert cli._ensure_spacy_installed(False, results) is False

    def test_ensure_model_ready(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _inject_module(monkeypatch, "spacy", load=lambda n: object())
        results: list = []
        cli._ensure_spacy_model(False, results)
        assert "ready" in results[0][2]

    def test_ensure_model_check_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _load(n):  # noqa: ANN001, ANN202
            raise OSError()

        _inject_module(monkeypatch, "spacy", load=_load)
        results: list = []
        cli._ensure_spacy_model(True, results)
        assert "model missing" in results[0][2]

    def test_ensure_model_download_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _load(n):  # noqa: ANN001, ANN202
            raise OSError()

        _inject_module(monkeypatch, "spacy", load=_load)
        monkeypatch.setattr("subprocess.run", lambda *a, **k: MagicMock(returncode=0))
        results: list = []
        cli._ensure_spacy_model(False, results)
        assert "downloaded" in results[0][2]

    def test_ensure_model_download_fail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _load(n):  # noqa: ANN001, ANN202
            raise OSError()

        _inject_module(monkeypatch, "spacy", load=_load)
        monkeypatch.setattr("subprocess.run", lambda *a, **k: MagicMock(returncode=1))
        results: list = []
        cli._ensure_spacy_model(False, results)
        assert results[0][1] == cli._SR_FAIL

    def test_run_spacy_setup_not_requested(self, monkeypatch: pytest.MonkeyPatch) -> None:
        m = MagicMock()
        monkeypatch.setattr(cli, "_spacy_report_existing", m)
        cli._run_spacy_setup(False, False, [])
        m.assert_called_once()

    def test_run_spacy_setup_requested(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli, "_ensure_spacy_installed", lambda c, r: True)
        m = MagicMock()
        monkeypatch.setattr(cli, "_ensure_spacy_model", m)
        cli._run_spacy_setup(False, True, [])
        m.assert_called_once()

    def test_run_spacy_setup_install_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli, "_ensure_spacy_installed", lambda c, r: False)
        m = MagicMock()
        monkeypatch.setattr(cli, "_ensure_spacy_model", m)
        cli._run_spacy_setup(False, True, [])
        m.assert_not_called()


# --------------------------------------------------------------------------- #
# setup helpers — sonarqube                                                    #
# --------------------------------------------------------------------------- #


class TestSetupSonarqube:
    def test_scanner_cli_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "sonar_scanner_installed", lambda: True)
        results: list = []
        cli._setup_sonar_scanner_cli(False, results)
        assert results[0][1] == cli._SR_OK

    def test_scanner_cli_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "sonar_scanner_installed", lambda: False)
        results: list = []
        cli._setup_sonar_scanner_cli(True, results)
        assert "not installed" in results[0][2]

    def test_scanner_cli_download_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "sonar_scanner_installed", lambda: False)
        monkeypatch.setattr(sonarqube_manager, "ensure_sonar_scanner", AsyncMock(return_value=Path("/sc")))
        results: list = []
        cli._setup_sonar_scanner_cli(False, results)
        assert "installed" in results[0][2]

    def test_scanner_cli_download_fail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "sonar_scanner_installed", lambda: False)
        monkeypatch.setattr(sonarqube_manager, "ensure_sonar_scanner", AsyncMock(return_value=None))
        results: list = []
        cli._setup_sonar_scanner_cli(False, results)
        assert results[0][1] == cli._SR_FAIL

    def test_scanner_cli_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "sonar_scanner_installed", lambda: False)
        monkeypatch.setattr(sonarqube_manager, "ensure_sonar_scanner", AsyncMock(side_effect=RuntimeError("x")))
        results: list = []
        cli._setup_sonar_scanner_cli(False, results)
        assert results[0][1] == cli._SR_FAIL

    def test_ce_already_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager, sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: Path("/sq"))
        monkeypatch.setattr(sonarqube_manager, "patch_sonar_port", MagicMock())
        results: list = []
        cli._setup_sonarqube_ce(False, True, results)
        assert results[0][1] == cli._SR_OK

    def test_ce_check_not_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: None)
        results: list = []
        cli._setup_sonarqube_ce(True, True, results)
        assert "not installed" in results[0][2]

    def test_ce_download_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager, sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(sonarqube_manager, "ensure_sonarqube", AsyncMock(return_value=Path("/sq")))
        results: list = []
        cli._setup_sonarqube_ce(False, True, results)
        assert results[0][1] == cli._SR_OK

    def test_ce_download_fail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager, sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(sonarqube_manager, "ensure_sonarqube", AsyncMock(return_value=None))
        results: list = []
        cli._setup_sonarqube_ce(False, True, results)
        assert results[0][1] == cli._SR_FAIL

    def test_ce_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager, sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(sonarqube_manager, "ensure_sonarqube", AsyncMock(side_effect=RuntimeError("x")))
        results: list = []
        cli._setup_sonarqube_ce(False, False, results)
        assert results[0][1] == cli._SR_FAIL

    def test_persist_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "persist_env_var", lambda n, v: True)
        results: list = []
        cli._persist_sonar_token("https://h", "tok", results)
        assert any("Admin token" in r[0] for r in results)

    def test_token_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "ensure_admin_token", AsyncMock(return_value=("tok", "ok")))
        m = MagicMock()
        monkeypatch.setattr(cli, "_persist_sonar_token", m)
        cli._setup_sonarqube_token("https://h", [])
        m.assert_called_once()

    def test_token_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "ensure_admin_token", AsyncMock(return_value=(None, "no token")))
        monkeypatch.setattr(sonarqube_manager, "persist_env_var", lambda n, v: True)
        results: list = []
        cli._setup_sonarqube_token("https://h", results)
        assert any("Admin token" in r[0] for r in results)

    def test_token_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "ensure_admin_token", AsyncMock(side_effect=RuntimeError("boom")))
        monkeypatch.setattr(sonarqube_manager, "persist_env_var", lambda n, v: True)
        results: list = []
        cli._setup_sonarqube_token("https://h", results)
        assert any("boom" in str(r[2]) for r in results)

    def test_start_no_home(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: None)
        results: list = []
        cli._setup_sonarqube_start(False, results)
        assert results == []

    def test_start_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager, sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: Path("/sq"))
        monkeypatch.setattr(sonarqube_manager, "start_and_wait", AsyncMock(return_value=True))
        monkeypatch.setattr(cli, "_setup_sonarqube_token", MagicMock())
        results: list = []
        cli._setup_sonarqube_start(False, results)
        assert any("running at" in r[2] for r in results)

    def test_start_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager, sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: Path("/sq"))
        monkeypatch.setattr(sonarqube_manager, "start_and_wait", AsyncMock(return_value=False))
        results: list = []
        cli._setup_sonarqube_start(False, results)
        assert any("did not become UP" in r[2] for r in results)

    def test_start_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager, sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: Path("/sq"))
        monkeypatch.setattr(sonarqube_manager, "start_and_wait", AsyncMock(side_effect=RuntimeError("x")))
        results: list = []
        cli._setup_sonarqube_start(False, results)
        assert results[0][1] == cli._SR_FAIL

    def test_run_setup_not_requested_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: Path("/sq"))
        results: list = []
        cli._run_sonarqube_setup(False, False, False, results)
        assert "installed at" in results[0][2]

    def test_run_setup_not_requested_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_scanner
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: None)
        results: list = []
        cli._run_sonarqube_setup(False, False, False, results)
        assert "optional" in results[0][2]

    def test_run_setup_java_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "check_java", lambda: (False, "no java"))
        results: list = []
        cli._run_sonarqube_setup(False, True, False, results)
        assert results[0][0] == "Java 17+"
        assert results[0][1] == cli._SR_FAIL

    def test_run_setup_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "check_java", lambda: (True, "Java 21"))
        monkeypatch.setattr(cli, "_setup_sonar_scanner_cli", MagicMock())
        monkeypatch.setattr(cli, "_setup_sonarqube_ce", MagicMock())
        monkeypatch.setattr(cli, "_setup_sonarqube_start", MagicMock())
        results: list = []
        cli._run_sonarqube_setup(False, True, False, results)
        assert results[0][0] == "Java 17+"
        assert results[0][1] == cli._SR_OK


# --------------------------------------------------------------------------- #
# obfuscate helpers                                                            #
# --------------------------------------------------------------------------- #


class TestObfHelpers:
    def test_load_suppress(self, tmp_path: Path) -> None:
        (tmp_path / "suppress.txt").write_text("rule-a\n", encoding="utf-8")
        persistent, by_scanner = cli._obf_load_suppress(tmp_path)
        assert "rule-a" in persistent

    def test_apply_saved_session_missing(self, tmp_path: Path) -> None:
        with pytest.raises(typer.Exit):
            cli._obf_apply_saved_session(
                tmp_path / "nope.json", tmp_path, tmp_path / "bk", False, None, False, set()
            )

    def test_apply_saved_session_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        sess_file = tmp_path / "s.json"
        _session(items=[_item(rule_id="keep")]).save(sess_file)
        from obfuscation import engine
        monkeypatch.setattr(engine, "apply_session", MagicMock())
        cli._obf_apply_saved_session(sess_file, tmp_path, tmp_path / "bk", True, None, False, {"drop"})

    def test_parse_scanners_none(self) -> None:
        assert cli._obf_parse_scanners(None) is None

    def test_parse_scanners_valid(self) -> None:
        assert cli._obf_parse_scanners("gitleaks,presidio") == ["gitleaks", "presidio"]

    def test_parse_scanners_unknown(self) -> None:
        with pytest.raises(typer.Exit):
            cli._obf_parse_scanners("bogus")

    def test_print_summary(self, capsys: pytest.CaptureFixture) -> None:
        report = make_report(findings=[make_finding()])
        cli._obf_print_summary(report)
        assert "Scan complete" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# _write_obfuscation_report                                                   #
# --------------------------------------------------------------------------- #


class TestWriteObfuscationReport:
    def test_with_report(self, tmp_path: Path) -> None:
        report = make_report(findings=[])
        out = tmp_path / "r.html"
        with patch.object(cli, "render_html", return_value="<html>"):
            cli._write_obfuscation_report(report, _session(), out)
        assert out.read_text(encoding="utf-8") == "<html>"

    def test_no_report_uses_cache(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        report = make_report(findings=[])
        from scanners import orchestrator
        monkeypatch.setattr(orchestrator, "load_cached_report", lambda: report)
        out = tmp_path / "r.html"
        with patch.object(cli, "render_html", return_value="<html>"):
            cli._write_obfuscation_report(None, _session(), out)
        assert out.exists()

    def test_no_report_no_cache_warns(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import orchestrator
        monkeypatch.setattr(orchestrator, "load_cached_report", lambda: None)
        cli._write_obfuscation_report(None, _session(), tmp_path / "r.html")
        assert not (tmp_path / "r.html").exists()


# --------------------------------------------------------------------------- #
# edit helpers                                                                 #
# --------------------------------------------------------------------------- #


class TestEditHelpers:
    def test_show_current(self, capsys: pytest.CaptureFixture) -> None:
        cli._edit_show_current(_item(skip_reason="dummy"))
        assert "src/app.py" in capsys.readouterr().out

    def test_update_decision_flag(self) -> None:
        item = _item()
        cli._edit_update_decision(item, "approved")
        assert item.decision == "approved"

    def test_update_decision_invalid(self) -> None:
        with pytest.raises(typer.Exit):
            cli._edit_update_decision(_item(), "bogus")

    def test_update_decision_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rich import prompt
        monkeypatch.setattr(prompt.Prompt, "ask", lambda *a, **k: "skipped")
        item = _item()
        cli._edit_update_decision(item, None)
        assert item.decision == "skipped"

    def test_update_replacement_flag(self) -> None:
        item = _item()
        cli._edit_update_replacement(item, "[NEW]")
        assert item.replacement == "[NEW]"

    def test_update_replacement_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rich import prompt
        monkeypatch.setattr(prompt.Prompt, "ask", lambda *a, **k: "[X]")
        item = _item()
        cli._edit_update_replacement(item, None)
        assert item.replacement == "[X]"

    def test_update_skip_reason_not_skipped(self) -> None:
        item = _item(decision="approved", skip_reason="old")
        cli._edit_update_skip_reason(item, None)
        assert item.skip_reason == ""

    def test_update_skip_reason_flag(self) -> None:
        item = _item(decision="skipped")
        cli._edit_update_skip_reason(item, "test data")
        assert item.skip_reason == "test data"

    def test_update_skip_reason_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rich import prompt
        monkeypatch.setattr(prompt.Prompt, "ask", lambda *a, **k: "manual reason")
        item = _item(decision="skipped")
        cli._edit_update_skip_reason(item, None)
        assert item.skip_reason == "manual reason"


# --------------------------------------------------------------------------- #
# main                                                                         #
# --------------------------------------------------------------------------- #


class TestMain:
    def test_main_invokes_app(self, monkeypatch: pytest.MonkeyPatch) -> None:
        m = MagicMock()
        monkeypatch.setattr(cli, "app", m)
        cli.main()
        m.assert_called_once()


# --------------------------------------------------------------------------- #
# Command tests via CliRunner                                                  #
# --------------------------------------------------------------------------- #


class TestScanCommand:
    def test_scan_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        report = make_report(findings=[])
        monkeypatch.setattr(cli, "run_scan", AsyncMock(return_value=report))
        result = runner.invoke(cli.app, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_unknown_scanner(self, tmp_path: Path) -> None:
        result = runner.invoke(cli.app, ["scan", str(tmp_path), "--scanners", "bogus"])
        assert result.exit_code == 1

    def test_scan_unknown_format(self, tmp_path: Path) -> None:
        result = runner.invoke(cli.app, ["scan", str(tmp_path), "--format", "xml"])
        assert result.exit_code == 1

    def test_scan_fail_on(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        report = make_report(findings=[make_finding(severity="critical")])
        monkeypatch.setattr(cli, "run_scan", AsyncMock(return_value=report))
        result = runner.invoke(cli.app, ["scan", str(tmp_path), "--fail-on", "high"])
        assert result.exit_code == 2


class TestStatusCommand:
    def test_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli, "_status_binary_lines", lambda: ["bin"])
        monkeypatch.setattr(cli, "_status_semgrep_line", lambda: "semgrep")
        monkeypatch.setattr(cli, "_status_sonarqube_lines", lambda *a: ["sq"])
        monkeypatch.setattr(cli, "_status_nlp_lines", lambda: ["nlp"])
        monkeypatch.setattr(cli, "_compute_tier", lambda *a: 1)
        from scanners import constants, sonarqube_scanner
        monkeypatch.setattr(constants, "detect_container_runtime", lambda: None)
        monkeypatch.setattr(sonarqube_scanner, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr("shutil.which", lambda t: None)
        result = runner.invoke(cli.app, ["status"])
        assert result.exit_code == 0
        assert "Active tier: 1" in result.stdout


class TestReportCommand:
    def test_report_no_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli, "load_cached_report", lambda: None)
        result = runner.invoke(cli.app, ["report"])
        assert result.exit_code == 1

    def test_report_bad_format(self) -> None:
        result = runner.invoke(cli.app, ["report", "--format", "xml"])
        assert result.exit_code == 1

    def test_report_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        report = make_report(findings=[])
        monkeypatch.setattr(cli, "load_cached_report", lambda: report)
        monkeypatch.setattr(cli, "_render_and_write", MagicMock())
        result = runner.invoke(cli.app, ["report", "--format", "json"])
        assert result.exit_code == 0

    def test_report_html_confidence(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        report = make_report(findings=[])
        monkeypatch.setattr(cli, "load_cached_report", lambda: report)
        from reporting import html_reporter
        monkeypatch.setattr(html_reporter, "render_html", lambda *a, **k: "<html>")
        out = tmp_path / "r.html"
        result = runner.invoke(cli.app, ["report", "--format", "html", "--show-confidence", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()


class TestSetupCommand:
    def test_setup_check(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from scanners import sonarqube_manager
        monkeypatch.setattr(sonarqube_manager, "_SQ_DIR", tmp_path / "sq")
        monkeypatch.setattr(cli, "_run_gitleaks_setup", MagicMock())
        monkeypatch.setattr(cli, "_run_semgrep_setup", MagicMock())
        monkeypatch.setattr(cli, "_run_spacy_setup", MagicMock())
        monkeypatch.setattr(cli, "_run_sonarqube_setup", MagicMock())
        result = runner.invoke(cli.app, ["setup", "--check"])
        assert result.exit_code == 0


class TestRollbackCommand:
    def test_rollback_missing_backup(self, tmp_path: Path) -> None:
        result = runner.invoke(cli.app, ["rollback", str(tmp_path), "--backup-dir", str(tmp_path / "nope")])
        assert result.exit_code == 1

    def test_rollback_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        backup = tmp_path / "bk"
        backup.mkdir()
        from obfuscation import engine
        monkeypatch.setattr(engine, "rollback", lambda *a, **k: 3)
        result = runner.invoke(cli.app, ["rollback", str(tmp_path), "--backup-dir", str(backup)])
        assert result.exit_code == 0
        assert "3 file(s) restored" in result.stdout

    def test_rollback_no_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        backup = tmp_path / "bk"
        backup.mkdir()
        from obfuscation import engine
        monkeypatch.setattr(engine, "rollback", lambda *a, **k: 0)
        result = runner.invoke(cli.app, ["rollback", str(tmp_path), "--backup-dir", str(backup)])
        assert result.exit_code == 0
        assert "No files found" in result.stdout


class TestEditCommand:
    def test_edit_no_session(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cli.app, ["edit", "abc123"])
        assert result.exit_code == 1

    def test_edit_id_not_found(self, tmp_path: Path) -> None:
        sess = tmp_path / "s.json"
        _session(items=[_item(finding_id="other")]).save(sess)
        result = runner.invoke(cli.app, ["edit", "abc123", "--session", str(sess)])
        assert result.exit_code == 1

    def test_edit_success(self, tmp_path: Path) -> None:
        sess = tmp_path / "s.json"
        _session(items=[_item(finding_id="abc123")]).save(sess)
        result = runner.invoke(
            cli.app, ["edit", "abc123", "--session", str(sess), "--decision", "approved", "--replacement", "[X]"]
        )
        assert result.exit_code == 0
        reloaded = ReviewSession.load(sess)
        assert reloaded.items[0].decision == "approved"
        assert reloaded.items[0].replacement == "[X]"

    def test_edit_success_with_report(self, tmp_path: Path) -> None:
        sess = tmp_path / "s.json"
        _session(items=[_item(finding_id="abc123")]).save(sess)
        out = tmp_path / "r.html"
        with patch.object(cli, "_write_obfuscation_report") as m:
            result = runner.invoke(
                cli.app,
                ["edit", "abc123", "--session", str(sess), "--decision", "skipped",
                 "--skip-reason", "test data", "--replacement", "[X]", "--report", str(out)],
            )
        assert result.exit_code == 0
        m.assert_called_once()


class TestObfuscateCommand:
    def test_obfuscate_apply_session(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        sess = tmp_path / "s.json"
        _session(items=[_item()]).save(sess)
        monkeypatch.setattr(cli, "_obf_apply_saved_session", MagicMock())
        result = runner.invoke(cli.app, ["obfuscate", str(tmp_path), "--apply-session", str(sess)])
        assert result.exit_code == 0

    def test_obfuscate_no_findings(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        report = make_report(findings=[])
        from scanners import orchestrator
        monkeypatch.setattr(orchestrator, "run_scan", AsyncMock(return_value=report))
        result = runner.invoke(cli.app, ["obfuscate", str(tmp_path)])
        assert result.exit_code == 0
        assert "nothing to obfuscate" in result.stdout

    def test_obfuscate_full_flow_applied(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        report = make_report(findings=[make_finding(file="app.py")])
        from scanners import orchestrator
        from obfuscation import reviewer, engine
        monkeypatch.setattr(orchestrator, "run_scan", AsyncMock(return_value=report))
        sess = _session(items=[_item(decision="approved")])
        monkeypatch.setattr(reviewer, "run_review", lambda *a, **k: sess)
        apply_result = MagicMock(applied_count=1, failed_count=0)
        monkeypatch.setattr(engine, "apply_session", lambda *a, **k: apply_result)
        out = tmp_path / "obf.html"
        with patch.object(cli, "render_html", return_value="<html>"):
            result = runner.invoke(cli.app, ["obfuscate", str(tmp_path), "--report", str(out)])
        assert result.exit_code == 0
        assert "Done." in result.stdout

    def test_obfuscate_no_approvals(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        report = make_report(findings=[make_finding(file="app.py")])
        from scanners import orchestrator
        from obfuscation import reviewer
        monkeypatch.setattr(orchestrator, "run_scan", AsyncMock(return_value=report))
        sess = _session(items=[_item(decision="skipped")])
        monkeypatch.setattr(reviewer, "run_review", lambda *a, **k: sess)
        result = runner.invoke(cli.app, ["obfuscate", str(tmp_path)])
        assert result.exit_code == 0
        assert "no files modified" in result.stdout
