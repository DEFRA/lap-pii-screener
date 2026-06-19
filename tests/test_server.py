"""Tests for src/server.py (MCP server tools and helpers)."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import server
from conftest import make_finding, make_report
from models.report import Report


# --------------------------------------------------------------------------- #
# _validate_path                                                              #
# --------------------------------------------------------------------------- #


class TestValidatePath:
    def test_valid_dir(self, tmp_path: Path) -> None:
        assert server._validate_path(str(tmp_path)) == tmp_path.resolve()

    def test_missing_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="does not exist"):
            server._validate_path(str(tmp_path / "nope"))

    def test_file_not_dir_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "f.txt"
        f.write_text("x", encoding="utf-8")
        with pytest.raises(ValueError, match="not a directory"):
            server._validate_path(str(f))


# --------------------------------------------------------------------------- #
# _render                                                                     #
# --------------------------------------------------------------------------- #


class TestRender:
    @pytest.fixture
    def report(self) -> Report:
        return make_report(findings=[])

    @pytest.mark.parametrize(
        "fmt,target",
        [
            ("json", "render_json"),
            ("JSON", "render_json"),
            ("html", "render_html"),
            ("console", "render_console"),
            ("markdown", "render_markdown"),
            ("unknown", "render_markdown"),
        ],
    )
    def test_dispatch(self, report: Report, fmt: str, target: str) -> None:
        with patch.object(server, target, return_value="OUT") as m:
            assert server._render(report, fmt) == "OUT"
        m.assert_called_once_with(report)


# --------------------------------------------------------------------------- #
# scan_codebase                                                               #
# --------------------------------------------------------------------------- #


class TestScanCodebase:
    @pytest.mark.asyncio
    async def test_invalid_path_returns_error(self, tmp_path: Path) -> None:
        out = await server.scan_codebase(str(tmp_path / "nope"))
        assert out.startswith("**Error:**")

    @pytest.mark.asyncio
    async def test_run_scan_exception_returns_error(self, tmp_path: Path) -> None:
        with patch.object(server, "run_scan", AsyncMock(side_effect=RuntimeError("boom"))):
            out = await server.scan_codebase(str(tmp_path))
        assert out.startswith("**Scan error:**")

    @pytest.mark.asyncio
    async def test_success_renders_markdown(self, tmp_path: Path) -> None:
        report = make_report(findings=[])
        with patch.object(server, "run_scan", AsyncMock(return_value=report)), patch.object(
            server, "render_markdown", return_value="MD"
        ):
            out = await server.scan_codebase(str(tmp_path))
        assert out == "MD"

    @pytest.mark.asyncio
    async def test_default_scanners_passed(self, tmp_path: Path) -> None:
        captured = {}

        async def _fake(config):  # noqa: ANN001, ANN202
            captured["scanners"] = config.scanners
            return make_report(findings=[])

        with patch.object(server, "run_scan", _fake), patch.object(server, "render_markdown", return_value="MD"):
            await server.scan_codebase(str(tmp_path))
        assert captured["scanners"] == ["gitleaks", "semgrep", "pii", "sonarqube"]


# --------------------------------------------------------------------------- #
# get_report                                                                  #
# --------------------------------------------------------------------------- #


class TestGetReport:
    @pytest.mark.asyncio
    async def test_no_report(self) -> None:
        with patch.object(server, "load_cached_report", return_value=None):
            out = await server.get_report()
        assert out == server._NO_REPORT_MSG

    @pytest.mark.asyncio
    async def test_renders_with_format(self) -> None:
        report = make_report(findings=[])
        with patch.object(server, "load_cached_report", return_value=report), patch.object(
            server, "_render", return_value="RENDERED"
        ) as m:
            out = await server.get_report("json")
        assert out == "RENDERED"
        m.assert_called_once_with(report, "json")


# --------------------------------------------------------------------------- #
# list_findings                                                               #
# --------------------------------------------------------------------------- #


class TestListFindings:
    @pytest.mark.asyncio
    async def test_no_report(self) -> None:
        with patch.object(server, "load_cached_report", return_value=None):
            out = await server.list_findings()
        assert out == server._NO_REPORT_MSG

    @pytest.mark.asyncio
    async def test_no_matches(self) -> None:
        report = make_report(findings=[make_finding(severity="low")])
        with patch.object(server, "load_cached_report", return_value=report):
            out = await server.list_findings(severity="critical")
        assert out == "No findings match the specified filters."

    @pytest.mark.asyncio
    async def test_filters_combined(self) -> None:
        f1 = make_finding(severity="high", category="pii_ssn", file="src/config.py")
        f2 = make_finding(severity="low", category="api_key_aws", file="README.md")
        report = make_report(findings=[f1, f2])
        with patch.object(server, "load_cached_report", return_value=report):
            out = await server.list_findings(severity="high", category="pii", file_pattern="config")
        assert "1 finding(s)" in out
        assert "pii_ssn" in out
        assert "api_key_aws" not in out

    @pytest.mark.asyncio
    async def test_table_header_present(self) -> None:
        report = make_report(findings=[make_finding(severity="high")])
        with patch.object(server, "load_cached_report", return_value=report):
            out = await server.list_findings()
        assert "| Severity | File | Line | Category | Match | Scanners |" in out


# --------------------------------------------------------------------------- #
# get_remediation                                                             #
# --------------------------------------------------------------------------- #


class TestGetRemediation:
    @pytest.mark.asyncio
    async def test_no_report(self) -> None:
        with patch.object(server, "load_cached_report", return_value=None):
            out = await server.get_remediation("abc")
        assert out == server._NO_REPORT_MSG

    @pytest.mark.asyncio
    async def test_not_found(self) -> None:
        report = make_report(findings=[make_finding()])
        with patch.object(server, "load_cached_report", return_value=report):
            out = await server.get_remediation("missing-id")
        assert "not found" in out

    @pytest.mark.asyncio
    async def test_full_remediation(self) -> None:
        f = make_finding(category="pii_ssn", severity="high")
        f.message = "SSN detected"
        f.references = ["https://owasp.org/x", "CWE-200"]
        report = make_report(findings=[f])
        with patch.object(server, "load_cached_report", return_value=report):
            out = await server.get_remediation(f.id)
        assert "Remediation: `pii_ssn`" in out
        assert "[https://owasp.org/x](https://owasp.org/x)" in out
        assert "- CWE-200" in out

    @pytest.mark.asyncio
    async def test_fix_steps_rendered(self) -> None:
        f = make_finding()
        f.fix_steps = ["Rotate the key", "Use a vault"]
        report = make_report(findings=[f])
        with patch.object(server, "load_cached_report", return_value=report):
            out = await server.get_remediation(f.id)
        assert "1. Rotate the key" in out
        assert "2. Use a vault" in out


# --------------------------------------------------------------------------- #
# _binary_status_lines                                                        #
# --------------------------------------------------------------------------- #


class TestBinaryStatusLines:
    def test_installed_and_system(self) -> None:
        with patch.object(server, "is_installed", return_value=True), patch.object(
            server.shutil, "which", side_effect=lambda t: "/usr/bin/" + t if t == "gitleaks" else None
        ):
            lines = server._binary_status_lines()
        assert any("installed" in ln for ln in lines)
        assert any("gitleaks** (system)" in ln for ln in lines)

    def test_not_downloaded(self) -> None:
        with patch.object(server, "is_installed", return_value=False), patch.object(
            server.shutil, "which", return_value=None
        ):
            lines = server._binary_status_lines()
        assert any("not downloaded" in ln for ln in lines)


# --------------------------------------------------------------------------- #
# _native_sonarqube_lines                                                     #
# --------------------------------------------------------------------------- #


class TestNativeSonarqubeLines:
    def test_native_with_scanner(self) -> None:
        with patch.object(server, "_find_sonar_scanner", return_value="/sc/bin"), patch.object(
            server.shutil, "which", return_value="/usr/bin/docker"
        ):
            lines = server._native_sonarqube_lines("/sq", "/java")
        text = "\n".join(lines)
        assert "Native SonarQube:** ✅" in text
        assert "sonar-scanner CLI:** ✅" in text
        assert "Container runtime:** ✅" in text

    def test_native_without_scanner(self) -> None:
        with patch.object(server, "_find_sonar_scanner", return_value=None), patch.object(
            server.shutil, "which", return_value=None
        ):
            lines = server._native_sonarqube_lines("/sq", "/java")
        text = "\n".join(lines)
        assert "sonar-scanner CLI:** ⚠️" in text
        assert "Container runtime:** ℹ️" in text

    def test_home_without_java(self) -> None:
        with patch.object(server.shutil, "which", return_value=None):
            lines = server._native_sonarqube_lines("/sq", None)
        assert any("Java is not on PATH" in ln for ln in lines)

    def test_no_home(self) -> None:
        with patch.object(server.shutil, "which", return_value=None):
            lines = server._native_sonarqube_lines(None, None)
        assert any("not found" in ln for ln in lines)


# --------------------------------------------------------------------------- #
# _spacy_status_lines                                                         #
# --------------------------------------------------------------------------- #


def _install_fake_spacy(monkeypatch: pytest.MonkeyPatch, load_side):  # noqa: ANN001, ANN202
    mod = types.ModuleType("spacy")
    mod.load = MagicMock(side_effect=load_side)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "spacy", mod)


class TestSpacyStatusLines:
    def test_loaded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_spacy(monkeypatch, lambda name: object())
        lines = server._spacy_status_lines()
        assert "en_core_web_sm loaded" in lines[0]

    def test_model_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_spacy(monkeypatch, OSError("missing"))
        lines = server._spacy_status_lines()
        assert "model missing" in lines[0]

    def test_not_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "spacy", None)
        lines = server._spacy_status_lines()
        assert "not installed" in lines[0]


# --------------------------------------------------------------------------- #
# _sonarqube_status_lines                                                     #
# --------------------------------------------------------------------------- #


class TestSonarqubeStatusLines:
    @pytest.mark.asyncio
    async def test_start_no_backend(self) -> None:
        sq = MagicMock()
        with patch.object(server, "_read_sonar_port", return_value=9000):
            lines = await server._sonarqube_status_lines(sq, None, None, None, start_sonarqube=True)
        assert any("cannot start" in ln for ln in lines)

    @pytest.mark.asyncio
    async def test_start_native_success(self) -> None:
        sq = MagicMock()
        sq.start_sonarqube = AsyncMock(return_value=True)
        with patch.object(server, "_read_sonar_port", return_value=9000):
            lines = await server._sonarqube_status_lines(sq, "/sq", "/java", None, start_sonarqube=True)
        assert any("ready at" in ln for ln in lines)

    @pytest.mark.asyncio
    async def test_start_docker_failure(self) -> None:
        sq = MagicMock()
        sq.start_sonarqube = AsyncMock(return_value=False)
        with patch.object(server, "_read_sonar_port", return_value=9000):
            lines = await server._sonarqube_status_lines(sq, None, None, "/docker", start_sonarqube=True)
        assert any("failed to start" in ln for ln in lines)

    @pytest.mark.asyncio
    async def test_already_running(self) -> None:
        sq = MagicMock()
        sq._is_ready = AsyncMock(return_value=True)
        with patch.object(server, "_read_sonar_port", return_value=9000):
            lines = await server._sonarqube_status_lines(sq, "/sq", "/java", None, start_sonarqube=False)
        assert any("running at" in ln for ln in lines)

    @pytest.mark.asyncio
    async def test_not_running_but_available(self) -> None:
        sq = MagicMock()
        sq._is_ready = AsyncMock(return_value=False)
        with patch.object(server, "_read_sonar_port", return_value=9000):
            lines = await server._sonarqube_status_lines(sq, "/sq", None, "/docker", start_sonarqube=False)
        assert any("not running" in ln for ln in lines)

    @pytest.mark.asyncio
    async def test_not_running_no_backend(self) -> None:
        sq = MagicMock()
        sq._is_ready = AsyncMock(return_value=False)
        lines = await server._sonarqube_status_lines(sq, None, None, None, start_sonarqube=False)
        assert any("install SonarQube CE" in ln for ln in lines)


# --------------------------------------------------------------------------- #
# check_scanner_status                                                        #
# --------------------------------------------------------------------------- #


class TestCheckScannerStatus:
    @pytest.mark.asyncio
    async def test_tier1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(server.shutil, "which", lambda t: None)
        monkeypatch.setattr(server, "SonarQubeScanner", lambda: MagicMock())
        monkeypatch.setattr(server, "_binary_status_lines", lambda: ["bin"])
        monkeypatch.setattr(server, "_native_sonarqube_lines", lambda *a: ["native"])
        monkeypatch.setattr(server, "_spacy_status_lines", lambda: ["spacy"])
        monkeypatch.setattr(server, "_sonarqube_status_lines", AsyncMock(return_value=["sq"]))
        monkeypatch.delenv("SONAR_TOKEN", raising=False)
        out = await server.check_scanner_status()
        assert "**Active tier:** 1" in out

    @pytest.mark.asyncio
    async def test_tier2_with_runtime(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(server.shutil, "which", lambda t: "/usr/bin/docker" if t == "docker" else None)
        monkeypatch.setattr(server, "SonarQubeScanner", lambda: MagicMock())
        monkeypatch.setattr(server, "_binary_status_lines", lambda: ["bin"])
        monkeypatch.setattr(server, "_native_sonarqube_lines", lambda *a: ["native"])
        monkeypatch.setattr(server, "_spacy_status_lines", lambda: ["spacy"])
        monkeypatch.setattr(server, "_sonarqube_status_lines", AsyncMock(return_value=["sq"]))
        monkeypatch.delenv("SONAR_TOKEN", raising=False)
        out = await server.check_scanner_status()
        assert "**Active tier:** 2" in out

    @pytest.mark.asyncio
    async def test_tier3_sonarcloud(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(server.shutil, "which", lambda t: "/usr/bin/docker" if t == "docker" else None)
        monkeypatch.setattr(server, "SonarQubeScanner", lambda: MagicMock())
        monkeypatch.setattr(server, "_binary_status_lines", lambda: ["bin"])
        monkeypatch.setattr(server, "_native_sonarqube_lines", lambda *a: ["native"])
        monkeypatch.setattr(server, "_spacy_status_lines", lambda: ["spacy"])
        monkeypatch.setattr(server, "_sonarqube_status_lines", AsyncMock(return_value=["sq"]))
        monkeypatch.setenv("SONAR_TOKEN", "tok")
        monkeypatch.setenv("SONAR_HOST_URL", "https://sonarcloud.io")
        out = await server.check_scanner_status()
        assert "**Active tier:** 3" in out


# --------------------------------------------------------------------------- #
# main                                                                        #
# --------------------------------------------------------------------------- #


class TestMain:
    def test_main_runs_stdio(self) -> None:
        with patch.object(server.mcp, "run") as m:
            server.main()
        m.assert_called_once_with(transport="stdio")
