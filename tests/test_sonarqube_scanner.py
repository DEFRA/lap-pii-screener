"""Tests for src/scanners/sonarqube_scanner.py."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from models.finding import ScanConfig
from conftest import make_finding
from scanners import sonarqube_scanner as ss
from scanners.sonarqube_scanner import SonarQubeScanner


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _client(get_resp=None, post_resp=None, get_side=None) -> AsyncMock:
    client = AsyncMock()
    if get_side is not None:
        client.get = AsyncMock(side_effect=get_side)
    else:
        client.get = AsyncMock(return_value=get_resp)
    client.post = AsyncMock(return_value=post_resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


def _proc(returncode: int = 0, stderr: bytes = b"") -> MagicMock:
    p = MagicMock()
    p.returncode = returncode
    p.communicate = AsyncMock(return_value=(b"", stderr))
    return p


def _rule(severity: str = "high") -> MagicMock:
    r = MagicMock()
    r.severity = severity
    r.description = "desc"
    r.fix_steps = ["step"]
    r.references = ["https://ref"]
    return r


# --------------------------------------------------------------------------- #
# _find_native_sonarqube                                                      #
# --------------------------------------------------------------------------- #


class TestFindNativeSonarqube:
    def test_env_var(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SONARQUBE_HOME", str(tmp_path))
        assert ss._find_native_sonarqube() == tmp_path

    def test_default_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SONARQUBE_HOME", raising=False)
        monkeypatch.setattr(ss, "_NATIVE_SQ_DEFAULT", tmp_path)
        assert ss._find_native_sonarqube() == tmp_path

    def test_versioned_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SONARQUBE_HOME", raising=False)
        default = tmp_path / "sonarqube"
        monkeypatch.setattr(ss, "_NATIVE_SQ_DEFAULT", default)
        versioned = tmp_path / "sonarqube-26.1.0.123"
        (versioned / "bin").mkdir(parents=True)
        out = ss._find_native_sonarqube()
        assert out == versioned

    def test_none_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SONARQUBE_HOME", raising=False)
        monkeypatch.setattr(ss, "_NATIVE_SQ_DEFAULT", tmp_path / "sonarqube")
        with patch.object(ss.Path, "exists", return_value=False):
            assert ss._find_native_sonarqube() is None


# --------------------------------------------------------------------------- #
# _read_sonar_port                                                            #
# --------------------------------------------------------------------------- #


class TestReadSonarPort:
    def test_missing_props_default(self, tmp_path: Path) -> None:
        assert ss._read_sonar_port(tmp_path) == 9100

    def test_reads_port(self, tmp_path: Path) -> None:
        conf = tmp_path / "conf"
        conf.mkdir()
        (conf / "sonar.properties").write_text("sonar.web.port=9200\n", encoding="utf-8")
        assert ss._read_sonar_port(tmp_path) == 9200

    def test_invalid_value_default(self, tmp_path: Path) -> None:
        conf = tmp_path / "conf"
        conf.mkdir()
        (conf / "sonar.properties").write_text("sonar.web.port=abc\n", encoding="utf-8")
        assert ss._read_sonar_port(tmp_path) == 9100

    def test_no_port_line_default(self, tmp_path: Path) -> None:
        conf = tmp_path / "conf"
        conf.mkdir()
        (conf / "sonar.properties").write_text("other=1\n", encoding="utf-8")
        assert ss._read_sonar_port(tmp_path) == 9100


# --------------------------------------------------------------------------- #
# _resolve_host_url                                                           #
# --------------------------------------------------------------------------- #


class TestResolveHostUrl:
    def test_env_var_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SONAR_HOST_URL", "https://sonarcloud.io/")
        assert ss._resolve_host_url() == "https://sonarcloud.io"

    def test_native_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SONAR_HOST_URL", raising=False)
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: Path("/sq"))
        monkeypatch.setattr(ss, "_read_sonar_port", lambda h: 9100)
        assert ss._resolve_host_url() == "http://localhost:9100"

    def test_no_native_default_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SONAR_HOST_URL", raising=False)
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: None)
        assert ss._resolve_host_url() == "http://localhost:9100"


# --------------------------------------------------------------------------- #
# _find_sonar_scanner                                                         #
# --------------------------------------------------------------------------- #


class TestFindSonarScanner:
    def test_env_home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SONAR_SCANNER_HOME", str(tmp_path))
        monkeypatch.setattr(ss.sys, "platform", "linux")
        exe = tmp_path / "bin" / "sonar-scanner"
        exe.parent.mkdir(parents=True)
        exe.write_text("x", encoding="utf-8")
        assert ss._find_sonar_scanner() == str(exe)

    def test_default_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SONAR_SCANNER_HOME", raising=False)
        monkeypatch.setattr(ss.sys, "platform", "linux")
        monkeypatch.setattr(ss, "_NATIVE_SCANNER_DEFAULT", tmp_path)
        exe = tmp_path / "bin" / "sonar-scanner"
        exe.parent.mkdir(parents=True)
        exe.write_text("x", encoding="utf-8")
        assert ss._find_sonar_scanner() == str(exe)

    def test_path_lookup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SONAR_SCANNER_HOME", raising=False)
        monkeypatch.setattr(ss.sys, "platform", "linux")
        monkeypatch.setattr(ss, "_NATIVE_SCANNER_DEFAULT", Path("/nonexistent"))
        monkeypatch.setattr(ss.shutil, "which", lambda t: "/usr/bin/sonar-scanner")
        assert ss._find_sonar_scanner() == "/usr/bin/sonar-scanner"


# --------------------------------------------------------------------------- #
# _native_start_script                                                        #
# --------------------------------------------------------------------------- #


class TestNativeStartScript:
    def test_windows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ss.platform, "system", lambda: "Windows")
        monkeypatch.setattr(ss.platform, "machine", lambda: "AMD64")
        s = tmp_path / "bin" / "windows-x86-64" / "StartSonar.bat"
        s.parent.mkdir(parents=True)
        s.write_text("x", encoding="utf-8")
        assert ss._native_start_script(tmp_path) == s

    def test_linux(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ss.platform, "system", lambda: "Linux")
        monkeypatch.setattr(ss.platform, "machine", lambda: "x86_64")
        s = tmp_path / "bin" / "linux-x86-64" / "sonar.sh"
        s.parent.mkdir(parents=True)
        s.write_text("x", encoding="utf-8")
        assert ss._native_start_script(tmp_path) == s

    def test_macos(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ss.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(ss.platform, "machine", lambda: "arm64")
        s = tmp_path / "bin" / "macosx-universal-64" / "sonar.sh"
        s.parent.mkdir(parents=True)
        s.write_text("x", encoding="utf-8")
        assert ss._native_start_script(tmp_path) == s

    def test_missing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ss.platform, "system", lambda: "Linux")
        monkeypatch.setattr(ss.platform, "machine", lambda: "x86_64")
        assert ss._native_start_script(tmp_path) is None


# --------------------------------------------------------------------------- #
# _is_non_security_rule                                                       #
# --------------------------------------------------------------------------- #


class TestIsNonSecurityRule:
    @pytest.mark.parametrize("rid", ["css:foo", "HTML:bar", "web:x", "xml:y", "jsp:z", "plsql:q"])
    def test_non_security(self, rid: str) -> None:
        assert ss._is_non_security_rule(rid) is True

    @pytest.mark.parametrize("rid", ["python:S123", "java:S456", "secrets:aws"])
    def test_security(self, rid: str) -> None:
        assert ss._is_non_security_rule(rid) is False


# --------------------------------------------------------------------------- #
# _apply_windows_sonar_props                                                  #
# --------------------------------------------------------------------------- #


class TestApplyWindowsSonarProps:
    def test_missing_noop(self, tmp_path: Path) -> None:
        ss._apply_windows_sonar_props(tmp_path / "nope.properties")  # no raise

    def test_sets_port_when_absent(self, tmp_path: Path) -> None:
        props = tmp_path / "sonar.properties"
        props.write_text("# config\n", encoding="utf-8")
        ss._apply_windows_sonar_props(props, 9100)
        assert "sonar.web.port=9100" in props.read_text(encoding="utf-8")

    def test_skips_when_already_set(self, tmp_path: Path) -> None:
        props = tmp_path / "sonar.properties"
        props.write_text("sonar.web.port=9000\n", encoding="utf-8")
        ss._apply_windows_sonar_props(props, 9100)
        text = props.read_text(encoding="utf-8")
        assert "sonar.web.port=9000" in text
        assert "9100" not in text

    def test_removes_obsolete_setting(self, tmp_path: Path) -> None:
        props = tmp_path / "sonar.properties"
        props.write_text("bootstrap.system_call_filter=false\n", encoding="utf-8")
        ss._apply_windows_sonar_props(props, 9100)
        text = props.read_text(encoding="utf-8")
        assert "bootstrap.system_call_filter" not in text
        assert "sonar.web.port=9100" in text


# --------------------------------------------------------------------------- #
# _print_startup_diagnostics                                                  #
# --------------------------------------------------------------------------- #


class TestPrintStartupDiagnostics:
    def test_with_logs(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        (tmp_path / "es.log").write_text("INFO ok\nERROR boom\n", encoding="utf-8")
        ss._print_startup_diagnostics(tmp_path)
        err = capsys.readouterr().err
        assert "ERROR boom" in err
        assert "Common fixes" in err

    def test_without_logs(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        ss._print_startup_diagnostics(tmp_path)
        assert "Common fixes" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# is_available / name                                                         #
# --------------------------------------------------------------------------- #


class TestIsAvailable:
    def test_name(self) -> None:
        assert SonarQubeScanner().name == "sonarqube"

    @pytest.mark.asyncio
    async def test_native(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: Path("/sq"))
        monkeypatch.setattr(ss.shutil, "which", lambda t: "/usr/bin/java")
        assert await SonarQubeScanner().is_available() is True

    @pytest.mark.asyncio
    async def test_docker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(ss.shutil, "which", lambda t: None)
        monkeypatch.setattr(ss, "detect_container_runtime", lambda: "docker")
        assert await SonarQubeScanner().is_available() is True

    @pytest.mark.asyncio
    async def test_sonarcloud(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(ss.shutil, "which", lambda t: None)
        monkeypatch.setattr(ss, "detect_container_runtime", lambda: None)
        monkeypatch.setenv("SONAR_HOST_URL", "https://sonarcloud.io")
        monkeypatch.setenv("SONAR_TOKEN", "tok")
        assert await SonarQubeScanner().is_available() is True

    @pytest.mark.asyncio
    async def test_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(ss.shutil, "which", lambda t: None)
        monkeypatch.setattr(ss, "detect_container_runtime", lambda: None)
        monkeypatch.delenv("SONAR_HOST_URL", raising=False)
        monkeypatch.delenv("SONAR_TOKEN", raising=False)
        assert await SonarQubeScanner().is_available() is False


# --------------------------------------------------------------------------- #
# start_sonarqube                                                             #
# --------------------------------------------------------------------------- #


class TestStartSonarqube:
    @pytest.mark.asyncio
    async def test_native(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: Path("/sq"))
        monkeypatch.setattr(ss.shutil, "which", lambda t: "/usr/bin/java")
        sq._start_native = AsyncMock(return_value=True)
        assert await sq.start_sonarqube() is True

    @pytest.mark.asyncio
    async def test_docker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(ss.shutil, "which", lambda t: None)
        monkeypatch.setattr(ss, "detect_container_runtime", lambda: "docker")
        sq._start_docker = AsyncMock(return_value=True)
        assert await sq.start_sonarqube() is True

    @pytest.mark.asyncio
    async def test_no_runtime(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(ss.shutil, "which", lambda t: None)
        monkeypatch.setattr(ss, "detect_container_runtime", lambda: None)
        assert await sq.start_sonarqube() is False


# --------------------------------------------------------------------------- #
# scan                                                                        #
# --------------------------------------------------------------------------- #


class TestScan:
    @pytest.mark.asyncio
    async def test_delegates_to_run(self) -> None:
        sq = SonarQubeScanner()
        sq._run = AsyncMock(return_value=["x"])
        cfg = ScanConfig(path="/p")
        assert await sq.scan(cfg) == ["x"]

    @pytest.mark.asyncio
    async def test_exception_returns_empty(self) -> None:
        sq = SonarQubeScanner()
        sq._run = AsyncMock(side_effect=RuntimeError("boom"))
        assert await sq.scan(ScanConfig(path="/p")) == []


# --------------------------------------------------------------------------- #
# _start_docker / _compose_cmd                                                #
# --------------------------------------------------------------------------- #


class TestStartDocker:
    def test_compose_cmd(self) -> None:
        assert SonarQubeScanner._compose_cmd("podman") == ["podman", "compose"]

    @pytest.mark.asyncio
    async def test_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss.asyncio, "create_subprocess_exec", AsyncMock(return_value=_proc(0)))
        monkeypatch.setattr(ss, "_resolve_host_url", lambda: "http://localhost:9100")
        sq._wait_ready = AsyncMock(return_value=True)
        assert await sq._start_docker("docker") is True

    @pytest.mark.asyncio
    async def test_compose_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss.asyncio, "create_subprocess_exec", AsyncMock(return_value=_proc(1)))
        assert await sq._start_docker("docker") is False


# --------------------------------------------------------------------------- #
# _start_native                                                               #
# --------------------------------------------------------------------------- #


class TestStartNative:
    @pytest.mark.asyncio
    async def test_no_script(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss, "_native_start_script", lambda h: None)
        assert await sq._start_native(tmp_path) is False

    @pytest.mark.asyncio
    async def test_windows_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        script = tmp_path / "StartSonar.bat"
        script.write_text("x", encoding="utf-8")
        monkeypatch.setattr(ss, "_native_start_script", lambda h: script)
        monkeypatch.setattr(ss.sys, "platform", "win32")
        monkeypatch.setattr(ss, "_apply_windows_sonar_props", MagicMock())
        monkeypatch.setattr(ss, "_read_sonar_port", lambda h: 9100)
        monkeypatch.setattr(ss.asyncio, "create_subprocess_exec", AsyncMock(return_value=MagicMock()))
        monkeypatch.delenv("SONAR_HOST_URL", raising=False)
        sq._wait_ready = AsyncMock(return_value=True)
        assert await sq._start_native(tmp_path) is True

    @pytest.mark.asyncio
    async def test_windows_launch_oserror(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        script = tmp_path / "StartSonar.bat"
        script.write_text("x", encoding="utf-8")
        monkeypatch.setattr(ss, "_native_start_script", lambda h: script)
        monkeypatch.setattr(ss.sys, "platform", "win32")
        monkeypatch.setattr(ss, "_apply_windows_sonar_props", MagicMock())
        monkeypatch.setattr(ss, "_read_sonar_port", lambda h: 9100)
        monkeypatch.setattr(ss.asyncio, "create_subprocess_exec", AsyncMock(side_effect=OSError("denied")))
        assert await sq._start_native(tmp_path) is False

    @pytest.mark.asyncio
    async def test_linux_not_ready_prints_diagnostics(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        script = tmp_path / "sonar.sh"
        script.write_text("x", encoding="utf-8")
        monkeypatch.setattr(ss, "_native_start_script", lambda h: script)
        monkeypatch.setattr(ss.sys, "platform", "linux")
        monkeypatch.setattr(ss, "_read_sonar_port", lambda h: 9100)
        monkeypatch.setattr(ss.asyncio, "create_subprocess_exec", AsyncMock(return_value=_proc(0)))
        diag = MagicMock()
        monkeypatch.setattr(ss, "_print_startup_diagnostics", diag)
        monkeypatch.delenv("SONAR_HOST_URL", raising=False)
        sq._wait_ready = AsyncMock(return_value=False)
        assert await sq._start_native(tmp_path) is False
        diag.assert_called_once()


# --------------------------------------------------------------------------- #
# _ensure_server_running                                                      #
# --------------------------------------------------------------------------- #


class TestEnsureServerRunning:
    @pytest.mark.asyncio
    async def test_already_ready(self) -> None:
        sq = SonarQubeScanner()
        sq._is_ready = AsyncMock(return_value=True)
        assert await sq._ensure_server_running("https://h") is True

    @pytest.mark.asyncio
    async def test_native_start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        sq._is_ready = AsyncMock(return_value=False)
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: Path("/sq"))
        monkeypatch.setattr(ss.shutil, "which", lambda t: "/usr/bin/java")
        sq._start_native = AsyncMock(return_value=True)
        assert await sq._ensure_server_running("https://h") is True

    @pytest.mark.asyncio
    async def test_docker_start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        sq._is_ready = AsyncMock(return_value=False)
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(ss.shutil, "which", lambda t: None)
        monkeypatch.setattr(ss, "detect_container_runtime", lambda: "docker")
        sq._start_docker = AsyncMock(return_value=True)
        assert await sq._ensure_server_running("https://h") is True

    @pytest.mark.asyncio
    async def test_nothing_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        sq._is_ready = AsyncMock(return_value=False)
        monkeypatch.setattr(ss, "_find_native_sonarqube", lambda: None)
        monkeypatch.setattr(ss.shutil, "which", lambda t: None)
        monkeypatch.setattr(ss, "detect_container_runtime", lambda: None)
        assert await sq._ensure_server_running("https://h") is False


# --------------------------------------------------------------------------- #
# _run                                                                        #
# --------------------------------------------------------------------------- #


class TestRun:
    @pytest.mark.asyncio
    async def test_no_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.delenv("SONAR_TOKEN", raising=False)
        monkeypatch.setattr(ss, "_resolve_host_url", lambda: "https://h")
        assert await sq._run(ScanConfig(path="/p")) == []

    @pytest.mark.asyncio
    async def test_server_not_running(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        sq._ensure_server_running = AsyncMock(return_value=False)
        cfg = ScanConfig(path="/p", sonar_token="tok", sonar_host_url="https://h")
        assert await sq._run(cfg) == []

    @pytest.mark.asyncio
    async def test_scanner_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        sq._ensure_server_running = AsyncMock(return_value=True)
        sq._ensure_project = AsyncMock()
        sq._run_scanner = AsyncMock(return_value=False)
        cfg = ScanConfig(path="/p", sonar_token="tok", sonar_host_url="https://h")
        assert await sq._run(cfg) == []

    @pytest.mark.asyncio
    async def test_full_flow_filters_excluded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        sq._ensure_server_running = AsyncMock(return_value=True)
        sq._ensure_project = AsyncMock()
        sq._run_scanner = AsyncMock(return_value=True)
        sq._poll_task = AsyncMock()
        keep = make_finding(file="src/app.py")
        drop = make_finding(file="excluded.py")
        sq._fetch_issues = AsyncMock(return_value=[keep])
        sq._fetch_hotspots = AsyncMock(return_value=[drop])
        cfg = ScanConfig(path="/p", sonar_token="tok", sonar_host_url="https://h", exclude_files=["excluded.py"])
        out = await sq._run(cfg)
        assert out == [keep]


# --------------------------------------------------------------------------- #
# _run_scanner                                                                #
# --------------------------------------------------------------------------- #


class TestRunScanner:
    @pytest.mark.asyncio
    async def test_native_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss, "_find_sonar_scanner", lambda: "/sc/sonar-scanner")
        monkeypatch.setattr(ss.Path, "home", classmethod(lambda cls: tmp_path))
        monkeypatch.setattr(ss.asyncio, "create_subprocess_exec", AsyncMock(return_value=_proc(0)))
        assert await sq._run_scanner("https://h", "tok", "key", "/src") is True

    @pytest.mark.asyncio
    async def test_native_failure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss, "_find_sonar_scanner", lambda: "/sc/sonar-scanner")
        monkeypatch.setattr(ss.Path, "home", classmethod(lambda cls: tmp_path))
        monkeypatch.setattr(ss.asyncio, "create_subprocess_exec", AsyncMock(return_value=_proc(2, b"err")))
        assert await sq._run_scanner("https://h", "tok", "key", "/src") is False

    @pytest.mark.asyncio
    async def test_docker_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss, "_find_sonar_scanner", lambda: None)
        monkeypatch.setattr(ss, "detect_container_runtime", lambda: "docker")
        monkeypatch.setattr(ss.asyncio, "create_subprocess_exec", AsyncMock(return_value=_proc(0)))
        assert await sq._run_scanner("https://h", "tok", "key", "/src") is True

    @pytest.mark.asyncio
    async def test_no_scanner_no_runtime(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss, "_find_sonar_scanner", lambda: None)
        monkeypatch.setattr(ss, "detect_container_runtime", lambda: None)
        assert await sq._run_scanner("https://h", "tok", "key", "/src") is False


# --------------------------------------------------------------------------- #
# _is_ready / _wait_ready                                                     #
# --------------------------------------------------------------------------- #


class TestReadiness:
    @pytest.mark.asyncio
    async def test_is_ready_up(self) -> None:
        sq = SonarQubeScanner()
        resp = MagicMock()
        resp.json = MagicMock(return_value={"status": "UP"})
        with patch.object(ss.httpx, "AsyncClient", return_value=_client(get_resp=resp)):
            assert await sq._is_ready("https://h") is True

    @pytest.mark.asyncio
    async def test_is_ready_error(self) -> None:
        sq = SonarQubeScanner()
        with patch.object(ss.httpx, "AsyncClient", side_effect=httpx.HTTPError("x")):
            assert await sq._is_ready("https://h") is False

    @pytest.mark.asyncio
    async def test_wait_ready_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        sq._is_ready = AsyncMock(return_value=True)
        assert await sq._wait_ready("https://h") is True

    @pytest.mark.asyncio
    async def test_wait_ready_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        sq._is_ready = AsyncMock(return_value=False)
        monkeypatch.setattr(ss.asyncio, "sleep", AsyncMock())
        calls = {"n": 0}

        def _mono() -> float:
            calls["n"] += 1
            return 9999.0 if calls["n"] > 2 else float(calls["n"] - 1)

        monkeypatch.setattr(ss.time, "monotonic", _mono)
        assert await sq._wait_ready("https://h", max_wait=10) is False


# --------------------------------------------------------------------------- #
# _ensure_project / _poll_task                                                #
# --------------------------------------------------------------------------- #


class TestEnsureProjectPollTask:
    @pytest.mark.asyncio
    async def test_ensure_project_swallows_error(self) -> None:
        sq = SonarQubeScanner()
        with patch.object(ss.httpx, "AsyncClient", side_effect=httpx.HTTPError("x")):
            await sq._ensure_project("https://h", "tok", "key", "name")  # no raise

    @pytest.mark.asyncio
    async def test_ensure_project_success(self) -> None:
        sq = SonarQubeScanner()
        client = _client(post_resp=MagicMock())
        with patch.object(ss.httpx, "AsyncClient", return_value=client):
            await sq._ensure_project("https://h", "tok", "key", "name")
        client.post.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_poll_task_done(self) -> None:
        sq = SonarQubeScanner()
        resp = MagicMock()
        resp.json = MagicMock(return_value={"tasks": []})
        with patch.object(ss.httpx, "AsyncClient", return_value=_client(get_resp=resp)):
            await sq._poll_task("https://h", "tok", "key")  # returns immediately

    @pytest.mark.asyncio
    async def test_poll_task_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        resp = MagicMock()
        resp.json = MagicMock(return_value={"tasks": [{"id": "1"}]})
        monkeypatch.setattr(ss.asyncio, "sleep", AsyncMock())
        calls = {"n": 0}

        def _mono() -> float:
            calls["n"] += 1
            return 9999.0 if calls["n"] > 2 else float(calls["n"] - 1)

        monkeypatch.setattr(ss.time, "monotonic", _mono)
        with patch.object(ss.httpx, "AsyncClient", return_value=_client(get_resp=resp)):
            await sq._poll_task("https://h", "tok", "key", max_wait=10)

    @pytest.mark.asyncio
    async def test_poll_task_error_swallowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss.asyncio, "sleep", AsyncMock())
        calls = {"n": 0}

        def _mono() -> float:
            calls["n"] += 1
            return 9999.0 if calls["n"] > 2 else float(calls["n"] - 1)

        monkeypatch.setattr(ss.time, "monotonic", _mono)
        client = _client(get_side=[ValueError("bad json")])
        with patch.object(ss.httpx, "AsyncClient", return_value=client):
            await sq._poll_task("https://h", "tok", "key", max_wait=10)


# --------------------------------------------------------------------------- #
# _source_line                                                                #
# --------------------------------------------------------------------------- #


class TestSourceLine:
    def test_reads_line(self, tmp_path: Path) -> None:
        f = tmp_path / "a.py"
        f.write_text("line1\n  secret = 1  \nline3\n", encoding="utf-8")
        assert SonarQubeScanner._source_line(str(tmp_path), "a.py", 2) == "secret = 1"

    def test_out_of_range(self, tmp_path: Path) -> None:
        f = tmp_path / "a.py"
        f.write_text("line1\n", encoding="utf-8")
        assert SonarQubeScanner._source_line(str(tmp_path), "a.py", 99) == "****"

    def test_missing_file(self, tmp_path: Path) -> None:
        assert SonarQubeScanner._source_line(str(tmp_path), "nope.py", 1) == "****"


# --------------------------------------------------------------------------- #
# _fetch_issues                                                               #
# --------------------------------------------------------------------------- #


class TestFetchIssues:
    @pytest.mark.asyncio
    async def test_single_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(
            return_value={"issues": [{"rule": "python:S1", "component": "key:a.py"}], "paging": {"total": 1}}
        )
        monkeypatch.setattr(sq, "_normalise_issue", lambda *a, **k: "F")
        with patch.object(ss.httpx, "AsyncClient", return_value=_client(get_resp=resp)):
            out = await sq._fetch_issues("https://h", "tok", "key", "/src")
        assert out == ["F"]

    @pytest.mark.asyncio
    async def test_error_breaks(self) -> None:
        sq = SonarQubeScanner()
        client = _client(get_side=[httpx.HTTPError("x")])
        with patch.object(ss.httpx, "AsyncClient", return_value=client):
            assert await sq._fetch_issues("https://h", "tok", "key", "/src") == []

    @pytest.mark.asyncio
    async def test_multi_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        page1 = MagicMock()
        page1.raise_for_status = MagicMock()
        page1.json = MagicMock(return_value={"issues": [{"rule": "a"}], "paging": {"total": 600}})
        page2 = MagicMock()
        page2.raise_for_status = MagicMock()
        page2.json = MagicMock(return_value={"issues": [{"rule": "b"}], "paging": {"total": 600}})
        monkeypatch.setattr(sq, "_normalise_issue", lambda *a, **k: "F")
        with patch.object(ss.httpx, "AsyncClient", return_value=_client(get_side=[page1, page2])):
            out = await sq._fetch_issues("https://h", "tok", "key", "/src")
        assert out == ["F", "F"]


# --------------------------------------------------------------------------- #
# _fetch_hotspots                                                             #
# --------------------------------------------------------------------------- #


class TestFetchHotspots:
    @pytest.mark.asyncio
    async def test_single_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value={"hotspots": [{"ruleKey": "r"}], "paging": {"total": 1}})
        monkeypatch.setattr(sq, "_normalise_hotspot", lambda *a, **k: "H")
        with patch.object(ss.httpx, "AsyncClient", return_value=_client(get_resp=resp)):
            out = await sq._fetch_hotspots("https://h", "tok", "key", "/src")
        assert out == ["H"]

    @pytest.mark.asyncio
    async def test_error_breaks(self) -> None:
        sq = SonarQubeScanner()
        client = _client(get_side=[httpx.HTTPError("x")])
        with patch.object(ss.httpx, "AsyncClient", return_value=client):
            assert await sq._fetch_hotspots("https://h", "tok", "key", "/src") == []

    @pytest.mark.asyncio
    async def test_multi_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        page1 = MagicMock()
        page1.raise_for_status = MagicMock()
        page1.json = MagicMock(return_value={"hotspots": [{"ruleKey": "r"}], "paging": {"total": 600}})
        page2 = MagicMock()
        page2.raise_for_status = MagicMock()
        page2.json = MagicMock(return_value={"hotspots": [{"ruleKey": "r"}], "paging": {"total": 600}})
        monkeypatch.setattr(sq, "_normalise_hotspot", lambda *a, **k: "H")
        with patch.object(ss.httpx, "AsyncClient", return_value=_client(get_side=[page1, page2])):
            out = await sq._fetch_hotspots("https://h", "tok", "key", "/src")
        assert out == ["H", "H"]


# --------------------------------------------------------------------------- #
# _normalise_issue                                                            #
# --------------------------------------------------------------------------- #


class TestNormaliseIssue:
    def test_drops_non_security_rule(self) -> None:
        sq = SonarQubeScanner()
        assert sq._normalise_issue({"rule": "css:S1"}, "key", "/src") is None

    def test_drops_generic_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss._ENGINE, "resolve", lambda rid: ("generic_secret", None))
        assert sq._normalise_issue({"rule": "python:S1"}, "key", "/src") is None

    def test_maps_real_category(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss._ENGINE, "resolve", lambda rid: ("pii_ssn", _rule("critical")))
        issue = {
            "rule": "python:S1",
            "component": "key:src/app.py",
            "textRange": {"startLine": 12},
            "message": "found",
            "severity": "BLOCKER",
        }
        f = sq._normalise_issue(issue, "key", "/src", show_secrets=False)
        assert f is not None
        assert f.category == "pii_ssn"
        assert f.severity == "critical"
        assert f.file == "src/app.py"
        assert f.line == 12
        assert f.match == "****"


# --------------------------------------------------------------------------- #
# _normalise_hotspot                                                          #
# --------------------------------------------------------------------------- #


class TestNormaliseHotspot:
    def test_security_category_mapping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss._ENGINE, "lookup", lambda cat: _rule("high"))
        hs = {
            "component": "key:src/a.py",
            "textRange": {"startLine": 5},
            "ruleKey": "r1",
            "message": "creds in code",
            "vulnerabilityProbability": "HIGH",
            "securityCategory": "credentials",
        }
        f = sq._normalise_hotspot(hs, "key", "/src", show_secrets=False)
        assert f is not None
        assert f.category == "hardcoded_password"
        assert f.severity == "high"

    def test_resolve_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss._ENGINE, "resolve", lambda rid: ("encryption_key", _rule("medium")))
        hs = {
            "component": "key:src/a.py",
            "textRange": {"startLine": 5},
            "ruleKey": "r1",
            "message": "",
            "vulnerabilityProbability": "LOW",
            "securityCategory": "",
        }
        f = sq._normalise_hotspot(hs, "key", "/src", show_secrets=False)
        assert f is not None
        assert f.category == "encryption_key"

    def test_drops_generic_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sq = SonarQubeScanner()
        monkeypatch.setattr(ss._ENGINE, "resolve", lambda rid: ("generic_secret", None))
        hs = {
            "component": "key:src/a.py",
            "ruleKey": "r1",
            "vulnerabilityProbability": "MEDIUM",
            "securityCategory": "unknown-cat",
        }
        assert sq._normalise_hotspot(hs, "key", "/src", show_secrets=False) is None
