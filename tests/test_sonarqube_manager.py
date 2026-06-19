"""Tests for src/scanners/sonarqube_manager.py."""

from __future__ import annotations

import io
import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from scanners import sonarqube_manager as sm


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _async_client(get_resp: MagicMock) -> AsyncMock:
    client = AsyncMock()
    client.get = AsyncMock(return_value=get_resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


def _zip_bytes(top_dir: str, files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(f"{top_dir}/{name}", data)
    return buf.getvalue()


def _zip_multi_top(dirs: dict[str, dict[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for top, files in dirs.items():
            for name, data in files.items():
                zf.writestr(f"{top}/{name}", data)
    return buf.getvalue()


def _stream_client(payload: bytes, headers: dict | None = None) -> AsyncMock:
    async def _aiter(chunk_size: int = 0):  # noqa: ANN202
        yield payload

    stream_resp = MagicMock()
    stream_resp.raise_for_status = MagicMock()
    stream_resp.headers = headers or {}
    stream_resp.aiter_bytes = _aiter
    stream_cm = AsyncMock()
    stream_cm.__aenter__ = AsyncMock(return_value=stream_resp)
    stream_cm.__aexit__ = AsyncMock(return_value=False)

    client = AsyncMock()
    client.stream = MagicMock(return_value=stream_cm)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


# --------------------------------------------------------------------------- #
# Platform helpers                                                            #
# --------------------------------------------------------------------------- #


class TestPlatform:
    def test_system(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.platform, "system", lambda: "Linux")
        assert sm._system() == "linux"

    @pytest.mark.parametrize("raw,exp", [("AMD64", "x64"), ("aarch64", "arm64"), ("ppc", "ppc")])
    def test_machine(self, monkeypatch: pytest.MonkeyPatch, raw: str, exp: str) -> None:
        monkeypatch.setattr(sm.platform, "machine", lambda: raw)
        assert sm._machine() == exp


# --------------------------------------------------------------------------- #
# Metadata                                                                     #
# --------------------------------------------------------------------------- #


class TestMeta:
    def test_roundtrip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "META_FILE", tmp_path / "m.json")
        sm._save_meta({"x": 1})
        assert sm._load_meta() == {"x": 1}

    def test_load_missing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "META_FILE", tmp_path / "none.json")
        assert sm._load_meta() == {}

    def test_load_corrupt(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        f = tmp_path / "m.json"
        f.write_text("broken", encoding="utf-8")
        monkeypatch.setattr(sm, "META_FILE", f)
        assert sm._load_meta() == {}


# --------------------------------------------------------------------------- #
# _persist_unix_env_var / persist_env_var                                      #
# --------------------------------------------------------------------------- #


class TestPersistEnv:
    def test_unix_appends_when_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        bashrc = tmp_path / ".bashrc"
        bashrc.write_text("# existing\n", encoding="utf-8")
        monkeypatch.setattr(sm.Path, "home", classmethod(lambda cls: tmp_path))
        ok = sm._persist_unix_env_var("FOO", "bar")
        assert ok is True
        assert 'export FOO="bar"' in bashrc.read_text(encoding="utf-8")

    def test_unix_replaces_existing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        zshrc = tmp_path / ".zshrc"
        zshrc.write_text('export FOO="old"\n', encoding="utf-8")
        monkeypatch.setattr(sm.Path, "home", classmethod(lambda cls: tmp_path))
        ok = sm._persist_unix_env_var("FOO", "new")
        assert ok is True
        content = zshrc.read_text(encoding="utf-8")
        assert 'export FOO="new"' in content
        assert "old" not in content

    def test_unix_no_files_returns_false(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.Path, "home", classmethod(lambda cls: tmp_path))
        assert sm._persist_unix_env_var("FOO", "bar") is False

    def test_persist_env_unix_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.sys, "platform", "linux")
        monkeypatch.setattr(sm, "_persist_unix_env_var", lambda n, v: True)
        assert sm.persist_env_var("FOO", "bar") is True
        assert sm.os.environ["FOO"] == "bar"

    def test_persist_env_windows_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.sys, "platform", "win32")
        fake_winreg = MagicMock()
        fake_winreg.HKEY_CURRENT_USER = 0
        fake_winreg.KEY_SET_VALUE = 0
        fake_winreg.REG_SZ = 1
        monkeypatch.setitem(sys.modules, "winreg", fake_winreg)
        # ctypes.windll may not exist; force the broadcast to be swallowed
        fake_ctypes = MagicMock()
        fake_ctypes.windll.user32.SendMessageTimeoutW = MagicMock()
        monkeypatch.setitem(sys.modules, "ctypes", fake_ctypes)
        assert sm.persist_env_var("MYVAR", "val") is True
        fake_winreg.SetValueEx.assert_called_once()

    def test_persist_env_windows_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.sys, "platform", "win32")
        fake_winreg = MagicMock()
        fake_winreg.OpenKey.side_effect = OSError("denied")
        monkeypatch.setitem(sys.modules, "winreg", fake_winreg)
        assert sm.persist_env_var("MYVAR", "val") is False


# --------------------------------------------------------------------------- #
# check_java                                                                   #
# --------------------------------------------------------------------------- #


class TestCheckJava:
    def test_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.shutil, "which", lambda t: None)
        ok, msg = sm.check_java()
        assert ok is False
        assert "Java not found" in msg

    def test_modern_version_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.shutil, "which", lambda t: "/usr/bin/java")
        proc = MagicMock()
        proc.stderr = 'openjdk version "21.0.1" 2023'
        proc.stdout = ""
        monkeypatch.setattr(sm.subprocess, "run", lambda *a, **k: proc)
        ok, msg = sm.check_java()
        assert ok is True
        assert "Java 21" in msg

    def test_old_version_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.shutil, "which", lambda t: "/usr/bin/java")
        proc = MagicMock()
        proc.stderr = 'java version "11.0.2"'
        proc.stdout = ""
        monkeypatch.setattr(sm.subprocess, "run", lambda *a, **k: proc)
        ok, msg = sm.check_java()
        assert ok is False
        assert "requires Java 17" in msg

    def test_legacy_1_8_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.shutil, "which", lambda t: "/usr/bin/java")
        proc = MagicMock()
        proc.stderr = 'java version "1.8.0_292"'
        proc.stdout = ""
        monkeypatch.setattr(sm.subprocess, "run", lambda *a, **k: proc)
        ok, msg = sm.check_java()
        assert ok is False
        assert "Java 8" in msg

    def test_subprocess_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.shutil, "which", lambda t: "/usr/bin/java")

        def _boom(*a, **k):  # noqa: ANN202
            raise subprocess.SubprocessError("fail")

        monkeypatch.setattr(sm.subprocess, "run", _boom)
        ok, msg = sm.check_java()
        assert ok is False
        assert "Could not determine" in msg

    def test_unparseable_version_returns_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.shutil, "which", lambda t: "/usr/bin/java")
        proc = MagicMock()
        proc.stderr = "no version string here"
        proc.stdout = ""
        monkeypatch.setattr(sm.subprocess, "run", lambda *a, **k: proc)
        ok, msg = sm.check_java()
        assert ok is True
        assert "Java found" in msg


# --------------------------------------------------------------------------- #
# GitHub release helpers                                                      #
# --------------------------------------------------------------------------- #


class TestReleaseHelpers:
    @pytest.mark.asyncio
    async def test_fetch_latest_success(self) -> None:
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value={"tag_name": "v1"})
        client = _async_client(resp)
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            out = await sm._fetch_latest_release("o", "r")
        assert out == {"tag_name": "v1"}

    @pytest.mark.asyncio
    async def test_fetch_latest_error(self) -> None:
        with patch.object(sm.httpx, "AsyncClient", side_effect=httpx.HTTPError("x")):
            assert await sm._fetch_latest_release("o", "r") is None

    @pytest.mark.asyncio
    async def test_fetch_sq_version_strips_prefix(self) -> None:
        with patch.object(sm, "_fetch_latest_release", AsyncMock(return_value={"tag_name": "sonarqube-10.5.1.90531"})):
            assert await sm._fetch_sq_version() == "10.5.1.90531"

    @pytest.mark.asyncio
    async def test_fetch_sq_version_none_release(self) -> None:
        with patch.object(sm, "_fetch_latest_release", AsyncMock(return_value=None)):
            assert await sm._fetch_sq_version() is None

    @pytest.mark.asyncio
    async def test_fetch_sq_version_empty_tag(self) -> None:
        with patch.object(sm, "_fetch_latest_release", AsyncMock(return_value={"tag_name": ""})):
            assert await sm._fetch_sq_version() is None


# --------------------------------------------------------------------------- #
# _download_and_extract_zip                                                   #
# --------------------------------------------------------------------------- #


class TestDownloadExtract:
    @pytest.mark.asyncio
    async def test_success_single_top_dir(self, tmp_path: Path) -> None:
        payload = _zip_bytes("pkg-1.0", {"bin/run": b"x", "README": b"y"})
        dest = tmp_path / "installed"
        called = {}

        def _cb(done: int, total: int) -> None:
            called["done"] = done

        client = _stream_client(payload, headers={"content-length": str(len(payload))})
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            out = await sm._download_and_extract_zip("http://dl", dest, "pkg", progress_callback=_cb)
        assert out == dest
        assert (dest / "bin" / "run").read_bytes() == b"x"
        assert called["done"] == len(payload)

    @pytest.mark.asyncio
    async def test_replaces_existing_dest(self, tmp_path: Path) -> None:
        dest = tmp_path / "installed"
        dest.mkdir()
        (dest / "stale.txt").write_text("old", encoding="utf-8")
        payload = _zip_bytes("pkg-2.0", {"new.txt": b"new"})
        client = _stream_client(payload)
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            out = await sm._download_and_extract_zip("http://dl", dest, "pkg")
        assert out == dest
        assert (dest / "new.txt").exists()
        assert not (dest / "stale.txt").exists()

    @pytest.mark.asyncio
    async def test_download_failure_returns_none(self, tmp_path: Path) -> None:
        with patch.object(sm.httpx, "AsyncClient", side_effect=httpx.HTTPError("net")):
            out = await sm._download_and_extract_zip("http://dl", tmp_path / "x", "pkg")
        assert out is None

    @pytest.mark.asyncio
    async def test_multiple_top_dirs(self, tmp_path: Path) -> None:
        payload = _zip_multi_top({"a": {"f1": b"1"}, "b": {"f2": b"2"}})
        dest = tmp_path / "installed"
        client = _stream_client(payload)
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            out = await sm._download_and_extract_zip("http://dl", dest, "pkg")
        assert out == dest
        assert (dest / "a" / "f1").exists()
        assert (dest / "b" / "f2").exists()


# --------------------------------------------------------------------------- #
# patch_sonar_port                                                            #
# --------------------------------------------------------------------------- #


class TestPatchSonarPort:
    def test_missing_props_noop(self, tmp_path: Path) -> None:
        sm.patch_sonar_port(tmp_path)  # no conf/sonar.properties — should not raise

    def test_replaces_commented_line(self, tmp_path: Path) -> None:
        conf = tmp_path / "conf"
        conf.mkdir()
        (conf / "sonar.properties").write_text("#sonar.web.port=9000\nother=1\n", encoding="utf-8")
        sm.patch_sonar_port(tmp_path, 9100)
        text = (conf / "sonar.properties").read_text(encoding="utf-8")
        assert "sonar.web.port=9100" in text
        assert "9000" not in text

    def test_appends_when_absent(self, tmp_path: Path) -> None:
        conf = tmp_path / "conf"
        conf.mkdir()
        (conf / "sonar.properties").write_text("other=1\n", encoding="utf-8")
        sm.patch_sonar_port(tmp_path, 9100)
        assert "sonar.web.port=9100" in (conf / "sonar.properties").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# sonar-scanner install helpers                                               #
# --------------------------------------------------------------------------- #


class TestScannerInstall:
    def test_scanner_exe_path_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "_system", lambda: "linux")
        monkeypatch.setattr(sm, "_SCANNER_DIR", tmp_path)
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin" / "sonar-scanner").write_text("x", encoding="utf-8")
        assert sm._scanner_exe_path() == tmp_path / "bin" / "sonar-scanner"
        assert sm.sonar_scanner_installed() is True

    def test_scanner_exe_path_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "_system", lambda: "linux")
        monkeypatch.setattr(sm, "_SCANNER_DIR", tmp_path)
        assert sm._scanner_exe_path() is None
        assert sm.sonar_scanner_installed() is False

    @pytest.mark.asyncio
    async def test_ensure_scanner_already_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonar_scanner_installed", lambda: True)
        out = await sm.ensure_sonar_scanner()
        assert out == sm._SCANNER_DIR

    @pytest.mark.asyncio
    async def test_ensure_scanner_no_release(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonar_scanner_installed", lambda: False)
        monkeypatch.setattr(sm, "_fetch_latest_release", AsyncMock(return_value=None))
        assert await sm.ensure_sonar_scanner() is None

    @pytest.mark.asyncio
    async def test_ensure_scanner_no_version(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonar_scanner_installed", lambda: False)
        monkeypatch.setattr(sm, "_fetch_latest_release", AsyncMock(return_value={"tag_name": ""}))
        assert await sm.ensure_sonar_scanner() is None

    @pytest.mark.asyncio
    async def test_ensure_scanner_no_asset_for_platform(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonar_scanner_installed", lambda: False)
        monkeypatch.setattr(sm, "_fetch_latest_release", AsyncMock(return_value={"tag_name": "5.0", "assets": []}))
        monkeypatch.setattr(sm, "_system", lambda: "plan9")
        monkeypatch.setattr(sm, "_machine", lambda: "x64")
        assert await sm.ensure_sonar_scanner() is None

    @pytest.mark.asyncio
    async def test_ensure_scanner_download_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonar_scanner_installed", lambda: False)
        monkeypatch.setattr(sm, "_fetch_latest_release", AsyncMock(return_value={"tag_name": "5.0", "assets": []}))
        monkeypatch.setattr(sm, "_system", lambda: "linux")
        monkeypatch.setattr(sm, "_machine", lambda: "x64")
        monkeypatch.setattr(sm, "_download_and_extract_zip", AsyncMock(return_value=None))
        assert await sm.ensure_sonar_scanner() is None

    @pytest.mark.asyncio
    async def test_ensure_scanner_success_with_asset_url(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonar_scanner_installed", lambda: False)
        monkeypatch.setattr(sm, "_SCANNER_DIR", tmp_path)
        monkeypatch.setattr(sm, "META_FILE", tmp_path / "meta.json")
        monkeypatch.setattr(sm, "_system", lambda: "windows")
        monkeypatch.setattr(sm, "_machine", lambda: "x64")
        release = {
            "tag_name": "5.0",
            "assets": [{"name": "sonar-scanner-cli-5.0-windows-x64.zip", "browser_download_url": "http://asset"}],
        }
        monkeypatch.setattr(sm, "_fetch_latest_release", AsyncMock(return_value=release))
        captured = {}

        async def _dl(url, dest, label="", progress_callback=None):  # noqa: ANN001, ANN202
            captured["url"] = url
            return dest

        monkeypatch.setattr(sm, "_download_and_extract_zip", _dl)
        out = await sm.ensure_sonar_scanner()
        assert out == tmp_path
        assert captured["url"] == "http://asset"
        assert sm._load_meta()["sonar-scanner-cli"] == {"version": "5.0"}

    @pytest.mark.asyncio
    async def test_ensure_scanner_fallback_url(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonar_scanner_installed", lambda: False)
        monkeypatch.setattr(sm, "_SCANNER_DIR", tmp_path)
        monkeypatch.setattr(sm, "META_FILE", tmp_path / "meta.json")
        monkeypatch.setattr(sm, "_system", lambda: "windows")
        monkeypatch.setattr(sm, "_machine", lambda: "x64")
        monkeypatch.setattr(
            sm, "_fetch_latest_release", AsyncMock(return_value={"tag_name": "5.0", "assets": []})
        )
        captured = {}

        async def _dl(url, dest, label="", progress_callback=None):  # noqa: ANN001, ANN202
            captured["url"] = url
            return dest

        monkeypatch.setattr(sm, "_download_and_extract_zip", _dl)
        out = await sm.ensure_sonar_scanner()
        assert out == tmp_path
        assert "releases/download/5.0/sonar-scanner-cli-5.0-windows-x64.zip" in captured["url"]

    @pytest.mark.asyncio
    async def test_ensure_scanner_unix_chmods_exe(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonar_scanner_installed", lambda: False)
        monkeypatch.setattr(sm, "_SCANNER_DIR", tmp_path)
        monkeypatch.setattr(sm, "META_FILE", tmp_path / "meta.json")
        monkeypatch.setattr(sm, "_system", lambda: "linux")
        monkeypatch.setattr(sm, "_machine", lambda: "x64")
        monkeypatch.setattr(
            sm, "_fetch_latest_release", AsyncMock(return_value={"tag_name": "5.0", "assets": []})
        )

        async def _dl(url, dest, label="", progress_callback=None):  # noqa: ANN001, ANN202
            exe = dest / "bin" / "sonar-scanner"
            exe.parent.mkdir(parents=True, exist_ok=True)
            exe.write_text("#!/bin/sh", encoding="utf-8")
            return dest

        monkeypatch.setattr(sm, "_download_and_extract_zip", _dl)
        out = await sm.ensure_sonar_scanner()
        assert out == tmp_path
        assert (tmp_path / "bin" / "sonar-scanner").exists()


# --------------------------------------------------------------------------- #
# SonarQube install helpers                                                   #
# --------------------------------------------------------------------------- #


class TestSonarqubeInstall:
    def test_sonarqube_installed_true(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "_SQ_DIR", tmp_path)
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "sonar.properties").write_text("x", encoding="utf-8")
        assert sm.sonarqube_installed() is True

    def test_sonarqube_installed_false(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "_SQ_DIR", tmp_path)
        assert sm.sonarqube_installed() is False

    @pytest.mark.asyncio
    async def test_ensure_sq_already_installed_repatches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonarqube_installed", lambda: True)
        patched = MagicMock()
        monkeypatch.setattr(sm, "patch_sonar_port", patched)
        out = await sm.ensure_sonarqube()
        assert out == sm._SQ_DIR
        patched.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_sq_no_version(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonarqube_installed", lambda: False)
        monkeypatch.setattr(sm, "_fetch_sq_version", AsyncMock(return_value=None))
        assert await sm.ensure_sonarqube() is None

    @pytest.mark.asyncio
    async def test_ensure_sq_download_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonarqube_installed", lambda: False)
        monkeypatch.setattr(sm, "_fetch_sq_version", AsyncMock(return_value="10.5"))
        monkeypatch.setattr(sm, "_download_and_extract_zip", AsyncMock(return_value=None))
        assert await sm.ensure_sonarqube() is None

    @pytest.mark.asyncio
    async def test_ensure_sq_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonarqube_installed", lambda: False)
        monkeypatch.setattr(sm, "_SQ_DIR", tmp_path)
        monkeypatch.setattr(sm, "META_FILE", tmp_path / "meta.json")
        monkeypatch.setattr(sm, "_system", lambda: "windows")
        monkeypatch.setattr(sm, "_fetch_sq_version", AsyncMock(return_value="10.5"))
        monkeypatch.setattr(sm, "_download_and_extract_zip", AsyncMock(return_value=tmp_path))
        monkeypatch.setattr(sm, "patch_sonar_port", MagicMock())
        out = await sm.ensure_sonarqube()
        assert out == tmp_path
        assert sm._load_meta()["sonarqube"] == {"version": "10.5", "port": sm.SONAR_PORT}

    @pytest.mark.asyncio
    async def test_ensure_sq_unix_chmods_scripts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "sonarqube_installed", lambda: False)
        monkeypatch.setattr(sm, "_SQ_DIR", tmp_path)
        monkeypatch.setattr(sm, "META_FILE", tmp_path / "meta.json")
        monkeypatch.setattr(sm, "_system", lambda: "linux")
        monkeypatch.setattr(sm, "_fetch_sq_version", AsyncMock(return_value="10.5"))

        async def _dl(url, dest, label="", progress_callback=None):  # noqa: ANN001, ANN202
            script = dest / "bin" / "linux-x86-64" / "sonar.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text("#!/bin/sh", encoding="utf-8")
            return dest

        monkeypatch.setattr(sm, "_download_and_extract_zip", _dl)
        monkeypatch.setattr(sm, "patch_sonar_port", MagicMock())
        out = await sm.ensure_sonarqube()
        assert out == tmp_path
        assert (tmp_path / "bin" / "linux-x86-64" / "sonar.sh").exists()


# --------------------------------------------------------------------------- #
# _start_script                                                               #
# --------------------------------------------------------------------------- #


class TestStartScript:
    def test_windows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.platform, "system", lambda: "Windows")
        monkeypatch.setattr(sm.platform, "machine", lambda: "AMD64")
        s = tmp_path / "bin" / "windows-x86-64" / "StartSonar.bat"
        s.parent.mkdir(parents=True)
        s.write_text("x", encoding="utf-8")
        assert sm._start_script(tmp_path) == s

    def test_linux_arm(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.platform, "system", lambda: "Linux")
        monkeypatch.setattr(sm.platform, "machine", lambda: "aarch64")
        s = tmp_path / "bin" / "linux-aarch64" / "sonar.sh"
        s.parent.mkdir(parents=True)
        s.write_text("x", encoding="utf-8")
        assert sm._start_script(tmp_path) == s

    def test_macos_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(sm.platform, "machine", lambda: "x86_64")
        s = tmp_path / "bin" / "macosx-universal-64" / "sonar.sh"
        s.parent.mkdir(parents=True)
        s.write_text("x", encoding="utf-8")
        assert sm._start_script(tmp_path) == s

    def test_missing_returns_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm.platform, "system", lambda: "Linux")
        monkeypatch.setattr(sm.platform, "machine", lambda: "x86_64")
        assert sm._start_script(tmp_path) is None


# --------------------------------------------------------------------------- #
# start_and_wait                                                              #
# --------------------------------------------------------------------------- #


class TestStartAndWait:
    @pytest.mark.asyncio
    async def test_no_start_script(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "_start_script", lambda h: None)
        assert await sm.start_and_wait(tmp_path) is False

    @pytest.mark.asyncio
    async def test_ready_immediately_windows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "_start_script", lambda h: tmp_path / "s.bat")
        monkeypatch.setattr(sm.platform, "system", lambda: "Windows")
        monkeypatch.setattr(sm.asyncio, "create_subprocess_exec", AsyncMock(return_value=MagicMock()))
        resp = MagicMock()
        resp.json = MagicMock(return_value={"status": "UP"})
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        ticks = []
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            ok = await sm.start_and_wait(tmp_path, tick_callback=lambda e, t: ticks.append(e))
        assert ok is True
        assert ticks  # tick_callback fired at least once

    @pytest.mark.asyncio
    async def test_timeout_returns_false(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sm, "_start_script", lambda h: tmp_path / "s")
        monkeypatch.setattr(sm.platform, "system", lambda: "Linux")
        monkeypatch.setattr(sm.asyncio, "create_subprocess_exec", AsyncMock(return_value=MagicMock()))
        monkeypatch.setattr(sm.asyncio, "sleep", AsyncMock())
        # time advances past max_wait after the first failed poll
        calls = {"n": 0}

        def _mono() -> float:
            calls["n"] += 1
            return 0.0 if calls["n"] <= 2 else 999.0

        monkeypatch.setattr(sm.time, "monotonic", _mono)
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.HTTPError("down"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            ok = await sm.start_and_wait(tmp_path, max_wait=180)
        assert ok is False


# --------------------------------------------------------------------------- #
# ensure_admin_token                                                          #
# --------------------------------------------------------------------------- #


class TestEnsureAdminToken:
    def _client_with(self, get_resp: MagicMock, post_resps: list[MagicMock]) -> AsyncMock:
        client = AsyncMock()
        client.get = AsyncMock(return_value=get_resp)
        client.post = AsyncMock(side_effect=post_resps)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        return client

    @pytest.mark.asyncio
    async def test_unreachable_api(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.HTTPError("down"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            token, reason = await sm.ensure_admin_token("http://h")
        assert token is None
        assert "Could not reach" in reason

    @pytest.mark.asyncio
    async def test_credentials_rejected(self) -> None:
        get = MagicMock()
        get.status_code = 401
        get.json = MagicMock(return_value={})
        client = self._client_with(get, [])
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            token, reason = await sm.ensure_admin_token("http://h")
        assert token is None
        assert "rejected" in reason

    @pytest.mark.asyncio
    async def test_unexpected_validate(self) -> None:
        get = MagicMock()
        get.status_code = 500
        get.json = MagicMock(return_value={"valid": False})
        client = self._client_with(get, [])
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            token, reason = await sm.ensure_admin_token("http://h")
        assert token is None
        assert "unexpected response" in reason

    @pytest.mark.asyncio
    async def test_token_success(self) -> None:
        get = MagicMock()
        get.status_code = 200
        get.json = MagicMock(return_value={"valid": True})
        revoke = MagicMock()
        gen = MagicMock()
        gen.status_code = 200
        gen.json = MagicMock(return_value={"token": "squ_abc"})
        client = self._client_with(get, [revoke, gen])
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            token, reason = await sm.ensure_admin_token("http://h")
        assert token == "squ_abc"
        assert reason == "ok"

    @pytest.mark.asyncio
    async def test_token_missing_field(self) -> None:
        get = MagicMock()
        get.status_code = 200
        get.json = MagicMock(return_value={"valid": True})
        revoke = MagicMock()
        gen = MagicMock()
        gen.status_code = 201
        gen.json = MagicMock(return_value={})
        gen.text = "no token here"
        client = self._client_with(get, [revoke, gen])
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            token, reason = await sm.ensure_admin_token("http://h")
        assert token is None
        assert "Token field missing" in reason

    @pytest.mark.asyncio
    async def test_password_change_required(self) -> None:
        get = MagicMock()
        get.status_code = 200
        get.json = MagicMock(return_value={"valid": True})
        revoke = MagicMock()
        gen = MagicMock()
        gen.status_code = 400
        gen.text = "You must change your password"
        client = self._client_with(get, [revoke, gen])
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            token, reason = await sm.ensure_admin_token("http://h")
        assert token is None
        assert "change the admin password" in reason

    @pytest.mark.asyncio
    async def test_generic_token_failure(self) -> None:
        get = MagicMock()
        get.status_code = 200
        get.json = MagicMock(return_value={"valid": True})
        revoke = MagicMock()
        gen = MagicMock()
        gen.status_code = 403
        gen.text = "forbidden"
        client = self._client_with(get, [revoke, gen])
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            token, reason = await sm.ensure_admin_token("http://h")
        assert token is None
        assert "HTTP 403" in reason

    @pytest.mark.asyncio
    async def test_generate_exception(self) -> None:
        get = MagicMock()
        get.status_code = 200
        get.json = MagicMock(return_value={"valid": True})
        revoke = MagicMock()
        client = AsyncMock()
        client.get = AsyncMock(return_value=get)
        client.post = AsyncMock(side_effect=[revoke, httpx.HTTPError("boom")])
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            token, reason = await sm.ensure_admin_token("http://h")
        assert token is None
        assert "exception" in reason

    @pytest.mark.asyncio
    async def test_revoke_error_swallowed(self) -> None:
        get = MagicMock()
        get.status_code = 200
        get.json = MagicMock(return_value={"valid": True})
        gen = MagicMock()
        gen.status_code = 200
        gen.json = MagicMock(return_value={"token": "squ_xyz"})
        client = AsyncMock()
        client.get = AsyncMock(return_value=get)
        # revoke raises (token not yet present) but generate succeeds
        client.post = AsyncMock(side_effect=[httpx.HTTPError("404"), gen])
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with patch.object(sm.httpx, "AsyncClient", return_value=client):
            token, reason = await sm.ensure_admin_token("http://h")
        assert token == "squ_xyz"
        assert reason == "ok"
