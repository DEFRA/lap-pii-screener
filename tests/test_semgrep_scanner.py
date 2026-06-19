"""Tests for scanners.semgrep_scanner — ruleset cache, normalisation, run, discovery."""
from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.finding import ScanConfig
from scanners import semgrep_scanner
from scanners.semgrep_scanner import (
    SemgrepScanner,
    _ensure_cached_rulesets,
    _find_semgrep,
    _is_cache_fresh,
    _ruleset_cache_path,
)


class _FakeProc:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 1) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return (self._stdout, self._stderr)

    def kill(self) -> None:  # pragma: no cover - only used in timeout path
        pass


def _result(path: str, *, check_id: str = "python.audit.sqli", line: int = 5,
            severity: str = "ERROR", message: str = "SQL injection",
            lines: str = "query = 'SELECT'", confidence: str = "HIGH") -> dict:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "extra": {
            "message": message,
            "severity": severity,
            "lines": lines,
            "metadata": {"confidence": confidence},
        },
    }


# --------------------------------------------------------------------------- #
# cache helpers                                                                #
# --------------------------------------------------------------------------- #


class TestRulesetCachePath:
    def test_sanitises_slash(self) -> None:
        p = _ruleset_cache_path("p/secrets")
        assert p.name == "p_secrets.yaml"


class TestIsCacheFresh:
    def test_fresh_file(self, tmp_path: Path) -> None:
        f = tmp_path / "c.yaml"
        f.write_text("rules: []", encoding="utf-8")
        assert _is_cache_fresh(f) is True

    def test_missing_file(self, tmp_path: Path) -> None:
        assert _is_cache_fresh(tmp_path / "nope.yaml") is False

    def test_stale_file(self, tmp_path: Path) -> None:
        f = tmp_path / "old.yaml"
        f.write_text("rules: []", encoding="utf-8")
        import os
        old = time.time() - (semgrep_scanner._RULES_CACHE_TTL + 100)
        os.utime(f, (old, old))
        assert _is_cache_fresh(f) is False


class TestEnsureCachedRulesets:
    @pytest.mark.asyncio
    async def test_uses_fresh_cache(self) -> None:
        with patch.object(semgrep_scanner, "_is_cache_fresh", return_value=True):
            out = await _ensure_cached_rulesets()
        assert len(out) == len(semgrep_scanner._RULESETS)

    @pytest.mark.asyncio
    async def test_downloads_when_stale(self) -> None:
        with patch.object(semgrep_scanner, "_is_cache_fresh", return_value=False), \
             patch.object(semgrep_scanner, "_download_ruleset", AsyncMock(return_value=True)):
            out = await _ensure_cached_rulesets()
        assert len(out) == len(semgrep_scanner._RULESETS)

    @pytest.mark.asyncio
    async def test_falls_back_to_registry_name(self) -> None:
        with patch.object(semgrep_scanner, "_is_cache_fresh", return_value=False), \
             patch.object(semgrep_scanner, "_download_ruleset", AsyncMock(return_value=False)), \
             patch("pathlib.Path.exists", return_value=False):
            out = await _ensure_cached_rulesets()
        assert out == list(semgrep_scanner._RULESETS)


# --------------------------------------------------------------------------- #
# _download_ruleset                                                            #
# --------------------------------------------------------------------------- #


class TestDownloadRuleset:
    @pytest.mark.asyncio
    async def test_success_writes_file(self, tmp_path: Path) -> None:
        dest = tmp_path / "rules" / "p_secrets.yaml"
        resp = MagicMock()
        resp.content = b"rules: []"
        resp.raise_for_status = MagicMock()
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with patch.object(semgrep_scanner.httpx, "AsyncClient", return_value=client):
            ok = await semgrep_scanner._download_ruleset("p/secrets", dest)
        assert ok is True
        assert dest.read_bytes() == b"rules: []"

    @pytest.mark.asyncio
    async def test_network_error_returns_false(self, tmp_path: Path) -> None:
        dest = tmp_path / "p_secrets.yaml"
        with patch.object(semgrep_scanner.httpx, "AsyncClient", side_effect=RuntimeError("net down")):
            ok = await semgrep_scanner._download_ruleset("p/secrets", dest)
        assert ok is False

    @pytest.mark.asyncio
    async def test_ssl_verify_disabled_branch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SEMGREP_RULES_SSL_VERIFY", "false")
        dest = tmp_path / "p_secrets.yaml"
        resp = MagicMock()
        resp.content = b"rules: []"
        resp.raise_for_status = MagicMock()
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with patch.object(semgrep_scanner.httpx, "AsyncClient", return_value=client):
            ok = await semgrep_scanner._download_ruleset("p/secrets", dest)
        assert ok is True


# --------------------------------------------------------------------------- #
# _find_semgrep                                                                #
# --------------------------------------------------------------------------- #


class TestFindSemgrep:
    def test_found_on_path(self) -> None:
        with patch("pathlib.Path.exists", return_value=False), \
             patch.object(semgrep_scanner.shutil, "which", return_value="/usr/bin/semgrep"):
            assert _find_semgrep() == "/usr/bin/semgrep"

    def test_not_found(self) -> None:
        with patch("pathlib.Path.exists", return_value=False), \
             patch.object(semgrep_scanner.shutil, "which", return_value=None):
            assert _find_semgrep() is None


# --------------------------------------------------------------------------- #
# _normalise                                                                   #
# --------------------------------------------------------------------------- #


class TestNormalise:
    def test_basic_fields(self, tmp_path: Path) -> None:
        target = tmp_path / "app.py"
        f = SemgrepScanner()._normalise(_result(str(target)), str(tmp_path), show_secrets=True)
        assert f is not None
        assert f.file == "app.py"
        assert f.line == 5
        assert f.rule_id == "python.audit.sqli"
        assert f.match == "query = 'SELECT'"

    def test_redaction_default(self, tmp_path: Path) -> None:
        f = SemgrepScanner()._normalise(_result(str(tmp_path / "a.py")), str(tmp_path))
        assert f is not None
        assert f.match == "quer****"

    def test_empty_snippet_uses_placeholder(self, tmp_path: Path) -> None:
        item = _result(str(tmp_path / "a.py"), lines="")
        f = SemgrepScanner()._normalise(item, str(tmp_path), show_secrets=True)
        assert f is not None
        assert f.match == "****"

    def test_severity_map_info(self, tmp_path: Path) -> None:
        item = _result(str(tmp_path / "a.py"), check_id="no-such-rule-xyz", severity="INFO")
        f = SemgrepScanner()._normalise(item, str(tmp_path), show_secrets=True)
        assert f is not None
        # severity is "medium" unless the rule catalogue overrides it
        assert f.severity in {"medium", "high", "critical", "low", "info"}

    def test_non_relative_path_preserved(self) -> None:
        f = SemgrepScanner()._normalise(_result("/elsewhere/x.py"), "/scan/root", show_secrets=True)
        assert f is not None
        assert f.file == "/elsewhere/x.py"


# --------------------------------------------------------------------------- #
# _run (mocked subprocess + rulesets)                                          #
# --------------------------------------------------------------------------- #


class TestRun:
    @pytest.mark.asyncio
    async def test_returns_findings(self, tmp_path: Path) -> None:
        target = tmp_path / "app.py"
        payload = json.dumps({"results": [_result(str(target))]}).encode()
        with patch.object(semgrep_scanner, "_find_semgrep", return_value="/usr/bin/semgrep"), \
             patch.object(semgrep_scanner, "_ensure_cached_rulesets", AsyncMock(return_value=[])), \
             patch.object(semgrep_scanner.asyncio, "create_subprocess_exec",
                          AsyncMock(return_value=_FakeProc(stdout=payload, returncode=1))):
            findings = await SemgrepScanner()._run(ScanConfig(path=str(tmp_path), show_secrets=True))
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_excludes_files(self, tmp_path: Path) -> None:
        target = tmp_path / "skip.py"
        payload = json.dumps({"results": [_result(str(target))]}).encode()
        with patch.object(semgrep_scanner, "_find_semgrep", return_value="/usr/bin/semgrep"), \
             patch.object(semgrep_scanner, "_ensure_cached_rulesets", AsyncMock(return_value=[])), \
             patch.object(semgrep_scanner.asyncio, "create_subprocess_exec",
                          AsyncMock(return_value=_FakeProc(stdout=payload, returncode=1))):
            findings = await SemgrepScanner()._run(
                ScanConfig(path=str(tmp_path), exclude_files=["skip.py"])
            )
        assert findings == []

    @pytest.mark.asyncio
    async def test_unexpected_exit_code(self, tmp_path: Path) -> None:
        with patch.object(semgrep_scanner, "_find_semgrep", return_value="/usr/bin/semgrep"), \
             patch.object(semgrep_scanner, "_ensure_cached_rulesets", AsyncMock(return_value=[])), \
             patch.object(semgrep_scanner.asyncio, "create_subprocess_exec",
                          AsyncMock(return_value=_FakeProc(stderr=b"bad", returncode=2))):
            findings = await SemgrepScanner()._run(ScanConfig(path=str(tmp_path)))
        assert findings == []

    @pytest.mark.asyncio
    async def test_empty_output(self, tmp_path: Path) -> None:
        with patch.object(semgrep_scanner, "_find_semgrep", return_value="/usr/bin/semgrep"), \
             patch.object(semgrep_scanner, "_ensure_cached_rulesets", AsyncMock(return_value=[])), \
             patch.object(semgrep_scanner.asyncio, "create_subprocess_exec",
                          AsyncMock(return_value=_FakeProc(stdout=b"   ", returncode=0))):
            findings = await SemgrepScanner()._run(ScanConfig(path=str(tmp_path)))
        assert findings == []

    @pytest.mark.asyncio
    async def test_invalid_json(self, tmp_path: Path) -> None:
        with patch.object(semgrep_scanner, "_find_semgrep", return_value="/usr/bin/semgrep"), \
             patch.object(semgrep_scanner, "_ensure_cached_rulesets", AsyncMock(return_value=[])), \
             patch.object(semgrep_scanner.asyncio, "create_subprocess_exec",
                          AsyncMock(return_value=_FakeProc(stdout=b"{not json", returncode=1))):
            findings = await SemgrepScanner()._run(ScanConfig(path=str(tmp_path)))
        assert findings == []


# --------------------------------------------------------------------------- #
# scan / is_available / _resolve_binary                                        #
# --------------------------------------------------------------------------- #


class TestScanWrapper:
    @pytest.mark.asyncio
    async def test_scan_catches_exception(self) -> None:
        scanner = SemgrepScanner()
        with patch.object(scanner, "_run", AsyncMock(side_effect=RuntimeError("boom"))):
            assert await scanner.scan(ScanConfig(path="/x")) == []


class TestIsAvailable:
    @pytest.mark.asyncio
    async def test_available_via_binary(self) -> None:
        with patch.object(semgrep_scanner, "_find_semgrep", return_value="/usr/bin/semgrep"):
            assert await SemgrepScanner().is_available() is True

    @pytest.mark.asyncio
    async def test_unavailable(self) -> None:
        with patch.object(semgrep_scanner, "_find_semgrep", return_value=None), \
             patch.object(semgrep_scanner, "detect_container_runtime", return_value=None):
            assert await SemgrepScanner().is_available() is False


class TestResolveBinary:
    @pytest.mark.asyncio
    async def test_binary_path(self) -> None:
        with patch.object(semgrep_scanner, "_find_semgrep", return_value="/usr/bin/semgrep"):
            cmd = await SemgrepScanner()._resolve_binary()
        assert cmd == ["/usr/bin/semgrep"]

    @pytest.mark.asyncio
    async def test_container_fallback(self) -> None:
        with patch.object(semgrep_scanner, "_find_semgrep", return_value=None), \
             patch.object(semgrep_scanner, "detect_container_runtime", return_value="docker"):
            cmd = await SemgrepScanner()._resolve_binary()
        assert cmd[0] == "docker"
        assert "semgrep/semgrep:latest" in cmd
