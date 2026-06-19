"""Tests for scanners.gitleaks_scanner — JSON normalisation, filtering, subprocess handling."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from models.finding import ScanConfig
from scanners import gitleaks_scanner
from scanners.gitleaks_scanner import GitleaksScanner


class _FakeProc:
    def __init__(self, returncode: int = 1) -> None:
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return (b"", b"")


def _subprocess_writing(report_data: object, returncode: int = 1):
    """Return a fake create_subprocess_exec that writes report_data to --report-path."""
    async def _fake(*args, **kwargs):  # noqa: ANN002
        argv = list(args)
        if "--report-path" in argv:
            rp = argv[argv.index("--report-path") + 1]
            Path(rp).write_text(json.dumps(report_data), encoding="utf-8")
        return _FakeProc(returncode)
    return _fake


def _item(file_path: str, *, rule_id: str = "generic-api-key", secret: str = "sk_live_abcd1234",
          start_line: int = 12, description: str = "Generic API key") -> dict:
    return {
        "RuleID": rule_id,
        "File": file_path,
        "Secret": secret,
        "StartLine": start_line,
        "Description": description,
    }


# --------------------------------------------------------------------------- #
# _normalise                                                                   #
# --------------------------------------------------------------------------- #


class TestNormalise:
    def test_basic_fields(self, tmp_path: Path) -> None:
        target = tmp_path / "config.py"
        scanner = GitleaksScanner()
        f = scanner._normalise(_item(str(target)), str(tmp_path), show_secrets=True)
        assert f.file == "config.py"
        assert f.line == 12
        assert f.rule_id == "generic-api-key"
        assert f.match == "sk_live_abcd1234"
        assert "gitleaks" in f.scanners

    def test_redaction_default(self, tmp_path: Path) -> None:
        target = tmp_path / "config.py"
        scanner = GitleaksScanner()
        f = scanner._normalise(_item(str(target)), str(tmp_path))
        assert f.match == "sk_l****"

    def test_falls_back_to_match_when_no_secret(self, tmp_path: Path) -> None:
        item = _item(str(tmp_path / "a.py"))
        del item["Secret"]
        item["Match"] = "fallback_value"
        scanner = GitleaksScanner()
        f = scanner._normalise(item, str(tmp_path), show_secrets=True)
        assert f.match == "fallback_value"

    def test_line_fallback_to_line_key(self, tmp_path: Path) -> None:
        item = _item(str(tmp_path / "a.py"))
        del item["StartLine"]
        item["Line"] = 7
        scanner = GitleaksScanner()
        f = scanner._normalise(item, str(tmp_path), show_secrets=True)
        assert f.line == 7

    def test_confidence_set_from_severity(self, tmp_path: Path) -> None:
        scanner = GitleaksScanner()
        f = scanner._normalise(_item(str(tmp_path / "a.py")), str(tmp_path))
        assert 0.0 < f.confidence <= 1.0

    def test_non_relative_path_preserved(self) -> None:
        scanner = GitleaksScanner()
        f = scanner._normalise(_item("/elsewhere/x.py"), "/scan/root", show_secrets=True)
        assert f.file == "/elsewhere/x.py"


# --------------------------------------------------------------------------- #
# _run (mocked subprocess)                                                     #
# --------------------------------------------------------------------------- #


class TestRun:
    @pytest.mark.asyncio
    async def test_returns_findings_from_report(self, tmp_path: Path) -> None:
        target = tmp_path / "secrets.py"
        target.write_text("x = 1", encoding="utf-8")
        data = [_item(str(target))]
        with patch.object(gitleaks_scanner, "ensure_binary", AsyncMock(return_value=Path("gitleaks"))), \
             patch.object(gitleaks_scanner.asyncio, "create_subprocess_exec",
                          side_effect=_subprocess_writing(data)):
            findings = await GitleaksScanner()._run(ScanConfig(path=str(tmp_path), show_secrets=True))
        assert len(findings) == 1
        assert findings[0].rule_id == "generic-api-key"

    @pytest.mark.asyncio
    async def test_excludes_by_file(self, tmp_path: Path) -> None:
        target = tmp_path / "skip.py"
        data = [_item(str(target))]
        with patch.object(gitleaks_scanner, "ensure_binary", AsyncMock(return_value=Path("gitleaks"))), \
             patch.object(gitleaks_scanner.asyncio, "create_subprocess_exec",
                          side_effect=_subprocess_writing(data)):
            findings = await GitleaksScanner()._run(
                ScanConfig(path=str(tmp_path), exclude_files=["skip.py"])
            )
        assert findings == []

    @pytest.mark.asyncio
    async def test_excludes_by_path_part(self, tmp_path: Path) -> None:
        sub = tmp_path / "vendor"
        sub.mkdir()
        data = [_item(str(sub / "lib.py"))]
        with patch.object(gitleaks_scanner, "ensure_binary", AsyncMock(return_value=Path("gitleaks"))), \
             patch.object(gitleaks_scanner.asyncio, "create_subprocess_exec",
                          side_effect=_subprocess_writing(data)):
            findings = await GitleaksScanner()._run(
                ScanConfig(path=str(tmp_path), exclude_paths=["vendor"])
            )
        assert findings == []

    @pytest.mark.asyncio
    async def test_excludes_by_pattern(self, tmp_path: Path) -> None:
        data = [_item(str(tmp_path / "config.test.py"))]
        with patch.object(gitleaks_scanner, "ensure_binary", AsyncMock(return_value=Path("gitleaks"))), \
             patch.object(gitleaks_scanner.asyncio, "create_subprocess_exec",
                          side_effect=_subprocess_writing(data)):
            findings = await GitleaksScanner()._run(
                ScanConfig(path=str(tmp_path), exclude_patterns=["*.test.py"])
            )
        assert findings == []

    @pytest.mark.asyncio
    async def test_unexpected_exit_code_returns_empty(self, tmp_path: Path) -> None:
        with patch.object(gitleaks_scanner, "ensure_binary", AsyncMock(return_value=Path("gitleaks"))), \
             patch.object(gitleaks_scanner.asyncio, "create_subprocess_exec",
                          side_effect=_subprocess_writing([], returncode=2)):
            findings = await GitleaksScanner()._run(ScanConfig(path=str(tmp_path)))
        assert findings == []

    @pytest.mark.asyncio
    async def test_invalid_json_returns_empty(self, tmp_path: Path) -> None:
        async def _fake(*args, **kwargs):  # noqa: ANN002
            argv = list(args)
            rp = argv[argv.index("--report-path") + 1]
            Path(rp).write_text("{not valid", encoding="utf-8")
            return _FakeProc(1)
        with patch.object(gitleaks_scanner, "ensure_binary", AsyncMock(return_value=Path("gitleaks"))), \
             patch.object(gitleaks_scanner.asyncio, "create_subprocess_exec", side_effect=_fake):
            findings = await GitleaksScanner()._run(ScanConfig(path=str(tmp_path)))
        assert findings == []


# --------------------------------------------------------------------------- #
# scan / is_available / _resolve_binary                                        #
# --------------------------------------------------------------------------- #


class TestScanWrapper:
    @pytest.mark.asyncio
    async def test_scan_catches_exception(self) -> None:
        scanner = GitleaksScanner()
        with patch.object(scanner, "_run", AsyncMock(side_effect=RuntimeError("boom"))):
            assert await scanner.scan(ScanConfig(path="/x")) == []


class TestIsAvailable:
    @pytest.mark.asyncio
    async def test_available_via_managed_binary(self) -> None:
        with patch.object(gitleaks_scanner, "ensure_binary", AsyncMock(return_value=Path("gitleaks"))):
            assert await GitleaksScanner().is_available() is True

    @pytest.mark.asyncio
    async def test_available_via_path(self) -> None:
        with patch.object(gitleaks_scanner, "ensure_binary", AsyncMock(return_value=None)), \
             patch.object(gitleaks_scanner.shutil, "which", return_value="/usr/bin/gitleaks"):
            assert await GitleaksScanner().is_available() is True

    @pytest.mark.asyncio
    async def test_unavailable(self) -> None:
        with patch.object(gitleaks_scanner, "ensure_binary", AsyncMock(return_value=None)), \
             patch.object(gitleaks_scanner.shutil, "which", return_value=None), \
             patch.object(gitleaks_scanner, "detect_container_runtime", return_value=None):
            assert await GitleaksScanner().is_available() is False


class TestResolveBinary:
    @pytest.mark.asyncio
    async def test_managed_binary(self) -> None:
        with patch.object(gitleaks_scanner, "ensure_binary", AsyncMock(return_value=Path("/bin/gitleaks"))):
            cmd = await GitleaksScanner()._resolve_binary()
        assert cmd == [str(Path("/bin/gitleaks"))]

    @pytest.mark.asyncio
    async def test_container_fallback(self) -> None:
        with patch.object(gitleaks_scanner, "ensure_binary", AsyncMock(return_value=None)), \
             patch.object(gitleaks_scanner.shutil, "which", return_value=None), \
             patch.object(gitleaks_scanner, "detect_container_runtime", return_value="podman"):
            cmd = await GitleaksScanner()._resolve_binary()
        assert cmd[0] == "podman"
        assert "zricethezav/gitleaks:latest" in cmd
