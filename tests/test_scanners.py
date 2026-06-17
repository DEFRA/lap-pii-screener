"""Tests for scanner utility modules — scanners.constants and scanners.base."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from scanners.base import AbstractScanner
from scanners.constants import detect_container_runtime
from models.finding import Finding, ScanConfig


# --------------------------------------------------------------------------- #
# detect_container_runtime                                                     #
# --------------------------------------------------------------------------- #


class TestDetectContainerRuntime:
    def test_returns_docker_when_available(self) -> None:
        with patch("scanners.constants.shutil.which", return_value="/usr/bin/docker"):
            result = detect_container_runtime()

        assert result == "docker"

    def test_returns_podman_when_only_podman_available(self) -> None:
        def _which(cmd: str) -> str | None:
            return "/usr/bin/podman" if cmd == "podman" else None

        with patch("scanners.constants.shutil.which", side_effect=_which):
            result = detect_container_runtime()

        assert result == "podman"

    def test_prefers_docker_over_podman(self) -> None:
        def _which(cmd: str) -> str | None:
            return f"/usr/bin/{cmd}"  # both available

        with patch("scanners.constants.shutil.which", side_effect=_which):
            result = detect_container_runtime()

        assert result == "docker"

    def test_returns_none_when_neither_available(self) -> None:
        with patch("scanners.constants.shutil.which", return_value=None):
            result = detect_container_runtime()

        assert result is None

    def test_return_type_is_str_or_none(self) -> None:
        with patch("scanners.constants.shutil.which", return_value=None):
            result = detect_container_runtime()

        assert result is None or isinstance(result, str)


# --------------------------------------------------------------------------- #
# AbstractScanner                                                              #
# --------------------------------------------------------------------------- #


class TestAbstractScanner:
    def test_cannot_instantiate_abstract_class(self) -> None:
        with pytest.raises(TypeError):
            AbstractScanner()  # type: ignore[abstract]

    def test_concrete_subclass_must_implement_name(self) -> None:
        class _IncompleteScanner(AbstractScanner):
            async def is_available(self) -> bool:
                return True

            async def scan(self, config: ScanConfig) -> list[Finding]:
                return []

        with pytest.raises(TypeError):
            _IncompleteScanner()  # type: ignore[abstract]

    def test_concrete_subclass_works(self) -> None:
        class _ConcreteScanner(AbstractScanner):
            @property
            def name(self) -> str:
                return "test-scanner"

            async def is_available(self) -> bool:
                return True

            async def scan(self, config: ScanConfig) -> list[Finding]:
                return []

        scanner = _ConcreteScanner()
        assert scanner.name == "test-scanner"

    @pytest.mark.asyncio
    async def test_concrete_is_available(self) -> None:
        class _ConcreteScanner(AbstractScanner):
            @property
            def name(self) -> str:
                return "test-scanner"

            async def is_available(self) -> bool:
                return True

            async def scan(self, config: ScanConfig) -> list[Finding]:
                return []

        scanner = _ConcreteScanner()
        assert await scanner.is_available() is True

    @pytest.mark.asyncio
    async def test_concrete_scan_returns_list(self) -> None:
        class _ConcreteScanner(AbstractScanner):
            @property
            def name(self) -> str:
                return "test-scanner"

            async def is_available(self) -> bool:
                return True

            async def scan(self, config: ScanConfig) -> list[Finding]:
                return []

        scanner = _ConcreteScanner()
        result = await scanner.scan(ScanConfig(path="/tmp"))
        assert isinstance(result, list)
