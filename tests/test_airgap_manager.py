"""Tests for src/scanners/airgap_manager.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanners import airgap_manager


# --------------------------------------------------------------------------- #
# optional_requirements / base_requirements                                   #
# --------------------------------------------------------------------------- #


class TestRequirements:
    def test_optional_requirements(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            """
[project.optional-dependencies]
semgrep = ["semgrep==1.2.3"]
spacy = ["spacy==3.2.1"]
docs = ["python-docx==1.0.0"]
""".strip(),
            encoding="utf-8",
        )
        assert airgap_manager.optional_requirements(tmp_path) == ["semgrep==1.2.3", "spacy==3.2.1"]

    def test_optional_requirements_missing_pyproject(self, tmp_path: Path) -> None:
        assert airgap_manager.optional_requirements(tmp_path) == []

    def test_base_requirements(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            """
[project]
dependencies = [
  "mcp[cli]==1.2.3",
  "pydantic==2.0.0",
  "pip>=26.0",
]
""".strip(),
            encoding="utf-8",
        )
        assert airgap_manager.base_requirements(tmp_path) == ["mcp[cli]==1.2.3", "pydantic==2.0.0"]

    def test_base_requirements_missing_pyproject(self, tmp_path: Path) -> None:
        assert airgap_manager.base_requirements(tmp_path) == []


# --------------------------------------------------------------------------- #
# distribution_entries                                                         #
# --------------------------------------------------------------------------- #


class TestDistributionEntries:
    def test_returns_top_level_paths(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        pkg_dir = tmp_path / "en_core_web_sm"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
        dist_info = tmp_path / "en_core_web_sm-1.0.0.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("", encoding="utf-8")

        class _FakeFile:
            def __init__(self, *parts: str) -> None:
                self.parts = parts

        class _FakeDist:
            files = [
                _FakeFile("en_core_web_sm", "__init__.py"),
                _FakeFile("en_core_web_sm-1.0.0.dist-info", "METADATA"),
            ]

            def locate_file(self, path: str) -> Path:
                return tmp_path / path

        monkeypatch.setattr(
            airgap_manager.importlib.metadata, "distribution", lambda name: _FakeDist()
        )
        assert airgap_manager.distribution_entries("en-core-web-sm") == [pkg_dir, dist_info]

    def test_missing_distribution_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import importlib.metadata as _meta

        monkeypatch.setattr(
            airgap_manager.importlib.metadata,
            "distribution",
            lambda name: (_ for _ in ()).throw(  # type: ignore[arg-type]
                _meta.PackageNotFoundError(name)
            ),
        )
        assert airgap_manager.distribution_entries("no-such-pkg") == []


# --------------------------------------------------------------------------- #
# restore_site_packages                                                        #
# --------------------------------------------------------------------------- #


class TestRestoreSitePackages:
    def test_restores_entries(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        bundle_dir = tmp_path / "bundle-site"
        bundle_dir.mkdir()
        model_dir = bundle_dir / "en_core_web_sm"
        model_dir.mkdir()
        (model_dir / "__init__.py").write_text("", encoding="utf-8")

        purelib = tmp_path / "purelib"
        monkeypatch.setattr(
            airgap_manager.sysconfig, "get_paths", lambda: {"purelib": str(purelib)}
        )

        restored = airgap_manager.restore_site_packages(bundle_dir)
        assert restored == 1
        assert (purelib / "en_core_web_sm" / "__init__.py").exists()

    def test_missing_bundle_dir_returns_zero(self, tmp_path: Path) -> None:
        assert airgap_manager.restore_site_packages(tmp_path / "nonexistent") == 0
