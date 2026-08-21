"""Tests for src/scanners/airgap_manager.py."""

from __future__ import annotations

import json
import sys
import zipfile
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

    def test_base_requirements_non_list_dependencies(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = "not-a-list"\n', encoding="utf-8"
        )
        assert airgap_manager.base_requirements(tmp_path) == []

    def test_optional_requirements_non_list_group(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project.optional-dependencies]\nsemgrep = "not-a-list"\n', encoding="utf-8"
        )
        assert airgap_manager.optional_requirements(tmp_path) == []


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

    def test_skips_files_with_no_parts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _FakeFile:
            def __init__(self, *parts: str) -> None:
                self.parts = parts

        class _FakeDist:
            files = [_FakeFile()]

            def locate_file(self, path: str) -> Path:
                return Path(path)

        monkeypatch.setattr(
            airgap_manager.importlib.metadata, "distribution", lambda name: _FakeDist()
        )
        assert airgap_manager.distribution_entries("empty-parts") == []


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


# --------------------------------------------------------------------------- #
# bundle_name / safe_copy                                                      #
# --------------------------------------------------------------------------- #


class TestBundleName:
    def test_format(self) -> None:
        name = airgap_manager.bundle_name()
        assert name.startswith(f"{airgap_manager.AIRGAP_PREFIX}-")
        assert name.endswith(".zip")


class TestSafeCopy:
    def test_missing_source_returns_false(self, tmp_path: Path) -> None:
        assert airgap_manager.safe_copy(tmp_path / "nope", tmp_path / "dst") is False

    def test_copies_file(self, tmp_path: Path) -> None:
        src = tmp_path / "src.txt"
        src.write_text("hello", encoding="utf-8")
        dst = tmp_path / "nested" / "dst.txt"
        assert airgap_manager.safe_copy(src, dst) is True
        assert dst.read_text(encoding="utf-8") == "hello"

    def test_copies_directory(self, tmp_path: Path) -> None:
        src = tmp_path / "src_dir"
        src.mkdir()
        (src / "a.txt").write_text("a", encoding="utf-8")
        dst = tmp_path / "dst_dir"
        assert airgap_manager.safe_copy(src, dst) is True
        assert (dst / "a.txt").read_text(encoding="utf-8") == "a"


# --------------------------------------------------------------------------- #
# download_wheels                                                              #
# --------------------------------------------------------------------------- #


class TestDownloadWheels:
    def test_no_requirements_found(self, tmp_path: Path) -> None:
        ok, note = airgap_manager.download_wheels(tmp_path / "wheels", tmp_path)
        assert ok is False
        assert "No project requirements" in note

    def test_success(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["foo==1.0"]\n', encoding="utf-8"
        )

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        monkeypatch.setattr(airgap_manager.subprocess, "run", lambda *a, **kw: _Proc())
        ok, note = airgap_manager.download_wheels(tmp_path / "wheels", tmp_path)
        assert ok is True
        assert note == "downloaded"

    def test_failure(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["foo==1.0"]\n', encoding="utf-8"
        )

        class _Proc:
            returncode = 1
            stdout = ""
            stderr = "line1\nno matching distribution"

        monkeypatch.setattr(airgap_manager.subprocess, "run", lambda *a, **kw: _Proc())
        ok, note = airgap_manager.download_wheels(tmp_path / "wheels", tmp_path)
        assert ok is False
        assert note == "no matching distribution"


# --------------------------------------------------------------------------- #
# _prefetch_step / _prefetch_bool_step                                        #
# --------------------------------------------------------------------------- #


class TestPrefetchStep:
    async def test_success_logs_ready(self) -> None:
        messages: list[str] = []

        async def _coro() -> None:
            return None

        await airgap_manager._prefetch_step("thing", _coro(), messages.append)
        assert any("ready" in m for m in messages)

    async def test_failure_logs_warning(self) -> None:
        messages: list[str] = []

        async def _coro() -> None:
            raise RuntimeError("boom")

        await airgap_manager._prefetch_step("thing", _coro(), messages.append)
        assert any("failed" in m and "boom" in m for m in messages)


class TestPrefetchBoolStep:
    async def test_success_logs_note(self) -> None:
        messages: list[str] = []

        async def _coro() -> tuple[bool, str]:
            return True, "ready"

        result = await airgap_manager._prefetch_bool_step("thing", _coro(), messages.append)
        assert result == (True, "ready")
        assert any("ready" in m for m in messages)

    async def test_failure_logs_warning(self) -> None:
        messages: list[str] = []

        async def _coro() -> tuple[bool, str]:
            return False, "nope"

        result = await airgap_manager._prefetch_bool_step("thing", _coro(), messages.append)
        assert result == (False, "nope")
        assert any("failed" in m for m in messages)


class TestPrefetchWrappers:
    async def test_prefetch_wheels_delegates(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(airgap_manager, "download_wheels", lambda dest, repo: (True, "downloaded"))
        ok, note = await airgap_manager._prefetch_wheels(tmp_path, tmp_path, lambda m: None)
        assert (ok, note) == (True, "downloaded")

    async def test_prefetch_spacy_delegates(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(airgap_manager, "bundle_spacy_model", lambda dest: (True, "bundled"))
        ok, note = await airgap_manager._prefetch_spacy(tmp_path, lambda m: None)
        assert (ok, note) == (True, "bundled")

    async def test_prefetch_semgrep_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(airgap_manager, "_install_semgrep", lambda: (True, "ready"))
        ok, note = await airgap_manager._prefetch_semgrep(lambda m: None)
        assert (ok, note) == (True, "ready")


# --------------------------------------------------------------------------- #
# _install_semgrep                                                             #
# --------------------------------------------------------------------------- #


class TestInstallSemgrep:
    def test_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Proc:
            returncode = 0
            stderr = ""

        monkeypatch.setattr(airgap_manager.subprocess, "run", lambda *a, **kw: _Proc())
        assert airgap_manager._install_semgrep() == (True, "ready")

    def test_failure_returncode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Proc:
            returncode = 1
            stderr = "boom\nlast line"

        monkeypatch.setattr(airgap_manager.subprocess, "run", lambda *a, **kw: _Proc())
        ok, err = airgap_manager._install_semgrep()
        assert ok is False
        assert err == "last line"

    def test_exception_returns_message(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*a, **kw):
            raise OSError("no uv")

        monkeypatch.setattr(airgap_manager.subprocess, "run", _raise)
        ok, err = airgap_manager._install_semgrep()
        assert ok is False
        assert err == "no uv"


# --------------------------------------------------------------------------- #
# _ensure_spacy_for_bundle / bundle_spacy_model                                #
# --------------------------------------------------------------------------- #


class TestEnsureSpacyForBundle:
    def test_model_download_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Proc:
            returncode = 0

        monkeypatch.setattr(airgap_manager.subprocess, "run", lambda *a, **kw: _Proc())
        ok, note = airgap_manager._ensure_spacy_for_bundle()
        assert (ok, note) == (True, "ready")

    def test_model_download_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Proc:
            returncode = 1

        monkeypatch.setattr(airgap_manager.subprocess, "run", lambda *a, **kw: _Proc())
        ok, note = airgap_manager._ensure_spacy_for_bundle()
        assert (ok, note) == (False, "en_core_web_sm download failed")

    def test_spacy_import_error_then_pip_install_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "spacy", None)

        class _Proc:
            returncode = 1

        monkeypatch.setattr(airgap_manager.subprocess, "run", lambda *a, **kw: _Proc())
        ok, note = airgap_manager._ensure_spacy_for_bundle()
        assert (ok, note) == (False, "spaCy uv pip install failed")


class TestBundleSpacyModel:
    def test_ensure_fails_short_circuits(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(
            airgap_manager, "_ensure_spacy_for_bundle", lambda: (False, "no spacy")
        )
        ok, note = airgap_manager.bundle_spacy_model(tmp_path / "dest")
        assert (ok, note) == (False, "no spacy")

    def test_no_entries_found(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(airgap_manager, "_ensure_spacy_for_bundle", lambda: (True, "ready"))
        monkeypatch.setattr(airgap_manager, "distribution_entries", lambda name: [])
        ok, note = airgap_manager.bundle_spacy_model(tmp_path / "dest")
        assert (ok, note) == (False, "model not installed")

    def test_copies_entries(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        model_dir = tmp_path / "en_core_web_sm"
        model_dir.mkdir()
        (model_dir / "__init__.py").write_text("", encoding="utf-8")

        monkeypatch.setattr(airgap_manager, "_ensure_spacy_for_bundle", lambda: (True, "ready"))
        monkeypatch.setattr(airgap_manager, "distribution_entries", lambda name: [model_dir])

        dest = tmp_path / "staged"
        ok, note = airgap_manager.bundle_spacy_model(dest)
        assert (ok, note) == (True, "bundled")
        assert (dest / "en_core_web_sm" / "__init__.py").exists()


# --------------------------------------------------------------------------- #
# create_bundle                                                                #
# --------------------------------------------------------------------------- #


class TestCreateBundle:
    def _stub_high_level_deps(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        import scanners.binary_manager as bm
        import scanners.sonarqube_manager as sm

        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "gitleaks").write_text("x", encoding="utf-8")
        meta_file = tmp_path / "meta.json"
        meta_file.write_text("{}", encoding="utf-8")

        monkeypatch.setattr(bm, "BIN_DIR", bin_dir)
        monkeypatch.setattr(bm, "META_FILE", meta_file)
        monkeypatch.setattr(sm, "_SCANNER_DIR", tmp_path / "sonar-scanner-missing")
        monkeypatch.setattr(sm, "_SQ_DIR", tmp_path / "sonarqube-missing")

        async def _fake_ensure_binary(name: str):
            return None

        async def _fake_ensure_sonar_scanner(progress_callback=None):
            return None

        async def _fake_ensure_sonarqube(progress_callback=None):
            return None

        monkeypatch.setattr(bm, "ensure_binary", _fake_ensure_binary)
        monkeypatch.setattr(sm, "ensure_sonar_scanner", _fake_ensure_sonar_scanner)
        monkeypatch.setattr(sm, "ensure_sonarqube", _fake_ensure_sonarqube)

        monkeypatch.setattr(
            airgap_manager, "download_wheels", lambda dest, repo: (True, "downloaded")
        )
        monkeypatch.setattr(
            airgap_manager, "bundle_spacy_model", lambda dest: (True, "bundled")
        )
        monkeypatch.setattr(airgap_manager, "_install_semgrep", lambda: (True, "ready"))

    def test_success_writes_bundle_zip(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._stub_high_level_deps(monkeypatch, tmp_path)

        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        (repo_root / "pyproject.toml").write_text(
            '[project]\ndependencies = ["foo==1.0"]\n', encoding="utf-8"
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        messages: list[str] = []

        class _Console:
            def print(self, msg: str) -> None:
                messages.append(msg)

        result = airgap_manager.create_bundle(
            repo_root, output_dir, console=_Console(), non_interactive=True
        )
        assert result.exists()
        assert result.parent == output_dir

        with zipfile.ZipFile(result) as zf:
            names = zf.namelist()
        assert "manifest.json" in names
        assert any("gitleaks" in n for n in names)
        assert any("meta.json" in n for n in names)
        assert any("bundle created" in m.lower() for m in messages)

    def test_interactive_preamble_printed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._stub_high_level_deps(monkeypatch, tmp_path)

        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        (repo_root / "pyproject.toml").write_text(
            '[project]\ndependencies = ["foo==1.0"]\n', encoding="utf-8"
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        messages: list[str] = []
        airgap_manager.create_bundle(
            repo_root, output_dir, console=None, non_interactive=False
        )
        # No console supplied: falls back to builtin print, nothing to assert on
        # messages, just ensure no exception was raised.
        assert messages == []

    def test_wheel_prefetch_failure_raises(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._stub_high_level_deps(monkeypatch, tmp_path)
        monkeypatch.setattr(
            airgap_manager, "download_wheels", lambda dest, repo: (False, "network down")
        )

        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        (repo_root / "pyproject.toml").write_text(
            '[project]\ndependencies = ["foo==1.0"]\n', encoding="utf-8"
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        with pytest.raises(RuntimeError, match="network down"):
            airgap_manager.create_bundle(repo_root, output_dir, non_interactive=True)


# --------------------------------------------------------------------------- #
# install_bundle helpers                                                       #
# --------------------------------------------------------------------------- #


class TestReadBundleManifest:
    def test_manifest_present(self, tmp_path: Path) -> None:
        (tmp_path / "manifest.json").write_text(
            json.dumps({"base_requirements": ["a==1"], "optional_requirements": ["b==2"]}),
            encoding="utf-8",
        )
        base, optional = airgap_manager._read_bundle_manifest(tmp_path)
        assert base == ["a==1"]
        assert optional == ["b==2"]

    def test_manifest_missing(self, tmp_path: Path) -> None:
        base, optional = airgap_manager._read_bundle_manifest(tmp_path)
        assert base == []
        assert optional == []


class TestInstallScannerAssets:
    def test_copies_when_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = tmp_path / airgap_manager.SENSITIVE_STORE_DIR
        store.mkdir()
        (store / "meta.json").write_text("{}", encoding="utf-8")

        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(airgap_manager.Path, "home", classmethod(lambda cls: home))

        messages: list[str] = []
        copied = airgap_manager._install_scanner_assets(tmp_path, messages.append)
        assert copied is True
        assert (home / airgap_manager.SENSITIVE_STORE_DIR / "meta.json").exists()

    def test_warns_when_missing(self, tmp_path: Path) -> None:
        messages: list[str] = []
        copied = airgap_manager._install_scanner_assets(tmp_path, messages.append)
        assert copied is False
        assert any("no" in m.lower() and "payload" in m.lower() for m in messages)


class TestInstallWheelsOffline:
    def test_installs_when_wheels_and_reqs_present(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        wheels = tmp_path / "wheels"
        wheels.mkdir()

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        monkeypatch.setattr(airgap_manager.subprocess, "run", lambda *a, **kw: _Proc())
        airgap_manager._install_wheels_offline(wheels, ["foo==1.0"], tmp_path, lambda m: None)

    def test_raises_on_failure(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        wheels = tmp_path / "wheels"
        wheels.mkdir()

        class _Proc:
            returncode = 1
            stdout = ""
            stderr = "oops\nlast error"

        monkeypatch.setattr(airgap_manager.subprocess, "run", lambda *a, **kw: _Proc())
        with pytest.raises(RuntimeError, match="last error"):
            airgap_manager._install_wheels_offline(wheels, ["foo==1.0"], tmp_path, lambda m: None)

    def test_warns_when_missing_wheels_or_reqs(self, tmp_path: Path) -> None:
        messages: list[str] = []
        airgap_manager._install_wheels_offline(
            tmp_path / "nonexistent", ["foo==1.0"], tmp_path, messages.append
        )
        assert any("skipped" in m.lower() for m in messages)

        messages.clear()
        wheels = tmp_path / "wheels"
        wheels.mkdir()
        airgap_manager._install_wheels_offline(wheels, [], tmp_path, messages.append)
        assert any("skipped" in m.lower() for m in messages)


class TestRestoreBundledSitePackages:
    def test_warns_when_nothing_restored(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(airgap_manager, "restore_site_packages", lambda dest: 0)
        messages: list[str] = []
        airgap_manager._restore_bundled_site_packages(tmp_path, messages.append)
        assert any("no bundled" in m.lower() for m in messages)

    def test_no_warning_when_restored(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(airgap_manager, "restore_site_packages", lambda dest: 3)
        messages: list[str] = []
        airgap_manager._restore_bundled_site_packages(tmp_path, messages.append)
        assert messages == []


# --------------------------------------------------------------------------- #
# install_bundle                                                               #
# --------------------------------------------------------------------------- #


class TestInstallBundle:
    def test_missing_bundle_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            airgap_manager.install_bundle(tmp_path / "nope.zip", tmp_path)

    def _make_bundle_zip(self, tmp_path: Path, *, with_assets: bool = True) -> Path:
        stage = tmp_path / "stage"
        stage.mkdir()
        (stage / "manifest.json").write_text(
            json.dumps({"base_requirements": ["foo==1.0"], "optional_requirements": []}),
            encoding="utf-8",
        )
        if with_assets:
            store = stage / airgap_manager.SENSITIVE_STORE_DIR
            store.mkdir()
            (store / "meta.json").write_text("{}", encoding="utf-8")

        bundle_zip = tmp_path / "bundle.zip"
        with zipfile.ZipFile(bundle_zip, "w") as zf:
            for p in stage.rglob("*"):
                if p.is_file():
                    zf.write(p, p.relative_to(stage))
        return bundle_zip

    def test_full_install_flow(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        bundle_zip = self._make_bundle_zip(tmp_path)

        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(airgap_manager.Path, "home", classmethod(lambda cls: home))

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        monkeypatch.setattr(airgap_manager.subprocess, "run", lambda *a, **kw: _Proc())
        monkeypatch.setattr(airgap_manager, "restore_site_packages", lambda dest: 0)

        messages: list[str] = []

        class _Console:
            def print(self, msg: str) -> None:
                messages.append(msg)

        airgap_manager.install_bundle(bundle_zip, tmp_path, console=_Console())

        assert (home / airgap_manager.SENSITIVE_STORE_DIR / "meta.json").exists()
        assert any("installed scanner assets" in m.lower() for m in messages)
        assert any("install complete" in m.lower() for m in messages)

    def test_install_without_assets_skips_message(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        bundle_zip = self._make_bundle_zip(tmp_path, with_assets=False)

        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(airgap_manager.Path, "home", classmethod(lambda cls: home))
        monkeypatch.setattr(airgap_manager, "restore_site_packages", lambda dest: 1)

        messages: list[str] = []
        airgap_manager.install_bundle(bundle_zip, tmp_path, console=None)
        # No assets in the bundle: install completes without the "Installed scanner
        # assets" message (printed via builtin print since console=None).
        assert messages == []
