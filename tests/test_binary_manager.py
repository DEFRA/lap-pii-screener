"""Tests for src/scanners/binary_manager.py."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from scanners import binary_manager as bm


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _make_zip(path: Path, arcname: str, data: bytes) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(arcname, data)


def _make_tar(path: Path, arcname: str, data: bytes) -> None:
    with tarfile.open(path, "w:gz") as tf:
        info = tarfile.TarInfo(name=arcname)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))


def _async_client(get_resp: MagicMock) -> AsyncMock:
    client = AsyncMock()
    client.get = AsyncMock(return_value=get_resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


# --------------------------------------------------------------------------- #
# _system / _machine                                                          #
# --------------------------------------------------------------------------- #


class TestPlatformHelpers:
    def test_system_lowercased(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm.platform, "system", lambda: "Windows")
        assert bm._system() == "windows"

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("AMD64", "x64"),
            ("x86_64", "x64"),
            ("aarch64", "arm64"),
            ("arm64", "arm64"),
            ("armv7l", "arm"),
            ("riscv", "riscv"),
        ],
    )
    def test_machine_normalisation(self, monkeypatch: pytest.MonkeyPatch, raw: str, expected: str) -> None:
        monkeypatch.setattr(bm.platform, "machine", lambda: raw)
        assert bm._machine() == expected


# --------------------------------------------------------------------------- #
# binary_path / is_installed                                                  #
# --------------------------------------------------------------------------- #


class TestBinaryPath:
    def test_binary_path_windows_suffix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "windows")
        monkeypatch.setattr(bm, "BIN_DIR", Path("/tmp/bin"))
        assert bm.binary_path("gitleaks") == Path("/tmp/bin/gitleaks.exe")

    def test_binary_path_unix_no_suffix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "linux")
        monkeypatch.setattr(bm, "BIN_DIR", Path("/tmp/bin"))
        assert bm.binary_path("gitleaks") == Path("/tmp/bin/gitleaks")

    def test_is_installed_true(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "linux")
        monkeypatch.setattr(bm, "BIN_DIR", tmp_path)
        (tmp_path / "gitleaks").write_bytes(b"x")
        assert bm.is_installed("gitleaks") is True

    def test_is_installed_false_missing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "linux")
        monkeypatch.setattr(bm, "BIN_DIR", tmp_path)
        assert bm.is_installed("gitleaks") is False

    def test_is_installed_false_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "linux")
        monkeypatch.setattr(bm, "BIN_DIR", tmp_path)
        (tmp_path / "gitleaks").write_bytes(b"")
        assert bm.is_installed("gitleaks") is False


# --------------------------------------------------------------------------- #
# _load_meta / _save_meta                                                     #
# --------------------------------------------------------------------------- #


class TestMeta:
    def test_save_and_load_roundtrip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        meta_file = tmp_path / "sub" / "meta.json"
        monkeypatch.setattr(bm, "META_FILE", meta_file)
        bm._save_meta({"gitleaks": {"version": "8.0.0"}})
        assert bm._load_meta() == {"gitleaks": {"version": "8.0.0"}}

    def test_load_meta_missing_returns_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "META_FILE", tmp_path / "nope.json")
        assert bm._load_meta() == {}

    def test_load_meta_corrupt_returns_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        meta_file = tmp_path / "meta.json"
        meta_file.write_text("{not json", encoding="utf-8")
        monkeypatch.setattr(bm, "META_FILE", meta_file)
        assert bm._load_meta() == {}


# --------------------------------------------------------------------------- #
# _fetch_release_info                                                         #
# --------------------------------------------------------------------------- #


class TestFetchReleaseInfo:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        spec = bm.SPECS["gitleaks"]
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value={"tag_name": "v8.0.0"})
        client = _async_client(resp)
        with patch.object(bm.httpx, "AsyncClient", return_value=client):
            info = await bm._fetch_release_info(spec)
        assert info == {"tag_name": "v8.0.0"}

    @pytest.mark.asyncio
    async def test_http_error_returns_none(self) -> None:
        spec = bm.SPECS["gitleaks"]
        with patch.object(bm.httpx, "AsyncClient", side_effect=httpx.HTTPError("boom")):
            info = await bm._fetch_release_info(spec)
        assert info is None


# --------------------------------------------------------------------------- #
# _find_in_zip / _find_in_tar / _extract_binary                              #
# --------------------------------------------------------------------------- #


class TestExtraction:
    def test_find_in_zip_success(self, tmp_path: Path) -> None:
        archive = tmp_path / "a.zip"
        _make_zip(archive, "gitleaks", b"BINARY")
        dest = tmp_path / "out"
        assert bm._find_in_zip(archive, "gitleaks", dest) is True
        assert dest.read_bytes() == b"BINARY"

    def test_find_in_zip_not_found(self, tmp_path: Path) -> None:
        archive = tmp_path / "a.zip"
        _make_zip(archive, "other", b"X")
        dest = tmp_path / "out"
        assert bm._find_in_zip(archive, "gitleaks", dest) is False
        assert not dest.exists()

    def test_find_in_tar_success(self, tmp_path: Path) -> None:
        archive = tmp_path / "a.tar.gz"
        _make_tar(archive, "nested/gitleaks", b"TARBIN")
        dest = tmp_path / "out"
        assert bm._find_in_tar(archive, "gitleaks", dest) is True
        assert dest.read_bytes() == b"TARBIN"

    def test_find_in_tar_not_found(self, tmp_path: Path) -> None:
        archive = tmp_path / "a.tar.gz"
        _make_tar(archive, "other", b"X")
        dest = tmp_path / "out"
        assert bm._find_in_tar(archive, "gitleaks", dest) is False

    def test_extract_binary_zip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "linux")
        archive = tmp_path / "a.zip"
        _make_zip(archive, "gitleaks", b"Z")
        dest = tmp_path / "out"
        assert bm._extract_binary(archive, "gitleaks", dest) is True
        assert dest.read_bytes() == b"Z"

    def test_extract_binary_tar(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "linux")
        archive = tmp_path / "a.tar.gz"
        _make_tar(archive, "gitleaks", b"T")
        dest = tmp_path / "out"
        assert bm._extract_binary(archive, "gitleaks", dest) is True
        assert dest.read_bytes() == b"T"

    def test_extract_binary_windows_exe_name(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "windows")
        archive = tmp_path / "a.zip"
        _make_zip(archive, "gitleaks.exe", b"W")
        dest = tmp_path / "out.exe"
        assert bm._extract_binary(archive, "gitleaks", dest) is True
        assert dest.read_bytes() == b"W"

    def test_extract_binary_bad_archive_returns_false(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "linux")
        archive = tmp_path / "a.zip"
        archive.write_bytes(b"not a real zip")
        dest = tmp_path / "out"
        assert bm._extract_binary(archive, "gitleaks", dest) is False


# --------------------------------------------------------------------------- #
# _resolve_download_url                                                       #
# --------------------------------------------------------------------------- #


class TestResolveDownloadUrl:
    def test_resolves_download_and_checksum(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "linux")
        monkeypatch.setattr(bm, "_machine", lambda: "x64")
        spec = bm.SPECS["gitleaks"]
        release = {
            "assets": [
                {"name": "gitleaks_8.0.0_linux_x64.tar.gz", "browser_download_url": "https://dl/bin"},
                {"name": "checksums.txt", "browser_download_url": "https://dl/cs"},
            ]
        }
        dl, cs, asset = bm._resolve_download_url(release, spec, "8.0.0")
        assert dl == "https://dl/bin"
        assert cs == "https://dl/cs"
        assert asset == "gitleaks_8.0.0_linux_x64.tar.gz"

    def test_no_pattern_for_platform(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "plan9")
        monkeypatch.setattr(bm, "_machine", lambda: "x64")
        spec = bm.SPECS["gitleaks"]
        dl, cs, asset = bm._resolve_download_url({"assets": []}, spec, "8.0.0")
        assert dl is None and cs is None and asset == ""

    def test_sha256_specific_checksum(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "_system", lambda: "linux")
        monkeypatch.setattr(bm, "_machine", lambda: "x64")
        spec = bm.SPECS["gitleaks"]
        asset_name = "gitleaks_8.0.0_linux_x64.tar.gz"
        release = {
            "assets": [
                {"name": asset_name, "browser_download_url": "https://dl/bin"},
                {"name": f"{asset_name}.sha256", "browser_download_url": "https://dl/cs256"},
            ]
        }
        dl, cs, asset = bm._resolve_download_url(release, spec, "8.0.0")
        assert dl == "https://dl/bin"
        assert cs == "https://dl/cs256"


# --------------------------------------------------------------------------- #
# _download_to_temp                                                           #
# --------------------------------------------------------------------------- #


def _stream_client(chunks: list[bytes]) -> AsyncMock:
    """Build an httpx-like client whose .stream() yields *chunks*."""

    async def _aiter(chunk_size: int = 0):  # noqa: ANN202
        for c in chunks:
            yield c

    stream_resp = MagicMock()
    stream_resp.raise_for_status = MagicMock()
    stream_resp.aiter_bytes = _aiter
    stream_cm = AsyncMock()
    stream_cm.__aenter__ = AsyncMock(return_value=stream_resp)
    stream_cm.__aexit__ = AsyncMock(return_value=False)

    client = AsyncMock()
    client.stream = MagicMock(return_value=stream_cm)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


class TestDownloadToTemp:
    @pytest.mark.asyncio
    async def test_success_writes_bytes(self) -> None:
        client = _stream_client([b"abc", b"def"])
        with patch.object(bm.httpx, "AsyncClient", return_value=client):
            path = await bm._download_to_temp("https://dl/bin", "bin.tar.gz", "gitleaks", "8.0.0")
        assert path is not None
        assert path.read_bytes() == b"abcdef"
        path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_download_error_returns_none(self) -> None:
        with patch.object(bm.httpx, "AsyncClient", side_effect=httpx.HTTPError("net")):
            path = await bm._download_to_temp("https://dl/bin", "bin.tar.gz", "gitleaks", "8.0.0")
        assert path is None


# --------------------------------------------------------------------------- #
# _verify_checksum                                                            #
# --------------------------------------------------------------------------- #


class TestVerifyChecksum:
    @pytest.mark.asyncio
    async def test_match_returns_true(self, tmp_path: Path) -> None:
        f = tmp_path / "bin"
        f.write_bytes(b"payload")
        digest = hashlib.sha256(b"payload").hexdigest()
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.text = f"{digest}  myasset.tar.gz"
        client = _async_client(resp)
        with patch.object(bm.httpx, "AsyncClient", return_value=client):
            ok = await bm._verify_checksum(f, "https://cs", "myasset.tar.gz", "gitleaks")
        assert ok is True

    @pytest.mark.asyncio
    async def test_mismatch_returns_false(self, tmp_path: Path) -> None:
        f = tmp_path / "bin"
        f.write_bytes(b"payload")
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.text = "deadbeef  myasset.tar.gz"
        client = _async_client(resp)
        with patch.object(bm.httpx, "AsyncClient", return_value=client):
            ok = await bm._verify_checksum(f, "https://cs", "myasset.tar.gz", "gitleaks")
        assert ok is False

    @pytest.mark.asyncio
    async def test_no_matching_line_returns_true(self, tmp_path: Path) -> None:
        f = tmp_path / "bin"
        f.write_bytes(b"payload")
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.text = "abc  other.tar.gz"
        client = _async_client(resp)
        with patch.object(bm.httpx, "AsyncClient", return_value=client):
            ok = await bm._verify_checksum(f, "https://cs", "myasset.tar.gz", "gitleaks")
        assert ok is True

    @pytest.mark.asyncio
    async def test_network_error_skips_returns_true(self, tmp_path: Path) -> None:
        f = tmp_path / "bin"
        f.write_bytes(b"payload")
        with patch.object(bm.httpx, "AsyncClient", side_effect=httpx.HTTPError("net")):
            ok = await bm._verify_checksum(f, "https://cs", "myasset.tar.gz", "gitleaks")
        assert ok is True


# --------------------------------------------------------------------------- #
# ensure_binary                                                               #
# --------------------------------------------------------------------------- #


class TestEnsureBinary:
    @pytest.mark.asyncio
    async def test_already_installed_returns_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "is_installed", lambda name: True)
        monkeypatch.setattr(bm, "binary_path", lambda name: Path("/bin/gitleaks"))
        out = await bm.ensure_binary("gitleaks")
        assert out == Path("/bin/gitleaks")

    @pytest.mark.asyncio
    async def test_no_spec_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "is_installed", lambda name: False)
        out = await bm.ensure_binary("unknown-tool")
        assert out is None

    @pytest.mark.asyncio
    async def test_release_fetch_fails_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "is_installed", lambda name: False)
        monkeypatch.setattr(bm, "_fetch_release_info", AsyncMock(return_value=None))
        out = await bm.ensure_binary("gitleaks")
        assert out is None

    @pytest.mark.asyncio
    async def test_no_download_url_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "is_installed", lambda name: False)
        monkeypatch.setattr(bm, "_fetch_release_info", AsyncMock(return_value={"tag_name": "v8.0.0"}))
        monkeypatch.setattr(bm, "_resolve_download_url", lambda *a: (None, None, ""))
        out = await bm.ensure_binary("gitleaks")
        assert out is None

    @pytest.mark.asyncio
    async def test_download_fails_returns_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bm, "is_installed", lambda name: False)
        monkeypatch.setattr(bm, "BIN_DIR", tmp_path / "bin")
        monkeypatch.setattr(bm, "_fetch_release_info", AsyncMock(return_value={"tag_name": "v8.0.0"}))
        monkeypatch.setattr(bm, "_resolve_download_url", lambda *a: ("https://dl", None, "a.tar.gz"))
        monkeypatch.setattr(bm, "_download_to_temp", AsyncMock(return_value=None))
        out = await bm.ensure_binary("gitleaks")
        assert out is None

    @pytest.mark.asyncio
    async def test_checksum_fail_returns_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        tmp_archive = tmp_path / "archive"
        tmp_archive.write_bytes(b"data")
        monkeypatch.setattr(bm, "is_installed", lambda name: False)
        monkeypatch.setattr(bm, "BIN_DIR", tmp_path / "bin")
        monkeypatch.setattr(bm, "_fetch_release_info", AsyncMock(return_value={"tag_name": "v8.0.0"}))
        monkeypatch.setattr(bm, "_resolve_download_url", lambda *a: ("https://dl", "https://cs", "a.tar.gz"))
        monkeypatch.setattr(bm, "_download_to_temp", AsyncMock(return_value=tmp_archive))
        monkeypatch.setattr(bm, "_verify_checksum", AsyncMock(return_value=False))
        out = await bm.ensure_binary("gitleaks")
        assert out is None
        assert not tmp_archive.exists()  # cleaned up in finally

    @pytest.mark.asyncio
    async def test_extract_fail_returns_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        tmp_archive = tmp_path / "archive"
        tmp_archive.write_bytes(b"data")
        monkeypatch.setattr(bm, "is_installed", lambda name: False)
        monkeypatch.setattr(bm, "BIN_DIR", tmp_path / "bin")
        monkeypatch.setattr(bm, "binary_path", lambda name: tmp_path / "bin" / "gitleaks")
        monkeypatch.setattr(bm, "_fetch_release_info", AsyncMock(return_value={"tag_name": "v8.0.0"}))
        monkeypatch.setattr(bm, "_resolve_download_url", lambda *a: ("https://dl", None, "a.tar.gz"))
        monkeypatch.setattr(bm, "_download_to_temp", AsyncMock(return_value=tmp_archive))
        monkeypatch.setattr(bm, "_extract_binary", lambda *a: False)
        out = await bm.ensure_binary("gitleaks")
        assert out is None

    @pytest.mark.asyncio
    async def test_full_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        tmp_archive = tmp_path / "archive"
        tmp_archive.write_bytes(b"data")
        bin_dir = tmp_path / "bin"
        dest = bin_dir / "gitleaks"
        monkeypatch.setattr(bm, "_system", lambda: "linux")
        monkeypatch.setattr(bm, "is_installed", lambda name: False)
        monkeypatch.setattr(bm, "BIN_DIR", bin_dir)
        monkeypatch.setattr(bm, "META_FILE", tmp_path / "meta.json")
        monkeypatch.setattr(bm, "binary_path", lambda name: dest)
        monkeypatch.setattr(bm, "_fetch_release_info", AsyncMock(return_value={"tag_name": "v8.0.0"}))
        monkeypatch.setattr(bm, "_resolve_download_url", lambda *a: ("https://dl", None, "a.tar.gz"))
        monkeypatch.setattr(bm, "_download_to_temp", AsyncMock(return_value=tmp_archive))

        def _fake_extract(archive: Path, name: str, d: Path) -> bool:
            d.parent.mkdir(parents=True, exist_ok=True)
            d.write_bytes(b"BIN")
            return True

        monkeypatch.setattr(bm, "_extract_binary", _fake_extract)
        out = await bm.ensure_binary("gitleaks")
        assert out == dest
        assert dest.read_bytes() == b"BIN"
        assert bm._load_meta() == {"gitleaks": {"version": "8.0.0"}}
        assert not tmp_archive.exists()


# --------------------------------------------------------------------------- #
# ensure_all                                                                  #
# --------------------------------------------------------------------------- #


class TestEnsureAll:
    @pytest.mark.asyncio
    async def test_maps_names_to_paths(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _fake(name: str) -> Path:
            return Path(f"/bin/{name}")

        monkeypatch.setattr(bm, "ensure_binary", _fake)
        result = await bm.ensure_all()
        assert result == {name: Path(f"/bin/{name}") for name in bm.SPECS}
