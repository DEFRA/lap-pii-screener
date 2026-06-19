from __future__ import annotations

import asyncio
import hashlib
import json
import platform
import stat
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import aiofiles
import aiofiles.tempfile
import httpx

# All binaries are stored under ~/.sensitive-scanner/bin/
BIN_DIR = Path.home() / ".sensitive-scanner" / "bin"
META_FILE = Path.home() / ".sensitive-scanner" / "meta.json"

GITHUB_API = "https://api.github.com/repos/{owner}/{repo}/releases/latest"


@dataclass
class BinarySpec:
    name: str          # logical name, e.g. "gitleaks"
    owner: str         # GitHub org/user
    repo: str          # GitHub repo name
    # Maps (system, machine) tuples to the asset name pattern
    asset_patterns: dict[tuple[str, str], str]
    # Suffix for the executable inside the archive, if any
    exe_name: str = ""


def _system() -> str:
    """Normalised OS name: windows | linux | darwin."""
    return platform.system().lower()


def _machine() -> str:
    """Normalised arch: x64 | arm64 | arm."""
    m = platform.machine().lower()
    if m in ("amd64", "x86_64"):
        return "x64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    if m.startswith("arm"):
        return "arm"
    return m


SPECS: dict[str, BinarySpec] = {
    "gitleaks": BinarySpec(
        name="gitleaks",
        owner="gitleaks",
        repo="gitleaks",
        asset_patterns={
            ("windows", "x64"): "gitleaks_{ver}_windows_x64.zip",
            ("windows", "arm64"): "gitleaks_{ver}_windows_arm64.zip",
            ("linux", "x64"): "gitleaks_{ver}_linux_x64.tar.gz",
            ("linux", "arm64"): "gitleaks_{ver}_linux_arm64.tar.gz",
            ("darwin", "x64"): "gitleaks_{ver}_darwin_x64.tar.gz",
            ("darwin", "arm64"): "gitleaks_{ver}_darwin_arm64.tar.gz",
        },
        exe_name="gitleaks",
    ),
    # Semgrep on Linux/macOS: standalone binary from GitHub releases.
    # On Windows, Semgrep is distributed via pip (no GitHub release binary).
    # SemgrepScanner handles the pip-installed exe directly.
    "semgrep": BinarySpec(
        name="semgrep",
        owner="semgrep",
        repo="semgrep",
        asset_patterns={
            ("linux", "x64"): "semgrep-{ver}-ubuntu-latest.tgz",
            ("linux", "arm64"): "semgrep-{ver}-ubuntu-latest.tgz",
            ("darwin", "x64"): "semgrep-{ver}-macos.zip",
            ("darwin", "arm64"): "semgrep-{ver}-macos-arm64.zip",
        },
        exe_name="semgrep",
    ),
}


def binary_path(name: str) -> Path:
    """Return the expected path for a managed binary."""
    suffix = ".exe" if _system() == "windows" else ""
    return BIN_DIR / f"{name}{suffix}"


def is_installed(name: str) -> bool:
    p = binary_path(name)
    return p.exists() and p.stat().st_size > 0


def _load_meta() -> dict:
    if META_FILE.exists():
        try:
            return json.loads(META_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {}


def _save_meta(meta: dict) -> None:
    META_FILE.parent.mkdir(parents=True, exist_ok=True)
    META_FILE.write_text(json.dumps(meta, indent=2), encoding="utf-8")


async def _fetch_release_info(spec: BinarySpec) -> Optional[dict]:
    url = GITHUB_API.format(owner=spec.owner, repo=spec.repo)
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers={"Accept": "application/vnd.github+json"})
            resp.raise_for_status()
            return resp.json()
    except (httpx.HTTPError, OSError, ValueError) as exc:
        print(f"[binary_manager] Could not fetch release info for {spec.name}: {exc}", file=sys.stderr)
        return None


def _find_in_zip(archive_path: Path, exe: str, dest: Path) -> bool:
    """Extract *exe* from a zip archive at *archive_path* into *dest*."""
    with zipfile.ZipFile(archive_path) as zf:
        for member in zf.namelist():
            if Path(member).name == exe:
                data = zf.read(member)
                dest.write_bytes(data)
                return True
    return False


def _find_in_tar(archive_path: Path, exe: str, dest: Path) -> bool:
    """Extract *exe* from a tar archive at *archive_path* into *dest*."""
    with tarfile.open(archive_path) as tf:
        for member in tf.getmembers():
            if Path(member.name).name == exe:
                f = tf.extractfile(member)
                if f:
                    dest.write_bytes(f.read())
                    return True
    return False


def _extract_binary(archive_path: Path, binary_name: str, dest: Path) -> bool:
    """Extract the binary from a zip or tar.gz archive into dest."""
    suffix = _system()
    exe = binary_name + (".exe" if suffix == "windows" else "")
    try:
        if archive_path.suffix == ".zip" or archive_path.name.endswith(".zip"):
            return _find_in_zip(archive_path, exe, dest)
        return _find_in_tar(archive_path, exe, dest)
    except (zipfile.BadZipFile, tarfile.TarError, OSError, KeyError) as exc:
        print(f"[binary_manager] Extraction failed for {archive_path}: {exc}", file=sys.stderr)
    return False


def _resolve_download_url(
    release: dict, spec: "BinarySpec", version: str
) -> tuple[Optional[str], Optional[str], str]:
    """Return (download_url, checksum_url, asset_name) for the current platform, or (None, None, '') on failure."""
    sys_key = (_system(), _machine())
    pattern = spec.asset_patterns.get(sys_key)
    if not pattern:
        print(
            f"[binary_manager] No asset pattern for {spec.name} on {sys_key}",
            file=sys.stderr,
        )
        return None, None, ""

    asset_name = pattern.replace("{ver}", version)
    download_url: Optional[str] = None
    checksum_url: Optional[str] = None

    for asset in release.get("assets", []):
        n = asset["name"]
        if n == asset_name:
            download_url = asset["browser_download_url"]
        if n in (f"{asset_name}.sha256", "checksums.txt"):
            checksum_url = asset["browser_download_url"]

    return download_url, checksum_url, asset_name


async def _download_to_temp(download_url: str, asset_name: str, name: str, version: str) -> Optional[Path]:
    """Stream *download_url* to a temp file and return its path, or None on error."""
    async with aiofiles.tempfile.NamedTemporaryFile(delete=False, suffix=Path(asset_name).suffix) as tmp:
        tmp_path = Path(str(tmp.name))
    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            print(f"[binary_manager] Downloading {name} {version}...", file=sys.stderr)
            async with client.stream("GET", download_url) as resp:
                resp.raise_for_status()
                async with aiofiles.open(tmp_path, "wb") as fh:
                    async for chunk in resp.aiter_bytes(chunk_size=65536):
                        await fh.write(chunk)
    except (httpx.HTTPError, OSError) as exc:
        print(f"[binary_manager] Download failed for {name}: {exc}", file=sys.stderr)
        tmp_path.unlink(missing_ok=True)
        return None
    return tmp_path


async def _verify_checksum(tmp_path: Path, checksum_url: str, asset_name: str, name: str) -> bool:
    """Return True if checksum matches (or verification is skipped due to error)."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            cs_resp = await client.get(checksum_url)
            cs_resp.raise_for_status()
            expected_hash = None
            for line in cs_resp.text.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[-1].endswith(asset_name):
                    expected_hash = parts[0]
                    break
            if expected_hash:
                actual_hash = hashlib.sha256(tmp_path.read_bytes()).hexdigest()
                if actual_hash != expected_hash:
                    print(
                        f"[binary_manager] Checksum mismatch for {name}. Aborting install.",
                        file=sys.stderr,
                    )
                    return False
    except (OSError, ValueError, httpx.HTTPError) as exc:
        print(f"[binary_manager] Checksum verification skipped: {exc}", file=sys.stderr)
    return True


async def ensure_binary(name: str) -> Optional[Path]:
    """
    Ensure the named binary is available in BIN_DIR.
    Downloads from GitHub Releases if not already present.
    Returns the path on success, None on failure.
    """
    if is_installed(name):
        return binary_path(name)

    spec = SPECS.get(name)
    if not spec:
        print(f"[binary_manager] No spec defined for '{name}'", file=sys.stderr)
        return None

    release = await _fetch_release_info(spec)
    if not release:
        return None

    version: str = release.get("tag_name", "").lstrip("v")
    download_url, checksum_url, asset_name = _resolve_download_url(release, spec, version)
    if not download_url:
        print(f"[binary_manager] Asset not found in release for {name}", file=sys.stderr)
        return None

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = await _download_to_temp(download_url, asset_name, name, version)
    if not tmp_path:
        return None

    try:
        if checksum_url:
            if not await _verify_checksum(tmp_path, checksum_url, asset_name, name):
                return None

        dest = binary_path(name)
        if not _extract_binary(tmp_path, spec.exe_name or name, dest):
            print(f"[binary_manager] Could not extract {name} from archive", file=sys.stderr)
            return None

        if _system() != "windows":
            dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        meta = _load_meta()
        meta[name] = {"version": version}
        _save_meta(meta)

        print(f"[binary_manager] {name} {version} installed to {dest}", file=sys.stderr)
        return dest

    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover - defensive cleanup
            pass


async def ensure_all() -> dict[str, Optional[Path]]:
    """Ensure all known binaries are available. Returns a map of name → path."""
    results = await asyncio.gather(*(ensure_binary(name) for name in SPECS), return_exceptions=False)
    return dict(zip(SPECS.keys(), results))
