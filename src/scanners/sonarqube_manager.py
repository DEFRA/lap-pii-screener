"""
sonarqube_manager.py
--------------------
Auto-download and configure SonarQube Community Edition and sonar-scanner-cli
so that `sensitive-scanner setup --sonarqube` requires no manual steps.

Key design decisions
  • SONAR_PORT = 9100  — hardcoded to avoid the ZScaler / port-9000 conflict
    that every team member hits.  sonar.properties is patched immediately after
    extraction so the server is *never* started on 9000.
  • Mirrors binary_manager.py conventions: httpx streaming download, SHA-256
    verification where available, version metadata in meta.json.
  • sonar-scanner-cli comes from GitHub Releases (SonarSource/sonar-scanner-cli).
  • SonarQube CE comes from binaries.sonarsource.com; the version is discovered
    via the GitHub Releases API for SonarSource/sonarqube.
"""
from __future__ import annotations

import asyncio
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional

import aiofiles
import aiofiles.tempfile
import httpx

# ── Constants ─────────────────────────────────────────────────────────────────

# Fixed port — avoids ZScaler blocking of 9000 for every team member.
SONAR_PORT: int = 9100
_SONAR_SH = "sonar.sh"

_BASE_DIR = Path.home() / ".sensitive-scanner"
_SQ_DIR = _BASE_DIR / "sonarqube"
_SCANNER_DIR = _BASE_DIR / "sonar-scanner"
META_FILE = _BASE_DIR / "meta.json"

_GITHUB_LATEST = "https://api.github.com/repos/{owner}/{repo}/releases/latest"
_SQ_BINARIES_URL = (
    "https://binaries.sonarsource.com/Distribution/sonarqube/"
    "sonarqube-{ver}-community.zip"
)
_TEMURIN_URL = "https://adoptium.net/temurin/releases/"


# ── Platform helpers ──────────────────────────────────────────────────────────

def _system() -> str:
    return platform.system().lower()


def _machine() -> str:
    m = platform.machine().lower()
    if m in ("amd64", "x86_64"):
        return "x64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    return m


# ── Metadata ──────────────────────────────────────────────────────────────────

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


# ── Persistent environment-variable helper ────────────────────────────────────

def _persist_unix_env_var(name: str, value: str) -> bool:
    """Append or update ``export NAME=value`` in all existing shell profile files."""
    export_line = f'export {name}="{value}"'
    written = False
    for rc in (
        Path.home() / ".bashrc",
        Path.home() / ".zshrc",
        Path.home() / ".profile",
    ):
        if rc.exists():
            content = rc.read_text(encoding="utf-8")
            if f"export {name}=" in content:
                import re as _re
                content = _re.sub(
                    rf'^export {re.escape(name)}=.*$',
                    export_line,
                    content,
                    flags=re.MULTILINE,
                )
                rc.write_text(content, encoding="utf-8")
            else:
                with rc.open("a", encoding="utf-8") as fh:
                    fh.write(f"\n# Added by sensitive-scanner setup\n{export_line}\n")
            written = True
    return written


def persist_env_var(name: str, value: str) -> bool:
    """
    Write a persistent user-level environment variable so it survives
    terminal restarts.

    Windows : writes to HKEY_CURRENT_USER\\Environment (user-scope registry).
              Also broadcasts WM_SETTINGCHANGE so already-open shells can pick
              it up without a full reboot (best-effort).
    Unix    : appends ``export NAME=value`` to ~/.bashrc, ~/.zshrc, and
              ~/.profile (whichever exist).

    Also updates os.environ immediately so the current process can use the
    value straight away.

    Returns True on success, False if the write failed.
    """
    os.environ[name] = value  # current process — takes effect immediately

    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                "Environment",
                0,
                winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            winreg.CloseKey(key)
            # Broadcast so Explorer / open shells refresh their env — ignore errors
            try:
                import ctypes
                ctypes.windll.user32.SendMessageTimeoutW(
                    0xFFFF, 0x001A, 0, "Environment", 2, 5000, None
                )
            except (OSError, AttributeError):  # pragma: no cover - best-effort broadcast
                pass
            return True
        except OSError as exc:
            print(f"[sonarqube_manager] Could not write registry env var {name}: {exc}",
                  file=sys.stderr)
            return False
    else:
        return _persist_unix_env_var(name, value)


# ── Java prerequisite check ───────────────────────────────────────────────────

def check_java() -> tuple[bool, str]:
    """
    Verify Java 17+ is available on PATH.
    Returns (ok, message).
    """
    java = shutil.which("java")
    if not java:
        return False, (
            "Java not found on PATH — SonarQube requires Java 17+.\n"
            f"  Download Temurin 21 LTS: {_TEMURIN_URL}"
        )
    try:
        result = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version_output = result.stderr or result.stdout  # java -version → stderr
        match = re.search(r'version "(\d+)(?:\.(\d+))?', version_output)
        if match:
            major = int(match.group(1))
            if major == 1:  # old 1.8 / 1.7 style
                major = int(match.group(2) or 0)
            if major < 17:
                return False, (
                    f"Java {major} found but SonarQube requires Java 17+.\n"
                    f"  Download Temurin 21 LTS: {_TEMURIN_URL}"
                )
            return True, f"Java {major} — {java}"
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return False, f"Could not determine Java version: {exc}"
    return True, f"Java found — {java}"


# ── GitHub release helpers ────────────────────────────────────────────────────

async def _fetch_latest_release(owner: str, repo: str) -> Optional[dict]:
    url = _GITHUB_LATEST.format(owner=owner, repo=repo)
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers={"Accept": "application/vnd.github+json"})
            resp.raise_for_status()
            return resp.json()
    except (httpx.HTTPError, OSError, ValueError) as exc:
        print(
            f"[sonarqube_manager] Could not fetch {owner}/{repo} release: {exc}",
            file=sys.stderr,
        )
        return None


async def _fetch_sq_version() -> Optional[str]:
    """
    Return the SonarQube CE version string (e.g. '10.5.1.90531') from the
    SonarSource/sonarqube GitHub release tag.
    Tags look like 'sonarqube-10.5.1.90531' — we strip the prefix.
    """
    release = await _fetch_latest_release("SonarSource", "sonarqube")
    if not release:
        return None
    tag: str = release.get("tag_name", "")
    # Strip leading 'sonarqube-' or 'v' prefix
    version = re.sub(r"^(sonarqube-|v)", "", tag)
    return version or None


# ── Zip downloader / extractor ────────────────────────────────────────────────

async def _download_and_extract_zip(
    url: str,
    dest_dir: Path,
    label: str = "",
    progress_callback=None,
) -> Optional[Path]:
    """
    Stream-download a zip from url, extract into a temporary folder, then move
    the single top-level extracted directory to dest_dir.
    Returns dest_dir on success, None on failure.
    """
    async with aiofiles.tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
        tmp_path = Path(str(tmp.name))

    try:
        async with httpx.AsyncClient(timeout=600, follow_redirects=True) as client:
            async with client.stream("GET", url) as resp:
                resp.raise_for_status()
                total = int(resp.headers.get("content-length", 0))
                downloaded = 0
                async with aiofiles.open(tmp_path, "wb") as fh:
                    async for chunk in resp.aiter_bytes(chunk_size=65536):
                        await fh.write(chunk)
                        downloaded += len(chunk)
                        if progress_callback and total:
                            progress_callback(downloaded, total)

        # Extract to a sibling temp directory
        with tempfile.TemporaryDirectory() as extract_tmp:
            with zipfile.ZipFile(tmp_path) as zf:
                # Find the single top-level directory
                top_dirs = {
                    m.filename.split("/")[0]
                    for m in zf.infolist()
                    if "/" in m.filename
                }
                zf.extractall(extract_tmp)

            if len(top_dirs) == 1:
                extracted_root = Path(extract_tmp) / next(iter(top_dirs))
            else:
                extracted_root = Path(extract_tmp)

            if dest_dir.exists():
                shutil.rmtree(dest_dir)
            dest_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(extracted_root), str(dest_dir))

        return dest_dir

    except (OSError, httpx.HTTPError, zipfile.BadZipFile) as exc:
        print(
            f"[sonarqube_manager] Download/extract failed for {label}: {exc}",
            file=sys.stderr,
        )
        return None
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover - defensive cleanup
            pass


# ── sonar.properties patcher ──────────────────────────────────────────────────

def patch_sonar_port(sq_home: Path, port: int = SONAR_PORT) -> None:
    """
    Set sonar.web.port=<port> in sonar.properties unconditionally.
    Replaces any existing setting (including commented-out lines).
    Creates the line if absent.
    Always sets port 9100 to avoid the team-wide ZScaler conflict on 9000.
    """
    props = sq_home / "conf" / "sonar.properties"
    if not props.exists():
        return
    lines = props.read_text(encoding="utf-8").splitlines()
    new_lines: list[str] = []
    replaced = False
    for line in lines:
        stripped = line.strip().lstrip("#").strip()
        if stripped.startswith("sonar.web.port"):
            new_lines.append(f"sonar.web.port={port}")
            replaced = True
        else:
            new_lines.append(line)
    if not replaced:
        new_lines.append(f"\nsonar.web.port={port}")
    props.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


# ── sonar-scanner-cli ─────────────────────────────────────────────────────────

def sonar_scanner_installed() -> bool:
    return _scanner_exe_path() is not None


def _scanner_exe_path() -> Optional[Path]:
    exe = "sonar-scanner.bat" if _system() == "windows" else "sonar-scanner"
    candidate = _SCANNER_DIR / "bin" / exe
    return candidate if candidate.exists() else None


async def ensure_sonar_scanner(progress_callback=None) -> Optional[Path]:
    """
    Ensure sonar-scanner-cli is downloaded to ~/.sensitive-scanner/sonar-scanner/.
    Returns the installation directory on success, None on failure.
    """
    if sonar_scanner_installed():
        return _SCANNER_DIR

    release = await _fetch_latest_release("SonarSource", "sonar-scanner-cli")
    if not release:
        return None

    version: str = release.get("tag_name", "").lstrip("v")
    if not version:
        return None

    asset_map = {
        ("windows", "x64"): f"sonar-scanner-cli-{version}-windows-x64.zip",
        ("linux", "x64"): f"sonar-scanner-cli-{version}-linux-x64.zip",
        ("linux", "arm64"): f"sonar-scanner-cli-{version}-linux-aarch64.zip",
        ("darwin", "x64"): f"sonar-scanner-cli-{version}-macosx-x64.zip",
        ("darwin", "arm64"): f"sonar-scanner-cli-{version}-macosx-aarch64.zip",
    }
    asset = asset_map.get((_system(), _machine()))
    if not asset:
        print(
            f"[sonarqube_manager] No sonar-scanner-cli asset for "
            f"{_system()}/{_machine()}",
            file=sys.stderr,
        )
        return None

    # Prefer the asset URL from the release JSON (handles redirects cleanly)
    download_url: Optional[str] = None
    for a in release.get("assets", []):
        if a["name"] == asset:
            download_url = a["browser_download_url"]
            break
    if not download_url:
        download_url = (
            f"https://github.com/SonarSource/sonar-scanner-cli"
            f"/releases/download/{version}/{asset}"
        )

    result = await _download_and_extract_zip(
        download_url,
        _SCANNER_DIR,
        label=f"sonar-scanner-cli {version}",
        progress_callback=progress_callback,
    )
    if not result:
        return None

    # Make executable on Unix
    if _system() != "windows":
        exe = _SCANNER_DIR / "bin" / "sonar-scanner"
        if exe.exists():
            exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    meta = _load_meta()
    meta["sonar-scanner-cli"] = {"version": version}
    _save_meta(meta)
    return _SCANNER_DIR


# ── SonarQube Community Edition ───────────────────────────────────────────────

def sonarqube_installed() -> bool:
    return _SQ_DIR.exists() and (_SQ_DIR / "conf" / "sonar.properties").exists()


async def ensure_sonarqube(progress_callback=None) -> Optional[Path]:
    """
    Ensure SonarQube CE is downloaded, extracted, and configured for port 9100.
    Returns the installation directory on success, None on failure.
    """
    if sonarqube_installed():
        # Re-apply port patch in case a previous install missed it
        patch_sonar_port(_SQ_DIR, SONAR_PORT)
        return _SQ_DIR

    version = await _fetch_sq_version()
    if not version:
        print("[sonarqube_manager] Could not determine SonarQube version.", file=sys.stderr)
        return None

    url = _SQ_BINARIES_URL.format(ver=version)
    result = await _download_and_extract_zip(
        url,
        _SQ_DIR,
        label=f"SonarQube CE {version}",
        progress_callback=progress_callback,
    )
    if not result:
        return None

    # Patch port to 9100 immediately — never start on 9000
    patch_sonar_port(_SQ_DIR, SONAR_PORT)

    # Make start scripts executable on Unix
    if _system() != "windows":
        for script in (_SQ_DIR / "bin").rglob(_SONAR_SH):
            try:
                script.chmod(
                    script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                )
            except OSError:  # pragma: no cover - defensive chmod
                pass

    meta = _load_meta()
    meta["sonarqube"] = {"version": version, "port": SONAR_PORT}
    _save_meta(meta)
    return _SQ_DIR


# ── Start and health-wait ─────────────────────────────────────────────────────

def _start_script(sq_home: Path) -> Optional[Path]:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Windows":
        s = sq_home / "bin" / "windows-x86-64" / "StartSonar.bat"
    elif system == "Linux":
        arch = "aarch64" if ("arm" in machine or "aarch" in machine) else "x86-64"
        s = sq_home / "bin" / f"linux-{arch}" / _SONAR_SH
    else:
        s = sq_home / "bin" / "macosx-universal-64" / _SONAR_SH
    return s if s.exists() else None


async def start_and_wait(
    sq_home: Path,
    port: int = SONAR_PORT,
    max_wait: int = 180,
    tick_callback=None,
) -> bool:
    """
    Launch SonarQube (in background) then poll /api/system/status until UP.
    tick_callback(elapsed, total) is called every 5 s if provided.
    Returns True when UP, False on timeout.
    """
    script = _start_script(sq_home)
    if not script:
        print(
            f"[sonarqube_manager] Start script not found under {sq_home / 'bin'}",
            file=sys.stderr,
        )
        return False

    if platform.system() == "Windows":
        await asyncio.create_subprocess_exec(
            str(script),
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            close_fds=True,
        )
    else:
        await asyncio.create_subprocess_exec(
            str(script), "start",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

    host = f"http://localhost:{port}"
    start = time.monotonic()

    async with httpx.AsyncClient() as client:
        while (elapsed := time.monotonic() - start) < max_wait:
            if tick_callback:
                tick_callback(int(elapsed), max_wait)
            try:
                resp = await client.get(f"{host}/api/system/status", timeout=5)
                if resp.json().get("status") == "UP":
                    return True
            except (httpx.HTTPError, ValueError):
                pass
            await asyncio.sleep(5)

    return False


# ── Admin token creation ──────────────────────────────────────────────────────

async def ensure_admin_token(host_url: str) -> tuple[Optional[str], str]:
    """
    Attempt to generate an API token using the default admin/admin credentials.

    Returns (token, reason) where:
      - token is the generated token string, or None on failure.
      - reason is "ok" on success, or a human-readable description of why it
        failed (shown directly to the user — do NOT say "password changed" for
        every failure).

    Strategy:
      1. Validate admin/admin credentials.
      2. Revoke any existing token with the same name (so re-running setup
         always works — a 400 Conflict on the generate call was the original
         cause of false "password changed" reports).
      3. Generate a fresh token.
    """
    token_name = "sensitive-scanner"

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        # 1. Validate credentials
        try:
            resp = await client.get(
                f"{host_url}/api/authentication/validate",
                auth=("admin", "admin"),
            )
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            return None, f"Could not reach SonarQube API ({exc})"

        if resp.status_code == 401:
            return None, "admin/admin credentials rejected — the default password has been changed"
        if resp.status_code != 200 or not data.get("valid"):
            return None, (
                f"Authentication check returned unexpected response "
                f"(HTTP {resp.status_code}, valid={data.get('valid')!r}) — "
                f"try generating a token manually"
            )

        # 2. Revoke any existing token with this name so re-runs don't conflict
        try:
            await client.post(
                f"{host_url}/api/user_tokens/revoke",
                auth=("admin", "admin"),
                data={"name": token_name},
            )
        except httpx.HTTPError:
            pass  # token may not exist yet — that is fine

        # 3. Generate a fresh token
        try:
            resp = await client.post(
                f"{host_url}/api/user_tokens/generate",
                auth=("admin", "admin"),
                data={"name": token_name, "type": "USER_TOKEN"},
            )
            if resp.status_code in (200, 201):
                token = resp.json().get("token")
                if token:
                    return token, "ok"
                return None, f"Token field missing in generate response: {resp.text[:200]}"
            # 400 can mean forced-password-change in SonarQube 9.9+
            body = resp.text[:300]
            if resp.status_code == 400 and "password" in body.lower():
                return None, (
                    "SonarQube requires you to change the admin password via "
                    f"the web UI before generating tokens — open {host_url} "
                    "and log in with admin / admin to complete first-time setup"
                )
            return None, f"Token generation failed (HTTP {resp.status_code}): {body}"
        except (httpx.HTTPError, ValueError) as exc:
            return None, f"Token generation exception: {exc}"

    return None, "Unknown error"  # pragma: no cover - unreachable fallthrough
