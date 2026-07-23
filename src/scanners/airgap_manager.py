"""
airgap_manager.py
-----------------
Create and install offline installation bundles for sensitive-scanner.

Supports air-gapped environments where internet access is unavailable by:
  • Downloading all required Python wheels and scanner binaries into a zip bundle.
  • Installing from that bundle on a machine with no outbound internet access.

Key functions
  create_bundle(repo_root, output_dir, ...)  — build the zip
  install_bundle(bundle_path, repo_root, ...) — unpack and install
"""
from __future__ import annotations

import asyncio
import importlib.metadata
import json
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import tomllib
import zipfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────────────

AIRGAP_PREFIX = "sensitive-scanner-airgap"
AIRGAP_OPTIONAL_GROUPS: tuple[str, ...] = ("semgrep", "spacy")
SPACY_MODEL_DIST = "en-core-web-sm"
SPACY_MODEL_MODULE = "en_core_web_sm"

# ── Pre-download helpers (run concurrently inside create_bundle) ─────────────


async def _prefetch_step(
    label: str,
    coro: object,
    print_fn: Callable[[str], None],
) -> None:
    """Await one async download coroutine, logging its start and outcome."""
    print_fn(f"[dim]  \u2192 {label} starting...[/dim]")
    try:
        await coro  # type: ignore[misc]
        print_fn(f"[dim]  \u2713 {label} ready[/dim]")
    except Exception as exc:
        print_fn(
            f"[bold yellow]  \u26a0  {label} failed (bundle will continue):[/bold yellow] {exc}"
        )


async def _prefetch_bool_step(
    label: str,
    coro: object,
    print_fn: Callable[[str], None],
) -> tuple[bool, str]:
    """Run *fn* in a thread, logging the start and (bool, str) outcome."""
    print_fn(f"[dim]  \u2192 {label}...[/dim]")
    result: tuple[bool, str] = await coro # type: ignore[misc]
    ok, note = result
    if ok:
        print_fn(f"[dim]  \u2713 {label} {note}[/dim]")
    else:
        print_fn(
            f"[bold yellow]  \u26a0  {label} failed (bundle will continue):[/bold yellow] {note}"
        )
    return result


def _install_semgrep() -> tuple[bool, str]:
    """Run pip install semgrep synchronously. Returns (ok, message)."""
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "semgrep"],
            capture_output=True, text=True, timeout=300,
        )
    except Exception as exc:
        return False, str(exc)
    if r.returncode == 0:
        return True, "ready"
    err = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "pip install failed"
    return False, err


async def _prefetch_wheels(wheel_dir: str, repo_root: str, print_fn: Callable[[str], None]) -> tuple[bool, str]:
    return await _prefetch_bool_step("Python wheels", asyncio.to_thread(download_wheels, wheel_dir, repo_root), print_fn=print_fn)

async def _prefetch_spacy(spacy_model_dir: str, print_fn: Callable[[str], None]) -> tuple[bool, str]:
    return await _prefetch_bool_step("spaCy model", asyncio.to_thread(bundle_spacy_model, spacy_model_dir), print_fn=print_fn)

async def _prefetch_semgrep(print_fn: Callable[[str], None]) -> tuple[bool, str]:
    """Install semgrep via pip in a thread, logging its start and outcome."""
    return await _prefetch_bool_step("semgrep", asyncio.to_thread(_install_semgrep), print_fn=print_fn)


# ── Low-level utilities ───────────────────────────────────────────────────────


def bundle_name() -> str:
    """Return a timestamped bundle filename."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{AIRGAP_PREFIX}-{ts}.zip"


def safe_copy(src: Path, dst: Path) -> bool:
    """Copy a file or directory if it exists. Returns True when copied."""
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        shutil.copy2(src, dst)
    return True


def base_requirements(repo_root: Path) -> list[str]:
    """Read pinned base package specs from pyproject.toml for offline bundling."""
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.exists():
        return []
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    values = data.get("project", {}).get("dependencies", [])
    if not isinstance(values, list):
        return []
    # Do not bundle pip itself as an application dependency.
    return [str(v) for v in values if not str(v).lower().startswith("pip")]


def optional_requirements(repo_root: Path) -> list[str]:
    """Read pinned optional package specs from pyproject.toml for offline bundling."""
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.exists():
        return []
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    groups = data.get("project", {}).get("optional-dependencies", {})
    requirements: list[str] = []
    for group in AIRGAP_OPTIONAL_GROUPS:
        values = groups.get(group, [])
        if isinstance(values, list):
            requirements.extend(str(v) for v in values)
    return requirements


def download_wheels(dest: Path, repo_root: Path) -> tuple[bool, str]:
    """Download dependency wheels into *dest* using pip download."""
    base_reqs = base_requirements(repo_root)
    opt_reqs = optional_requirements(repo_root)
    direct_reqs = [*base_reqs, *opt_reqs]
    if not direct_reqs:
        return False, "No project requirements found in pyproject.toml"
    cmd = [
        sys.executable, "-m", "pip", "download",
        "--only-binary=:all:", "-d", str(dest),
        *direct_reqs,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(repo_root), timeout=1200)
    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip() or "pip download failed"
        return False, err.splitlines()[-1]
    return True, "downloaded"


def distribution_entries(dist_name: str) -> list[Path]:
    """Return top-level installed filesystem entries for a distribution."""
    try:
        dist = importlib.metadata.distribution(dist_name)
    except importlib.metadata.PackageNotFoundError:
        return []
    entries: dict[str, Path] = {}
    for file in dist.files or []:
        if not file.parts:
            continue
        top_level = file.parts[0]
        entries.setdefault(top_level, Path(dist.locate_file(top_level)).resolve())
    return sorted(entries.values(), key=lambda p: p.name)


def restore_site_packages(bundle_dir: Path) -> int:
    """Restore packaged site-packages entries from the bundle into the active environment."""
    if not bundle_dir.exists():
        return 0
    purelib = Path(sysconfig.get_paths()["purelib"])
    restored = 0
    for entry in bundle_dir.iterdir():
        if safe_copy(entry, purelib / entry.name):
            restored += 1
    return restored


def _ensure_spacy_for_bundle() -> tuple[bool, str]:
    """Ensure spaCy and its en_core_web_sm model are available. Returns (ok, message)."""
    try:
        import spacy  # type: ignore  # noqa: F401
    except ImportError:
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "spacy"],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            return False, "spaCy pip install failed"

    try:
        import spacy as _spacy  # type: ignore
        _spacy.load(SPACY_MODEL_MODULE)
    except OSError:
        r = subprocess.run(
            [sys.executable, "-m", "spacy", "download", SPACY_MODEL_MODULE],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            return False, "en_core_web_sm download failed"

    return True, "ready"


def bundle_spacy_model(dest: Path) -> tuple[bool, str]:
    """Ensure the spaCy model is installed and copy it into the bundle staging area."""
    ok, note = _ensure_spacy_for_bundle()
    if not ok:
        return False, note

    entries = distribution_entries(SPACY_MODEL_DIST)
    if not entries:
        return False, "model not installed"

    dest.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        safe_copy(entry, dest / entry.name)
    return True, "bundled"


# ── High-level bundle / install ───────────────────────────────────────────────


def create_bundle(
    repo_root: Path,
    output_dir: Path,
    *,
    console: object = None,
    non_interactive: bool = False,
) -> Path:
    """Create an offline bundle with downloaded scanner assets and Python wheels.

    Args:
        repo_root:        Root of the repository (contains pyproject.toml).
        output_dir:       Directory to write the bundle zip into.
        console:          Optional Rich Console for progress messages.
        non_interactive:  Suppress the 'preparing' preamble when True.

    Returns:
        Path to the created bundle zip.

    Raises:
        RuntimeError: When wheel download or spaCy bundling fails.
    """
    from scanners.binary_manager import BIN_DIR, META_FILE, ensure_binary
    from scanners.sonarqube_manager import (
        _SCANNER_DIR, _SQ_DIR,
        ensure_sonar_scanner, ensure_sonarqube,
    )

    def _print(msg: str) -> None:
        if console is not None:
            console.print(msg)  # type: ignore[union-attr]
        else:
            print(msg)

    if not non_interactive:
        _print("\n[dim]Preparing components for offline bundle...[/dim]")

    out_zip = output_dir / bundle_name()
    with tempfile.TemporaryDirectory() as tmp_dir:
        stage = Path(tmp_dir) / "bundle"
        stage.mkdir(parents=True, exist_ok=True)

        wheel_dir = stage / "wheels"
        wheel_dir.mkdir(parents=True, exist_ok=True)
        spacy_model_dir = stage / "site-packages"

        # Download all components concurrently (best-effort; logged but non-fatal for binaries)
        async def _run_prefetch() -> tuple[bool, str]:

            results = await asyncio.gather(
                _prefetch_step("gitleaks", ensure_binary("gitleaks"), _print),
                _prefetch_step("sonar-scanner-cli", ensure_sonar_scanner(), _print),
                _prefetch_step("sonarqube", ensure_sonarqube(), _print),
                _prefetch_semgrep(_print),
                _prefetch_wheels(wheel_dir, repo_root, _print),
                _prefetch_spacy(spacy_model_dir, _print),
            )
            return results[4]

        ok, wheel_note = asyncio.run(_run_prefetch())
        if not ok:
            raise RuntimeError(f"Air-gap wheel download failed: {wheel_note}")

        _print("[dim]  → copying scanner assets...[/dim]")
        local_store = stage / ".sensitive-scanner"
        copied = []
        if safe_copy(BIN_DIR, local_store / "bin"):
            copied.append("bin")
        if safe_copy(_SCANNER_DIR, local_store / "sonar-scanner"):
            copied.append("sonar-scanner")
        if safe_copy(_SQ_DIR, local_store / "sonarqube"):
            copied.append("sonarqube")
        if safe_copy(META_FILE, local_store / "meta.json"):
            copied.append("meta.json")
        _print(f"[dim]  ✓ assets copied: {', '.join(copied) or 'none'}[/dim]")

        manifest = {
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "source": str(repo_root),
            "copied_components": copied,
            "base_requirements": base_requirements(repo_root),
            "optional_requirements": optional_requirements(repo_root),
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        _print("[dim]  → writing bundle zip...[/dim]")
        with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for p in stage.rglob("*"):
                if p.is_file():
                    zf.write(p, p.relative_to(stage))

    _print(f"\n[bold green]Air-gap bundle created:[/bold green] {out_zip.resolve()}")
    _print("[dim]Transfer this zip to the target machine and run setup --airgap-bundle <zip>.[/dim]")
    return out_zip


def install_bundle(bundle_path: Path, repo_root: Path, *, console: object = None) -> None:
    """Install scanner assets and Python packages from a local offline bundle zip.

    Args:
        bundle_path: Path to the bundle zip produced by :func:`create_bundle`.
        repo_root:   Repository root used as cwd for the pip install step.
        console:     Optional Rich Console for progress messages.

    Raises:
        FileNotFoundError: When *bundle_path* does not exist or is not a file.
        RuntimeError:      When the offline pip install step fails.
    """
    bundle = Path(bundle_path).resolve()
    if not bundle.exists() or not bundle.is_file():
        raise FileNotFoundError(f"Bundle not found: {bundle}")

    def _print(msg: str) -> None:
        if console is not None:
            console.print(msg)  # type: ignore[union-attr]
        else:
            print(msg)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        with zipfile.ZipFile(bundle) as zf:
            zf.extractall(tmp)

        manifest_path = tmp / "manifest.json"
        base_reqs: list[str] = []
        optional_reqs: list[str] = []
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            base_reqs = [str(req) for req in manifest.get("base_requirements", [])]
            optional_reqs = [str(req) for req in manifest.get("optional_requirements", [])]

        src_store = tmp / ".sensitive-scanner"
        dst_store = Path.home() / ".sensitive-scanner"
        copied_any = False
        if src_store.exists():
            for p in src_store.iterdir():
                copied_any |= safe_copy(p, dst_store / p.name)
        else:
            _print("[bold yellow]Warning:[/bold yellow] Bundle has no .sensitive-scanner payload.")

        wheels = tmp / "wheels"
        direct_reqs = [*base_reqs, *optional_reqs]
        if wheels.exists() and direct_reqs:
            cmd = [
                sys.executable, "-m", "pip", "install",
                "--no-index", "--find-links", str(wheels),
                *direct_reqs,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(repo_root), timeout=1200)
            if proc.returncode != 0:
                err = proc.stderr.strip() or proc.stdout.strip() or "offline pip install failed"
                raise RuntimeError(f"Offline package install failed: {err.splitlines()[-1]}")
        else:
            _print("[bold yellow]Warning:[/bold yellow] Wheels or bundle requirements missing; skipped pip install.")

        restored = restore_site_packages(tmp / "site-packages")
        if restored == 0:
            _print("[bold yellow]Warning:[/bold yellow] No bundled site-packages payload restored.")

    if copied_any:
        _print(
            f"\n[bold green]Installed scanner assets from bundle into[/bold green] "
            f"{Path.home() / '.sensitive-scanner'}"
        )
    _print("[bold green]Air-gap bundle install complete.[/bold green]")
