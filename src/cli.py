"""
sensitive-scanner  —  standalone CLI
--------------------------------------
Usage examples:

  sensitive-scanner scan ./my-project
  sensitive-scanner scan ./my-project --format markdown --output report.md
  sensitive-scanner scan ./my-project --format html    --output report.html
  sensitive-scanner scan ./my-project --scanners gitleaks,pii
  sensitive-scanner scan ./my-project --history
  sensitive-scanner status
  sensitive-scanner report --format markdown
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import yaml

# Ensure project root is importable when run directly (python cli.py ...)
_ROOT = Path(__file__).parent.resolve()
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from models.finding import ScanConfig
from models.report import Report
from config_loader import parse_suppress_file, suppress_findings
from reporting.console import render_console
from reporting.html_reporter import render_html
from reporting.json_reporter import render_json
from reporting.markdown_reporter import render_markdown
from scanners.orchestrator import load_cached_report, run_scan

app = typer.Typer(
    name="sensitive-scanner",
    help="Scan codebases for secrets, API keys, and PII.",
    add_completion=False,
    pretty_exceptions_show_locals=False,
)

_console = Console()

# ── Helpers ───────────────────────────────────────────────────────────────────

_FORMAT_RENDERERS = {
    "console": render_console,
    "markdown": render_markdown,
    "html": render_html,
    "json": render_json,
}

_VALID_SCANNERS = {"gitleaks", "semgrep", "presidio", "sonarqube"}
_SUPPRESS_FILE = "suppress.txt"
_LABEL_SONARQUBE_CE = "SonarQube CE"
_LABEL_SONARQUBE_START = "SonarQube start"
_VALID_FORMATS = set(_FORMAT_RENDERERS)


_FORMAT_EXTENSIONS = {
    "json": ".json",
    "markdown": ".md",
    "html": ".html",
    "console": ".txt",
}


def _render_and_write(report: Report, fmt: str, output: Path | None) -> None:
    renderer = _FORMAT_RENDERERS[fmt]
    content = renderer(report)

    if output:
        output.write_text(content, encoding="utf-8")
        _console.print(f"\n[bold green]Report saved to[/bold green] {output.resolve()}")
    else:
        if fmt == "console":
            # Rich markup — print via Console so colours render
            _console.print(content)
        else:
            print(content)


def _render_and_write_per_file(report: Report, fmt: str, output_dir: Path) -> int:
    """Write one report file per scanned source file. Returns the count of files written."""
    from collections import defaultdict

    ext = _FORMAT_EXTENSIONS.get(fmt, ".txt")
    renderer = _FORMAT_RENDERERS[fmt]

    by_file: dict[str, list] = defaultdict(list)
    for finding in report.findings:
        by_file[finding.file].append(finding)

    if not by_file:
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for file_path, findings in sorted(by_file.items()):
        file_report = report.model_copy(update={"findings": findings})
        file_report.build_summary()
        file_report.summary.files_scanned = 1
        file_report.summary.files_skipped = 0
        file_report.summary.lines_scanned = report.summary.lines_scanned  # whole-scan total; per-file not tracked
        file_report.summary.lines_skipped = report.summary.lines_skipped
        content = renderer(file_report)

        # Mirror the scanned relative path: src/config.py -> output_dir/src/config.py.json
        out_path = output_dir / (file_path + ext)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")
        written += 1

    return written


def _validate_path(path: Path) -> Path:
    path = path.resolve()
    if not path.exists():
        _console.print(f"[bold red]Error:[/bold red] Path does not exist: {path}")
        raise typer.Exit(code=1)
    if not path.is_dir():
        _console.print(f"[bold red]Error:[/bold red] Path is not a directory: {path}")
        raise typer.Exit(code=1)
    return path


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        help="Directory to scan.",
        exists=False,  # validated manually for nicer error messages
        file_okay=False,
    ),
    scanners: str = typer.Option(
        None,
        "--scanners", "-s",
        help=(
            "Comma-separated list of scanners to run. "
            "Available: gitleaks, semgrep, pii, sonarqube. "
            "Defaults to all available."
        ),
    ),
    fmt: str = typer.Option(   # noqa: A002
        "console",
        "--format", "-f",
        help="Output format: console (default), markdown, html, json.",
    ),
    output: Path = typer.Option(
        None,
        "--output", "-o",
        help="Write report to this file instead of stdout.",
    ),
    project_name: str = typer.Option(
        None,
        "--project", "-p",
        help="Project name used in the report header and SonarQube project key.",
    ),
    history: bool = typer.Option(
        False,
        "--history",
        help="Include git history in the scan (Gitleaks git mode).",
    ),
    fail_on: str = typer.Option(
        None,
        "--fail-on",
        help=(
            "Exit with code 2 if any finding at or above this severity is found. "
            "Values: critical, high, medium, low."
        ),
    ),
    exclude: str = typer.Option(
        None,
        "--exclude", "-e",
        help=(
            "Comma-separated additional folder names to exclude (e.g. 'coverage,docs'). "
            "Added on top of the built-in defaults (.git, .vs, node_modules, etc.)."
        ),
    ),
    show_secrets: bool = typer.Option(
        False,
        "--show-secrets",
        help="Expose the full matched value in the report instead of redacting it.",
    ),
    show_confidence: bool = typer.Option(
        False,
        "--show-confidence",
        help="Add a Confidence column to the HTML report showing how certain each detection is (0–100%).",
    ),
    skip_comments: bool = typer.Option(
        False,
        "--skip-comments",
        help="Ignore code comments when scanning (lines/blocks starting with //, #, <!-- or /* ... */).",
    ),
    suppress: str = typer.Option(
        None,
        "--suppress",
        help=(
            "Comma-separated rule IDs to suppress from results "
            "(e.g. 'secrets:S6706,python:S1192'). "
            "Use the Rule column in the output to find IDs."
        ),
    ),
    config_file: Path = typer.Option(
        None,
        "--config", "-c",
        help=(
            "Path to a YAML config file. Defaults to sensitive-scanner.yaml in the "
            "scan directory if present. CLI flags override config file values."
        ),
    ),
    per_file: bool = typer.Option(
        False,
        "--per-file",
        help="Write one report file per scanned source file instead of a single combined report.",
    ),
    output_dir: Path = typer.Option(
        None,
        "--output-dir",
        help=(
            "Directory to write per-file reports into (implies --per-file). "
            "Defaults to './scan-reports' when --per-file is used without --output-dir."
        ),
    ),
    session_file: Path = typer.Option(
        None,
        "--session",
        help=(
            "Path to an obfuscation review session JSON file (produced by the "
            "'obfuscate' command).  When provided with --format html, an "
            "'Obfuscation' column is added to the report showing the decision "
            "(approved / skipped / manual / pending) for each finding."
        ),
    ),
) -> None:
    """Scan a directory for secrets, API keys, and PII."""
    target = _validate_path(path)

    # Parse scanners
    scanner_list: list[str] | None = None
    if scanners:
        scanner_list = [s.strip().lower() for s in scanners.split(",")]
        unknown = set(scanner_list) - _VALID_SCANNERS
        if unknown:
            _console.print(f"[bold red]Unknown scanner(s):[/bold red] {', '.join(unknown)}")
            _console.print(f"Valid options: {', '.join(sorted(_VALID_SCANNERS))}")
            raise typer.Exit(code=1)

    # Validate format
    if fmt not in _VALID_FORMATS:
        _console.print(f"[bold red]Unknown format:[/bold red] {fmt!r}")
        _console.print(f"Valid options: {', '.join(sorted(_VALID_FORMATS))}")
        raise typer.Exit(code=1)

    from models.finding import _DEFAULT_EXCLUDE

    # ── Load YAML config file (auto-discover or explicit --config) ────────
    _cfg: dict = {}
    _cfg_path = config_file or target / "sensitive-scanner.yaml"
    if _cfg_path and Path(_cfg_path).exists():
        try:
            with open(_cfg_path, encoding="utf-8") as _f:
                _cfg = yaml.safe_load(_f) or {}
            _console.print(f"[dim]Using config: {Path(_cfg_path).resolve()}[/dim]")
        except Exception as _e:
            _console.print(f"[bold yellow]Warning:[/bold yellow] Could not read config file: {_e}")

    # Merge config file values — CLI flags take precedence (None = not supplied)
    if scanners is None and _cfg.get("scanners"):
        scanners = ",".join(_cfg["scanners"]) if isinstance(_cfg["scanners"], list) else str(_cfg["scanners"])
    if fmt == "console" and _cfg.get("format"):
        fmt = _cfg["format"]
    if output is None and _cfg.get("output"):
        output = Path(_cfg["output"])
    if project_name is None and _cfg.get("project_name"):
        project_name = _cfg["project_name"]
    if not history and _cfg.get("include_git_history"):
        history = bool(_cfg["include_git_history"])
    if fail_on is None and _cfg.get("fail_on"):
        fail_on = _cfg["fail_on"]
    if not show_secrets and _cfg.get("show_secrets"):
        show_secrets = bool(_cfg["show_secrets"])
    if not skip_comments and _cfg.get("skip_comments"):
        skip_comments = bool(_cfg["skip_comments"])
    if suppress is None and _cfg.get("suppress"):
        _sup = _cfg["suppress"]
        suppress = ",".join(_sup) if isinstance(_sup, list) else str(_sup)

    # ── Load suppress files (global + per-scanner) ────────────────────────
    _persistent_suppress: set[str] = set()
    _suppress_by_scanner: dict[str, list[str]] = {}

    def _merge_suppress(path: Path) -> None:
        if not path.exists():
            return
        g, per = parse_suppress_file(path)
        _persistent_suppress.update(g)
        for scanner, rules in per.items():
            _suppress_by_scanner.setdefault(scanner, []).extend(rules)

    _merge_suppress(_ROOT / "config" / _SUPPRESS_FILE)   # global install-level
    _merge_suppress(target / _SUPPRESS_FILE)              # per-project

    # Per-scanner rules from sensitive-scanner.yaml suppress_by_scanner key
    _cfg_sbs = _cfg.get("suppress_by_scanner", {})
    if isinstance(_cfg_sbs, dict):
        for _sc, _rules in _cfg_sbs.items():
            if isinstance(_rules, list):
                _suppress_by_scanner.setdefault(_sc, []).extend(str(r) for r in _rules)

    # ── Parse exclusions ──────────────────────────────────────────────────
    # An entry is a "glob pattern" if it contains * ? [ or a path separator.
    # Otherwise it is treated as a plain directory name (matched on path parts).
    def _is_pattern(s: str) -> bool:
        return any(c in s for c in ("*", "?", "[", "/", "\\"))

    def _add_entry(entry: str) -> None:
        """Route a raw entry to dir-names, glob-patterns, or excluded files."""
        entry = entry.replace("\\", "/")
        if _is_pattern(entry):
            extra_patterns.append(entry)
        elif "." in entry.split("/")[-1] and "/" not in entry:
            # Plain filename with an extension (e.g. report.html) — exclude as a file
            excluded_files.append(entry)
        else:
            extra_dir_excludes.append(entry)

    extra_dir_excludes: list[str] = []
    extra_patterns: list[str] = []
    excluded_files: list[str] = []

    # Pull exclude entries from the config file
    _cfg_exc = _cfg.get("exclude", {})
    if isinstance(_cfg_exc, dict):
        for _d in _cfg_exc.get("directories", []):
            extra_dir_excludes.append(str(_d))
        for _p in _cfg_exc.get("patterns", []):
            extra_patterns.append(str(_p).replace("\\", "/"))
        for _fi in _cfg_exc.get("files", []):
            excluded_files.append(str(_fi).replace("\\", "/"))

    # Load .scannerignore from the scan target (if present)
    ignore_file = target / ".scannerignore"
    if ignore_file.exists():
        _console.print(f"[dim]Using .scannerignore: {ignore_file.resolve()}[/dim]")
        for raw in ignore_file.read_text(encoding="utf-8").splitlines():
            entry = raw.split("#", 1)[0].strip()
            if not entry:
                continue
            _add_entry(entry)
    else:
        _console.print(f"[dim]No .scannerignore found at {ignore_file.resolve()}[/dim]")

    # Parse --exclude flag (supports both dir names and glob patterns)
    if exclude:
        for entry in (x.strip() for x in exclude.split(",") if x.strip()):
            _add_entry(entry)

    # If --output is inside the scan directory, exclude it automatically
    if output:
        try:
            rel = output.resolve().relative_to(target)
            excluded_files.append(str(rel))
        except ValueError:
            pass  # output is outside the scan root — no action needed

    # Auto-exclude any previously generated PII-Screener report files sitting
    # in the scan root (e.g. combined_pii_report.html left over from a prior run).
    _REPORT_SUFFIXES = {".html", ".json", ".md"}
    _REPORT_STEMS = {"combined_pii_report", "pii_report", "scan_report", "sensitive_scan_report", "report"}
    for _p in target.iterdir():
        if _p.is_file() and _p.suffix.lower() in _REPORT_SUFFIXES and _p.stem.lower() in _REPORT_STEMS:
            try:
                excluded_files.append(str(_p.relative_to(target)))
            except ValueError:
                pass

    config = ScanConfig(
        path=str(target),
        scanners=scanner_list or ["gitleaks", "semgrep", "presidio", "sonarqube"],
        project_name=project_name or target.name,
        include_git_history=history,
        exclude_paths=list(_DEFAULT_EXCLUDE) + extra_dir_excludes,
        exclude_files=excluded_files,
        exclude_patterns=extra_patterns,
        suppress_by_scanner=_suppress_by_scanner,
        suppress_global=sorted(_persistent_suppress),
        show_secrets=show_secrets,
        skip_comments=skip_comments,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=_console,
    ) as progress:
        progress.add_task(f"Scanning [cyan]{target}[/cyan]...", total=None)
        report = asyncio.run(run_scan(config))

    s = report.summary
    _console.print(
        f"\n[bold]Scan complete[/bold] — "
        f"Total: [bold]{s.total}[/bold]  "
        f"[bold red]Critical: {s.critical}[/bold red]  "
        f"[bold dark_orange]High: {s.high}[/bold dark_orange]  "
        f"[bold yellow]Medium: {s.medium}[/bold yellow]  "
        f"[bold cyan]Low: {s.low}[/bold cyan]"
    )

    suppress_set = {r.strip() for r in suppress.split(",") if r.strip()} if suppress else set()
    suppress_set |= _persistent_suppress

    if suppress_set:
        before = len(report.findings)
        report.findings = suppress_findings(report.findings, suppress_set)
        report.build_summary()
        dropped = before - len(report.findings)
        if dropped:
            _console.print(f"[dim]Suppressed {dropped} finding(s) matching: {', '.join(sorted(suppress_set))}[/dim]")

    if per_file or output_dir is not None:
        _dir = output_dir or Path("scan-reports")
        written = _render_and_write_per_file(report, fmt, _dir)
        if written:
            _console.print(
                f"\n[bold green]Per-file reports written:[/bold green] "
                f"{written} file(s) → {_dir.resolve()}"
            )
        else:
            _console.print("\n[dim]No findings — no per-file reports written.[/dim]")
    elif fmt == "html" and session_file is not None:
        from obfuscation.session import ReviewSession as _ReviewSession
        if not session_file.exists():
            _console.print(
                f"[bold red]Session file not found:[/bold red] {session_file}"
            )
            raise typer.Exit(code=1)
        _session = _ReviewSession.load(session_file)
        content = render_html(report, session=_session, show_confidence=show_confidence)
        if output:
            output.write_text(content, encoding="utf-8")
            _console.print(f"\n[bold green]Report saved to[/bold green] {output.resolve()}")
        else:
            print(content)
    else:
        _render_and_write(report, fmt, output)

    # --fail-on exit code
    if fail_on:
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        threshold = severity_rank.get(fail_on.lower(), 0)
        worst = max(
            (severity_rank.get(f.severity, 0) for f in report.findings),
            default=0,
        )
        if worst >= threshold:
            raise typer.Exit(code=2)


@app.command()
def status() -> None:
    """Show which scanner backends are available and the active tier."""
    import os
    from scanners.binary_manager import SPECS, is_installed
    from scanners.constants import detect_container_runtime
    from scanners.sonarqube_scanner import (
        SonarQubeScanner,
        _find_native_sonarqube,
        _find_sonar_scanner,
    )

    lines: list[str] = []

    # Managed binaries
    for name in SPECS:
        ok = is_installed(name)
        mark = "✅" if ok else "⬇ "
        note = "" if ok else "  (auto-downloaded on first scan)"
        lines.append(f"  {mark} {name}{note}")

    # Semgrep (pip-installed)
    import shutil
    semgrep = shutil.which("semgrep")
    if semgrep:
        lines.append(f"  ✅ semgrep  {semgrep}")
    else:
        lines.append("  ❌ semgrep  not found — run: pip install semgrep")

    # Java + native SonarQube
    sq_home = _find_native_sonarqube()
    java = shutil.which("java")
    lines.append("")
    if sq_home and java:
        lines.append(f"  ✅ SonarQube (native)  {sq_home}")
        sc = _find_sonar_scanner()
        lines.append(f"  {'✅' if sc else '⚠ '} sonar-scanner  {sc or 'not found'}")
    elif sq_home:
        lines.append(f"  ⚠  SonarQube found at {sq_home} but Java not on PATH")
    else:
        lines.append("  ℹ  SonarQube (native)  not installed")

    # Container runtime
    runtime = detect_container_runtime()
    if runtime:
        lines.append(f"  ✅ container runtime  {runtime}")
    else:
        lines.append("  ℹ  Docker / Podman  not found")

    # spaCy
    try:
        import spacy  # type: ignore
        try:
            spacy.load("en_core_web_sm")
            lines.append("  ✅ spaCy NLP  en_core_web_sm loaded")
        except OSError:
            lines.append("  ⚠  spaCy installed but model missing — run: python -m spacy download en_core_web_sm")
    except ImportError:
        lines.append("  ℹ  spaCy NLP  not installed (optional — pip install spacy)")

    # Presidio
    try:
        from presidio_analyzer import AnalyzerEngine  # type: ignore  # noqa: F401
        lines.append("  ✅ Presidio NER  installed (best name/entity detection)")
    except ImportError:
        lines.append("  ℹ  Presidio NER  not installed (optional — pip install presidio-analyzer presidio-anonymizer)")

    # Tier
    tier = 1
    if (sq_home and java) or runtime:
        tier = 2
    if os.environ.get("SONAR_TOKEN") and "sonarcloud.io" in os.environ.get("SONAR_HOST_URL", ""):
        tier = 3

    tier_labels = {
        1: "Gitleaks + Semgrep + PII scanner (no infrastructure required)",
        2: "Tier 1 + SonarQube",
        3: "Tier 2 + SonarCloud",
    }

    _console.print("\n[bold]Scanner Status[/bold]")
    for line in lines:
        _console.print(line)
    _console.print(f"\n[bold]Active tier: {tier}[/bold]  —  {tier_labels[tier]}")
    _console.print("\n[dim]Run [bold]sensitive-scanner setup[/bold] to install missing tools.  Add [bold]--sonarqube[/bold] or [bold]--all[/bold] for full setup.[/dim]")


@app.command()
def setup(
    sonarqube: bool = typer.Option(
        False,
        "--sonarqube",
        help="Auto-download and configure SonarQube Community Edition + sonar-scanner-cli.",
    ),
    spacy_nlp: bool = typer.Option(
        False,
        "--spacy",
        help="Install spaCy and download the en_core_web_sm NLP model.",
    ),
    all_deps: bool = typer.Option(
        False,
        "--all",
        help="Install all optional dependencies (equivalent to --sonarqube --spacy).",
    ),
    check: bool = typer.Option(
        False,
        "--check",
        help="Report component status without installing anything.",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Skip confirmation prompts (for scripted / CI use).",
    ),
) -> None:
    """
    Install and configure sensitive-scanner dependencies.

    \b
    Default (no flags): installs Gitleaks + Semgrep.
    --spacy:            also installs spaCy NLP model for unstructured PII.
    --sonarqube:        also downloads SonarQube CE + sonar-scanner-cli (~550 MB).
    --all:              everything above.
    --check:            report current status without installing anything.
    """
    import subprocess
    import shutil

    from rich.table import Table
    from rich.status import Status

    from scanners.binary_manager import ensure_binary, is_installed
    from scanners.sonarqube_manager import (
        SONAR_PORT,
        check_java,
        ensure_sonar_scanner,
        ensure_sonarqube,
        ensure_admin_token,
        persist_env_var,
        sonar_scanner_installed,
        sonarqube_installed,
        start_and_wait,
        _SQ_DIR,
        _SCANNER_DIR,
        _TEMURIN_URL,
    )
    from scanners.sonarqube_scanner import _find_native_sonarqube

    do_sonarqube = sonarqube or all_deps
    do_spacy = spacy_nlp or all_deps

    _console.print("\n[bold]sensitive-scanner setup[/bold]\n")

    # Ensure base directories exist regardless of flags
    (_SQ_DIR.parent / "bin").mkdir(parents=True, exist_ok=True)

    # ── Results tracking ──────────────────────────────────────────────────────
    results: list[tuple[str, str, str]] = []  # (component, status_emoji, note)

    def _ok(component: str, note: str = "") -> None:
        results.append((component, "[bold green]✅[/bold green]", note))

    def _warn(component: str, note: str = "") -> None:
        results.append((component, "[bold yellow]⚠ [/bold yellow]", note))

    def _fail(component: str, note: str = "") -> None:
        results.append((component, "[bold red]✗ [/bold red]", note))

    def _skip(component: str, note: str = "") -> None:
        results.append((component, "[dim]–[/dim]", note))

    # ── 1. Python version ─────────────────────────────────────────────────────
    import sys as _sys
    v = _sys.version_info
    if v >= (3, 11):
        _ok("Python", f"{v.major}.{v.minor}.{v.micro}")
    else:
        _warn("Python", f"{v.major}.{v.minor} — 3.11+ recommended")

    # ── 2. Gitleaks ───────────────────────────────────────────────────────────
    if check:
        if is_installed("gitleaks"):
            _ok("Gitleaks", "installed")
        else:
            _warn("Gitleaks", "not downloaded (auto-downloads on first scan)")
    else:
        if is_installed("gitleaks"):
            _ok("Gitleaks", "already installed")
        else:
            with Status("Downloading Gitleaks...", console=_console):
                try:
                    path = asyncio.run(ensure_binary("gitleaks"))
                    if path:
                        _ok("Gitleaks", f"downloaded → {path}")
                    else:
                        _warn("Gitleaks", "no binary for this platform (uses system PATH)")
                except Exception as exc:
                    _fail("Gitleaks", f"download failed: {exc}")

    # ── 3. Semgrep ────────────────────────────────────────────────────────────
    semgrep_path = shutil.which("semgrep")
    if semgrep_path:
        _ok("Semgrep", semgrep_path)
    elif check:
        _warn("Semgrep", "not found — run: pip install semgrep")
    else:
        with Status("Installing Semgrep via pip...", console=_console):
            try:
                r = subprocess.run(
                    [_sys.executable, "-m", "pip", "install", "--quiet", "semgrep"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if r.returncode == 0:
                    _ok("Semgrep", "installed")
                else:
                    _fail("Semgrep", r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "pip failed")
            except Exception as exc:
                _fail("Semgrep", str(exc))

    # ── 4. spaCy NLP (optional) ───────────────────────────────────────────────
    if do_spacy:
        spacy_ok = False
        try:
            import spacy as _spacy  # type: ignore
            spacy_ok = True
        except ImportError:
            if check:
                _warn("spaCy", "not installed — run: pip install spacy")
            else:
                with Status("Installing spaCy via pip...", console=_console):
                    try:
                        r = subprocess.run(
                            [_sys.executable, "-m", "pip", "install", "--quiet", "spacy"],
                            capture_output=True, text=True, timeout=300,
                        )
                        spacy_ok = r.returncode == 0
                        if not spacy_ok:
                            _fail("spaCy", "pip install failed")
                    except Exception as exc:
                        _fail("spaCy", str(exc))

        if spacy_ok:
            try:
                import spacy as _spacy  # type: ignore  # re-import after install
                _spacy.load("en_core_web_sm")
                _ok("spaCy", "en_core_web_sm ready")
            except OSError:
                if check:
                    _warn("spaCy", "installed but en_core_web_sm model missing")
                else:
                    with Status("Downloading en_core_web_sm model...", console=_console):
                        try:
                            r = subprocess.run(
                                [_sys.executable, "-m", "spacy", "download", "en_core_web_sm"],
                                capture_output=True, text=True, timeout=300,
                            )
                            if r.returncode == 0:
                                _ok("spaCy", "en_core_web_sm downloaded")
                            else:
                                _fail("spaCy", "model download failed")
                        except Exception as exc:
                            _fail("spaCy", str(exc))
    else:
        try:
            import spacy as _spacy  # type: ignore
            try:
                _spacy.load("en_core_web_sm")
                _ok("spaCy", "en_core_web_sm ready")
            except OSError:
                _warn("spaCy", "model missing — run: sensitive-scanner setup --spacy")
        except ImportError:
            _skip("spaCy", "optional — add --spacy to install")

    # ── 5. SonarQube (optional) ───────────────────────────────────────────────
    if do_sonarqube:
        # 5a. Java prerequisite
        java_ok, java_msg = check_java()
        if not java_ok:
            _fail("Java 17+", java_msg)
            _skip("sonar-scanner-cli", "skipped — Java required")
            _skip(_LABEL_SONARQUBE_CE, "skipped — Java required")
        else:
            _ok("Java 17+", java_msg)

            # 5b. sonar-scanner-cli
            if sonar_scanner_installed():
                _ok("sonar-scanner-cli", f"{_SCANNER_DIR}")
            elif check:
                _warn("sonar-scanner-cli", "not installed")
            else:
                with Status(
                    "Downloading sonar-scanner-cli...", console=_console
                ):
                    try:
                        path = asyncio.run(ensure_sonar_scanner())
                        if path:
                            _ok("sonar-scanner-cli", f"installed → {path}")
                        else:
                            _fail("sonar-scanner-cli", "download failed")
                    except Exception as exc:
                        _fail("sonar-scanner-cli", str(exc))

            # 5c. SonarQube CE
            sq_already = bool(_find_native_sonarqube())
            if sq_already:
                sq_home = _find_native_sonarqube()
                # Ensure port is patched even on pre-existing installs
                if not check:
                    from scanners.sonarqube_manager import patch_sonar_port
                    patch_sonar_port(sq_home)
                _ok(_LABEL_SONARQUBE_CE, f"port {SONAR_PORT} — {sq_home}")
            elif check:
                _warn(_LABEL_SONARQUBE_CE, "not installed")
            else:
                if not non_interactive:
                    _console.print(
                        f"\n  [dim]SonarQube CE is ~500 MB.  Downloading to "
                        f"{_SQ_DIR}[/dim]"
                    )
                with Status(
                    "Downloading SonarQube CE (~500 MB, this may take a few minutes)...",
                    console=_console,
                ):
                    try:
                        path = asyncio.run(ensure_sonarqube())
                        if path:
                            _ok(_LABEL_SONARQUBE_CE, f"port {SONAR_PORT} — {path}")
                        else:
                            _fail(_LABEL_SONARQUBE_CE, "download failed — check internet connection")
                    except Exception as exc:
                        _fail(_LABEL_SONARQUBE_CE, str(exc))

            # 5d. Start SonarQube + token (only when we just installed or on explicit request)
            sq_home = _find_native_sonarqube()
            if sq_home and not check:
                _console.print(
                    f"\n  Starting SonarQube on port {SONAR_PORT} "
                    f"(first start can take ~2 min)..."
                )
                host_url = f"http://localhost:{SONAR_PORT}"
                try:
                    up = asyncio.run(start_and_wait(sq_home, port=SONAR_PORT, timeout=180))
                except Exception as exc:
                    up = False
                    _fail(_LABEL_SONARQUBE_START, str(exc))

                if up:
                    _ok(_LABEL_SONARQUBE_START, f"running at {host_url}")
                    # 5e. Auto-create token
                    try:
                        token, token_reason = asyncio.run(ensure_admin_token(host_url))
                    except Exception as exc:
                        token, token_reason = None, str(exc)

                    if token:
                        # Persist both variables as permanent user env vars
                        tok_ok = persist_env_var("SONAR_TOKEN", token)
                        url_ok = persist_env_var("SONAR_HOST_URL", host_url)
                        env_note = "saved to user environment" if (tok_ok and url_ok) else "shown below — save manually"
                        _ok("Admin token", env_note)
                        _ok("SONAR_HOST_URL", host_url)
                        _console.print(
                            "\n  [bold green]✔ SONAR_TOKEN[/bold green] and "
                            "[bold green]SONAR_HOST_URL[/bold green] have been written "
                            "to your user environment automatically."
                        )
                        _console.print(
                            "  Open a [bold]new[/bold] terminal window for them to "
                            "take effect in future sessions."
                        )
                        _console.print(
                            f"\n  [dim]SONAR_TOKEN=[/dim][bold]{token}[/bold]"
                        )
                        _console.print(
                            f"  [dim](Change the admin password at {host_url} when convenient.)[/dim]"
                        )
                    else:
                        _warn(
                            "Admin token",
                            token_reason,
                        )
                        # Still persist SONAR_HOST_URL even without a token
                        persist_env_var("SONAR_HOST_URL", host_url)
                        _ok("SONAR_HOST_URL", f"{host_url} — saved to user environment")
                        _console.print(
                            f"\n  Generate a token at: "
                            f"[link]{host_url}/account/security[/link]"
                        )
                        _console.print(
                            "  Then run:\n"
                            "  [bold]sensitive-scanner setup --sonarqube[/bold]\n"
                            "  — or set it manually in a new terminal:\n"
                            "  [dim][Environment]::SetEnvironmentVariable"
                            '("SONAR_TOKEN", "<your-token>", "User")[/dim]'
                        )
                else:
                    _warn(_LABEL_SONARQUBE_START, "did not become UP within 3 min — try starting manually")
    else:
        sq_home = _find_native_sonarqube()
        if sq_home:
            _ok(_LABEL_SONARQUBE_CE, f"installed at {sq_home}")
        else:
            _skip(_LABEL_SONARQUBE_CE, "optional — add --sonarqube to auto-download")

    # ── Summary table ─────────────────────────────────────────────────────────
    _console.print()
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Component")
    table.add_column("Status")
    table.add_column("Details")
    for component, emoji, note in results:
        table.add_row(component, emoji, note)
    _console.print(table)

    any_fail = any(r[1].startswith("[bold red]") for r in results)
    if any_fail:
        _console.print(
            "\n[bold yellow]Some components have issues — see above.[/bold yellow]  "
            "Run [bold]sensitive-scanner status[/bold] to re-check."
        )
    else:
        _console.print(
            "\n[bold green]All done.[/bold green]  "
            "Run [bold]sensitive-scanner status[/bold] to verify."
        )


@app.command()
def report(
    fmt: str = typer.Option(
        "console",
        "--format", "-f",
        help="Output format: console (default), markdown, html, json.",
    ),
    output: Path = typer.Option(
        None,
        "--output", "-o",
        help="Write report to this file instead of stdout.",
    ),
    show_confidence: bool = typer.Option(
        False,
        "--show-confidence",
        help="Add a Confidence column to the HTML report (only applies to html format).",
    ),
) -> None:
    """Display or export the report from the last scan (no re-scan)."""
    if fmt not in _VALID_FORMATS:
        _console.print(f"[bold red]Unknown format:[/bold red] {fmt!r}")
        raise typer.Exit(code=1)

    cached = load_cached_report()
    if not cached:
        _console.print("[bold yellow]No cached report found.[/bold yellow] Run [bold]scan[/bold] first.")
        raise typer.Exit(code=1)

    if fmt == "html" and show_confidence:
        from reporting.html_reporter import render_html as _render_html
        content = _render_html(cached, show_confidence=True)
        if output:
            output.write_text(content, encoding="utf-8")
            _console.print(f"\n[bold green]Report saved to[/bold green] {output.resolve()}")
        else:
            print(content)
    else:
        _render_and_write(cached, fmt, output)


# ── obfuscate command ─────────────────────────────────────────────────────────

@app.command()
def obfuscate(
    path: Path = typer.Argument(
        ...,
        help="Directory to scan and obfuscate.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    scanners: str = typer.Option(
        None,
        "--scanners", "-s",
        help="Comma-separated scanners to run (default: all available).",
    ),
    session_file: Path = typer.Option(
        None,
        "--session",
        help=(
            "Path to save / load the review session JSON.  "
            "Defaults to <target>/pii-review-session.json."
        ),
    ),
    apply_session_file: Optional[Path] = typer.Option(
        None,
        "--apply-session",
        help=(
            "Load a specific session file and apply all approved items "
            "without re-scanning or running the TUI."
        ),
    ),
    apply_default: bool = typer.Option(
        False,
        "--apply",
        help=(
            "Apply the session at the default location "
            "(<target>/pii-review-session.json) without re-scanning or TUI.  "
            "Equivalent to --apply-session <target>/pii-review-session.json."
        ),
    ),
    report_path: Path = typer.Option(
        None,
        "--report",
        help="Write an HTML obfuscation report to this path after applying.",
    ),
    backup_dir: Path = typer.Option(
        None,
        "--backup-dir",
        help="Directory for file backups (default: <target>/.pii-backups/<timestamp>).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview replacements without writing any files.",
    ),
    auto_approve_severity: str = typer.Option(
        None,
        "--auto-approve",
        help=(
            "Auto-approve all obfuscatable findings at or above this severity "
            "without showing them in the TUI (critical | high | medium | low)."
        ),
    ),
    show_secrets: bool = typer.Option(
        False,
        "--show-secrets",
        help=(
            "Display the full raw matched value in the TUI instead of the "
            "redacted 'first4****' form.  Useful when reviewing to confirm "
            "whether a finding is a genuine secret."
        ),
    ),
) -> None:
    """Scan a directory for PII/secrets, review findings interactively, and obfuscate them.

    Workflow:

    \b
      1. Scan the target (with show_secrets=True to capture raw values).
      2. Build a review session — binary/archive findings are pre-marked 'manual'.
      3. Interactively approve or skip each finding in the TUI.
      4. Apply approved replacements (with automatic file backups).
      5. Optionally write an HTML report with full obfuscation status.

    Re-run with --apply-session <session.json> to skip the scan and TUI and
    re-apply a previously saved session.
    """
    from datetime import datetime as _dt

    from rich.progress import Progress, SpinnerColumn, TextColumn

    from models.finding import Finding as _Finding, ScanConfig, _DEFAULT_EXCLUDE
    from scanners.orchestrator import run_scan
    from obfuscation.session import ReviewSession
    from obfuscation.engine import apply_session as _apply_session
    from obfuscation.reviewer import run_review

    target = _validate_path(path)
    _ts = _dt.now().strftime("%Y%m%d_%H%M%S")
    _backup_dir   = backup_dir   or (target / ".pii-backups" / _ts)
    _session_path = session_file or (target / "pii-review-session.json")

    # ── Load suppress files (must happen before any early return) ─────────────
    _persistent_suppress: set[str] = set()
    _suppress_by_scanner: dict[str, list[str]] = {}

    def _merge_sup(sup_path: Path) -> None:
        if not sup_path.exists():
            return
        g, per = parse_suppress_file(sup_path)
        _persistent_suppress.update(g)
        for sc, rules in per.items():
            _suppress_by_scanner.setdefault(sc, []).extend(rules)

    _merge_sup(_ROOT / "config" / _SUPPRESS_FILE)
    _merge_sup(target / _SUPPRESS_FILE)

    # ── --apply / --apply-session shortcut (no scan, no TUI) ─────────────────
    _resolved_session = apply_session_file or (_session_path if apply_default else None)
    if _resolved_session is not None:
        if not _resolved_session.exists():
            _console.print(f"[bold red]Session file not found:[/bold red] {_resolved_session}")
            _console.print(f"[dim]Expected at: {_resolved_session.resolve()}[/dim]")
            raise typer.Exit(code=1)
        _console.print(f"[dim]Loading session: {_resolved_session}[/dim]")
        session = ReviewSession.load(_resolved_session)
        # Filter any session items whose finding has since been suppressed
        if _persistent_suppress:
            before = len(session.items)
            session.items = [
                i for i in session.items
                if i.rule_id not in _persistent_suppress
            ]
            dropped = before - len(session.items)
            if dropped:
                _console.print(f"[dim]Suppressed {dropped} session item(s) matching suppress rules.[/dim]")
        _apply_session(session, target, _backup_dir, dry_run=dry_run, console=_console)
        if report_path:
            _write_obfuscation_report(None, session, report_path, dry_run=dry_run, show_secrets=show_secrets)
        return

    # ── Parse scanners ────────────────────────────────────────────────────────
    scanner_list: list[str] | None = None
    if scanners:
        scanner_list = [s.strip().lower() for s in scanners.split(",")]
        unknown = set(scanner_list) - _VALID_SCANNERS
        if unknown:
            _console.print(f"[bold red]Unknown scanner(s):[/bold red] {', '.join(unknown)}")
            raise typer.Exit(code=1)

    # ── Run scan (show_secrets=True to capture raw match values) ─────────────
    scan_config = ScanConfig(
        path=str(target),
        scanners=scanner_list or ["gitleaks", "semgrep", "presidio"],
        project_name=target.name,
        exclude_paths=list(_DEFAULT_EXCLUDE),
        exclude_files=[str(_session_path.relative_to(target))]
            if _session_path.is_relative_to(target) else [],
        suppress_by_scanner=_suppress_by_scanner,
        suppress_global=sorted(_persistent_suppress),
        show_secrets=True,   # raw values needed for replacement
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=_console,
    ) as progress:
        progress.add_task(f"Scanning [cyan]{target}[/cyan]...", total=None)
        _report = asyncio.run(run_scan(scan_config))

    if _persistent_suppress:
        _report.findings = suppress_findings(_report.findings, _persistent_suppress)
        _report.build_summary()

    s = _report.summary
    _console.print(
        f"\n[bold]Scan complete[/bold] — "
        f"Total: [bold]{s.total}[/bold]  "
        f"[bold red]Critical: {s.critical}[/bold red]  "
        f"[bold dark_orange]High: {s.high}[/bold dark_orange]  "
        f"[bold yellow]Medium: {s.medium}[/bold yellow]  "
        f"[bold cyan]Low: {s.low}[/bold cyan]"
    )

    if not _report.findings:
        _console.print("[bold green]No findings — nothing to obfuscate.[/bold green]")
        return

    # ── Build session (while match still holds raw text from show_secrets=True) ─
    session = ReviewSession.from_findings(
        _report.findings,
        scan_id=_report.scan_id,
        target_path=str(target),
    )

    # Re-redact match for display AFTER session has captured the raw values
    for f in _report.findings:
        f.match = _Finding.redact(f.match)

    _session_path = session.save(_session_path)
    _console.print(f"[dim]Session saved: {_session_path}[/dim]")

    c = session.counts()
    _console.print(
        f"[dim]Pending: {c['pending']}  "
        f"Manual: {c['manual']}[/dim]"
    )

    # ── TUI review ────────────────────────────────────────────────────────────
    session = run_review(
        session,
        target_path=target,
        session_path=_session_path,
        auto_approve_severity=auto_approve_severity,
        show_secrets=show_secrets,
        console=_console,
    )

    approved_count = len(session.approved())
    if approved_count == 0:
        _console.print(
            "\n[dim]No findings approved for obfuscation — no files modified.[/dim]"
        )
        if report_path:
            _write_obfuscation_report(_report, session, report_path, dry_run=dry_run, show_secrets=show_secrets)
        return

    # ── Apply replacements ────────────────────────────────────────────────────
    _console.print(
        f"\n[bold]Applying[/bold] {approved_count} replacement(s)…"
        + ("  [dim](dry-run — no files written)[/dim]" if dry_run else "")
    )
    apply_result = _apply_session(session, target, _backup_dir, dry_run=dry_run, console=_console)

    _console.print(
        f"\n[bold green]Done.[/bold green]  "
        f"Applied: {apply_result.applied_count}  "
        f"Failed: {apply_result.failed_count}"
    )

    if not dry_run and apply_result.applied_count:
        _console.print(
            f"[dim]Backups in: {_backup_dir}[/dim]\n"
            f"[dim]To undo:   sensitive-scanner rollback {target} "
            f"--backup-dir {_backup_dir}[/dim]"
        )

    # ── HTML report ───────────────────────────────────────────────────────────
    if report_path:
        _write_obfuscation_report(_report, session, report_path, dry_run=dry_run, show_secrets=show_secrets)


def _write_obfuscation_report(
    report: "Report | None",
    session: "object",
    report_path: Path,
    dry_run: bool = False,
    show_secrets: bool = False,
) -> None:
    """Render and save an HTML report enriched with obfuscation session data."""
    from obfuscation.session import ReviewSession as _RS

    if report is None:
        # No scan report available — build a minimal one from the session
        from scanners.orchestrator import load_cached_report
        report = load_cached_report()

    if report is None:
        _console.print(
            "[bold yellow]Warning:[/bold yellow] No scan report available for HTML output. "
            "Run [bold]scan[/bold] first or combine with a fresh scan."
        )
        return

    content = render_html(report, session=session, dry_run=dry_run, show_secrets=show_secrets)  # type: ignore[arg-type]
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(content, encoding="utf-8")
    _console.print(f"\n[bold green]Report saved to[/bold green] {report_path.resolve()}")


# ── rollback command ──────────────────────────────────────────────────────────

@app.command()
def rollback(
    path: Path = typer.Argument(
        ...,
        help="The directory that was originally obfuscated (scan target root).",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    backup_dir: Path = typer.Option(
        ...,
        "--backup-dir",
        help=(
            "Path to the backup directory created by the obfuscate command "
            "(e.g. .pii-backups/20260609_143022).  Printed at the end of a "
            "successful obfuscate run."
        ),
    ),
) -> None:
    """Restore files to their pre-obfuscation state from a backup directory.

    Use the backup path printed after running [bold]obfuscate[/bold]:

    \b
      sensitive-scanner rollback ./myrepo --backup-dir .pii-backups/20260609_143022
    """
    from obfuscation.engine import rollback as _rollback

    target = _validate_path(path)
    backup = Path(backup_dir).resolve()

    if not backup.exists():
        _console.print(f"[bold red]Backup directory not found:[/bold red] {backup}")
        raise typer.Exit(code=1)

    _console.print(f"[dim]Restoring from: {backup}[/dim]")
    count = _rollback(backup, target, console=_console)

    if count:
        _console.print(
            f"\n[bold green]Rollback complete[/bold green] — "
            f"{count} file(s) restored."
        )
    else:
        _console.print(
            "[bold yellow]No files found in backup directory.[/bold yellow]"
        )



# ── Entry point ───────────────────────────────────────────────────────────────

@app.command()
def edit(
    finding_id: str = typer.Argument(
        ...,
        help="Finding ID to edit (the short hex ID shown in the report, e.g. 'a1b2c3d4e5f6a1b2').",
    ),
    session_file: Optional[Path] = typer.Option(
        None,
        "--session", "-s",
        help="Path to the review session JSON file.  Defaults to <cwd>/pii-review-session.json.",
    ),
    report_path: Optional[Path] = typer.Option(
        None,
        "--report", "-o",
        help="Path to regenerate the HTML report after editing.  Skipped if not provided.",
    ),
    replacement: Optional[str] = typer.Option(
        None,
        "--replacement", "-r",
        help="New replacement token (e.g. '[REDACTED_NAME]').  Prompted interactively if omitted.",
    ),
    decision: Optional[str] = typer.Option(
        None,
        "--decision", "-d",
        help="Override decision: approved | skipped | pending.",
    ),
    skip_reason: Optional[str] = typer.Option(
        None,
        "--skip-reason",
        help="Reason to record when setting decision to skipped.",
    ),
) -> None:
    """Edit a single finding in an existing review session by its ID.

    Lets you change the replacement token or decision for any finding, then
    optionally regenerates the HTML report.

    \b
    Examples:
      sensitive-scanner edit a1b2c3d4e5f6a1b2 --replacement "[REDACTED_EMPLOYEE]"
      sensitive-scanner edit a1b2c3d4e5f6a1b2 --decision skipped --skip-reason "test data"
      sensitive-scanner edit a1b2c3d4e5f6a1b2 --report scan-reports/report.html
    """
    from obfuscation.session import ReviewSession

    _session_path = Path(session_file) if session_file else Path.cwd() / "pii-review-session.json"

    if not _session_path.exists():
        _console.print(f"[bold red]Session file not found:[/bold red] {_session_path}")
        raise typer.Exit(code=1)

    session = ReviewSession.load(_session_path)

    # Find the item
    item = next((i for i in session.items if i.finding_id == finding_id), None)
    if item is None:
        _console.print(f"[bold red]Finding ID not found:[/bold red] {finding_id}")
        _console.print(f"[dim]Available IDs in session: {len(session.items)} items[/dim]")
        raise typer.Exit(code=1)

    # ── Show current state ────────────────────────────────────────────────────
    from rich.table import Table
    tbl = Table.grid(padding=(0, 2))
    tbl.add_column(style="dim", min_width=14)
    tbl.add_column()
    tbl.add_row("ID",          item.finding_id)
    tbl.add_row("File",        f"{item.file}:{item.line}")
    tbl.add_row("Category",    item.category)
    tbl.add_row("Decision",    item.decision)
    tbl.add_row("Replacement", f"[green]{item.replacement}[/green]")
    if item.skip_reason:
        tbl.add_row("Skip reason", item.skip_reason)
    _console.print(tbl)
    _console.print()

    # ── Apply changes (interactive if flags not supplied) ─────────────────────
    _VALID_DECISIONS = {"approved", "skipped", "pending"}

    if decision is not None:
        if decision not in _VALID_DECISIONS:
            _console.print(f"[bold red]Invalid decision:[/bold red] '{decision}'. Must be one of: {', '.join(sorted(_VALID_DECISIONS))}")
            raise typer.Exit(code=1)
        item.decision = decision  # type: ignore[assignment]
    else:
        from rich.prompt import Prompt
        new_decision = Prompt.ask(
            f"  [bold]Decision[/bold] (current: [dim]{item.decision}[/dim] — press Enter to keep)",
            console=_console,
            default=item.decision,
        ).strip()
        if new_decision in _VALID_DECISIONS:
            item.decision = new_decision  # type: ignore[assignment]

    if replacement is not None:
        item.replacement = replacement
    else:
        from rich.prompt import Prompt
        new_rep = Prompt.ask(
            f"  [bold]Replacement token[/bold] (current: [green]{item.replacement}[/green] — press Enter to keep)",
            console=_console,
            default=item.replacement,
        ).strip()
        if new_rep:
            item.replacement = new_rep

    if item.decision == "skipped":
        if skip_reason is not None:
            item.skip_reason = skip_reason
        else:
            from rich.prompt import Prompt
            new_reason = Prompt.ask(
                r"  [bold]Skip reason[/bold] (optional \[press Enter to keep])",
                console=_console,
                default=item.skip_reason or "",
            ).strip()
            if new_reason.lower() not in {"a", "s", "q", "e"}:
                item.skip_reason = new_reason
    else:
        # Clear skip reason if decision changed away from skipped
        item.skip_reason = ""

    # ── Save session ──────────────────────────────────────────────────────────
    session.save(_session_path)
    _console.print(f"\n[bold green]Saved.[/bold green]  Session updated at [dim]{_session_path}[/dim]")

    # ── Regenerate report ─────────────────────────────────────────────────────
    if report_path:
        _write_obfuscation_report(None, session, Path(report_path))
        _console.print(f"[dim]Report regenerated: {report_path}[/dim]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
