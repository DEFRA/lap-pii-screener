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
if str(_ROOT) not in sys.path:  # pragma: no cover - import-time path bootstrap
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


def _load_yaml_config(config_file: Optional[Path], target: Path) -> dict:
    """Load the YAML config file (explicit or auto-discovered). Returns a config dict."""
    cfg_path = config_file or target / "sensitive-scanner.yaml"
    if cfg_path and Path(cfg_path).exists():
        try:
            with open(cfg_path, encoding="utf-8") as fh:
                cfg = yaml.safe_load(fh) or {}
            _console.print(f"[dim]Using config: {Path(cfg_path).resolve()}[/dim]")
            return cfg
        except Exception as exc:
            _console.print(f"[bold yellow]Warning:[/bold yellow] Could not read config file: {exc}")
    return {}


def _load_suppress_config(
    target: Path, cfg: dict
) -> tuple[set[str], dict[str, list[str]]]:
    """Load suppress rules from install-level and per-project suppress files + config."""
    persistent: set[str] = set()
    by_scanner: dict[str, list[str]] = {}

    def _merge(path: Path) -> None:
        if not path.exists():
            return
        g, per = parse_suppress_file(path)
        persistent.update(g)
        for scanner, rules in per.items():
            by_scanner.setdefault(scanner, []).extend(rules)

    _merge(_ROOT / "config" / _SUPPRESS_FILE)
    _merge(target / _SUPPRESS_FILE)

    cfg_sbs = cfg.get("suppress_by_scanner", {})
    if isinstance(cfg_sbs, dict):
        for sc, rules in cfg_sbs.items():
            if isinstance(rules, list):
                by_scanner.setdefault(sc, []).extend(str(r) for r in rules)

    return persistent, by_scanner


def _is_pattern(s: str) -> bool:
    return any(c in s for c in ("*", "?", "[", "/", "\\"))


def _classify_exclusion(entry: str) -> tuple[str, str]:
    """Return (kind, normalised_entry) where kind is 'pattern' | 'file' | 'dir'."""
    entry = entry.replace("\\", "/")
    if _is_pattern(entry):
        return "pattern", entry
    if "." in entry.split("/")[-1] and "/" not in entry:
        return "file", entry
    return "dir", entry


def _excludes_from_config(cfg: dict) -> tuple[list[str], list[str], list[str]]:
    """Return (dirs, patterns, files) declared in the config's `exclude` block."""
    dirs: list[str] = []
    patterns: list[str] = []
    files: list[str] = []
    cfg_exc = cfg.get("exclude", {})
    if isinstance(cfg_exc, dict):
        dirs.extend(str(d) for d in cfg_exc.get("directories", []))
        patterns.extend(str(p).replace("\\", "/") for p in cfg_exc.get("patterns", []))
        files.extend(str(fi).replace("\\", "/") for fi in cfg_exc.get("files", []))
    return dirs, patterns, files


def _report_artifact_excludes(target: Path) -> list[str]:
    """Return previously-generated report files in *target* so they are not rescanned."""
    _REPORT_SUFFIXES = {".html", ".json", ".md"}
    _REPORT_STEMS = {"combined_pii_report", "pii_report", "scan_report", "sensitive_scan_report", "report"}
    out: list[str] = []
    for p in target.iterdir():
        if p.is_file() and p.suffix.lower() in _REPORT_SUFFIXES and p.stem.lower() in _REPORT_STEMS:
            try:
                out.append(str(p.relative_to(target)))
            except ValueError:
                pass
    return out


def _collect_exclusion_lists(
    target: Path,
    cfg: dict,
    exclude: Optional[str],
    output: Optional[Path],
) -> tuple[list[str], list[str], list[str]]:
    """Build (extra_dir_excludes, extra_patterns, excluded_files) from config and flags."""
    extra_dir_excludes, extra_patterns, excluded_files = _excludes_from_config(cfg)
    _buckets = {"dir": extra_dir_excludes, "pattern": extra_patterns, "file": excluded_files}

    def _add_entry(entry: str) -> None:
        kind, value = _classify_exclusion(entry)
        _buckets[kind].append(value)

    ignore_file = target / ".scannerignore"
    if ignore_file.exists():
        _console.print(f"[dim]Using .scannerignore: {ignore_file.resolve()}[/dim]")
        for raw in ignore_file.read_text(encoding="utf-8").splitlines():
            entry = raw.split("#", 1)[0].strip()
            if entry:
                _add_entry(entry)
    else:
        _console.print(f"[dim]No .scannerignore found at {ignore_file.resolve()}[/dim]")

    if exclude:
        for entry in (x.strip() for x in exclude.split(",") if x.strip()):
            _add_entry(entry)

    if output:
        try:
            rel = output.resolve().relative_to(target)
            excluded_files.append(str(rel))
        except ValueError:
            pass

    excluded_files.extend(_report_artifact_excludes(target))

    return extra_dir_excludes, extra_patterns, excluded_files


def _parse_scanner_list(raw) -> list[str]:
    """Normalise a scanners value (list or comma-string) to lowercase names."""
    if isinstance(raw, list):
        return [s.strip().lower() for s in raw]
    return [s.strip().lower() for s in str(raw).split(",")]


def _join_suppress_value(raw) -> str:
    """Normalise a suppress config value (list or string) to a comma-string."""
    return ",".join(raw) if isinstance(raw, list) else str(raw)


def _cfg_default(cli_value, cli_is_unset: bool, cfg_value, transform=lambda x: x):
    """Return the CLI value, or the (transformed) config value when the CLI value is unset."""
    return transform(cfg_value) if (cli_is_unset and cfg_value) else cli_value


def _print_scan_summary(report) -> None:
    s = report.summary
    _console.print(
        f"\n[bold]Scan complete[/bold] — "
        f"Total: [bold]{s.total}[/bold]  "
        f"[bold red]Critical: {s.critical}[/bold red]  "
        f"[bold dark_orange]High: {s.high}[/bold dark_orange]  "
        f"[bold yellow]Medium: {s.medium}[/bold yellow]  "
        f"[bold cyan]Low: {s.low}[/bold cyan]"
    )


def _apply_cli_suppression(report, suppress, persistent: set[str]) -> None:
    """Filter findings by the combined CLI/persistent suppression set (in place)."""
    suppress_set = {r.strip() for r in suppress.split(",") if r.strip()} if suppress else set()
    suppress_set |= persistent
    if not suppress_set:
        return
    before = len(report.findings)
    report.findings = suppress_findings(report.findings, suppress_set)
    report.build_summary()
    dropped = before - len(report.findings)
    if dropped:
        _console.print(f"[dim]Suppressed {dropped} finding(s) matching: {', '.join(sorted(suppress_set))}[/dim]")


def _emit_html_with_session(report, output, session_file, show_confidence) -> None:
    """Render the HTML report enriched with an obfuscation review session."""
    from obfuscation.session import ReviewSession as _ReviewSession
    if not session_file.exists():
        _console.print(f"[bold red]Session file not found:[/bold red] {session_file}")
        raise typer.Exit(code=1)
    _session = _ReviewSession.load(session_file)
    content = render_html(report, session=_session, show_confidence=show_confidence)
    if output:
        output.write_text(content, encoding="utf-8")
        _console.print(f"\n[bold green]Report saved to[/bold green] {output.resolve()}")
    else:
        print(content)


def _emit_scan_report(report, fmt, output, per_file, output_dir, session_file, show_confidence) -> None:
    """Render and write the scan report according to the chosen output mode."""
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
        return
    if fmt == "html" and session_file is not None:
        _emit_html_with_session(report, output, session_file, show_confidence)
        return
    _render_and_write(report, fmt, output)


def _apply_fail_on(report, fail_on) -> None:
    """Exit with code 2 if any finding meets or exceeds the --fail-on severity."""
    if not fail_on:
        return
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    threshold = severity_rank.get(fail_on.lower(), 0)
    worst = max((severity_rank.get(f.severity, 0) for f in report.findings), default=0)
    if worst >= threshold:
        raise typer.Exit(code=2)


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command()
def scan(  # NOSONAR - CLI entry point; each parameter is a distinct user-facing option
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
        scanner_list = _parse_scanner_list(scanners)
        unknown = set(scanner_list) - _VALID_SCANNERS
        if unknown:
            _console.print(f"[bold red]Unknown scanner(s):[/bold red] {', '.join(unknown)}")
            _console.print(f"Valid options: {', '.join(sorted(_VALID_SCANNERS))}")
            raise typer.Exit(code=1)

    if fmt not in _VALID_FORMATS:
        _console.print(f"[bold red]Unknown format:[/bold red] {fmt!r}")
        _console.print(f"Valid options: {', '.join(sorted(_VALID_FORMATS))}")
        raise typer.Exit(code=1)

    from models.finding import _DEFAULT_EXCLUDE

    _cfg = _load_yaml_config(config_file, target)

    # Merge config file values — CLI flags take precedence (unset = not supplied)
    scanner_list = _cfg_default(scanner_list, scanner_list is None, _cfg.get("scanners"), _parse_scanner_list)
    fmt = _cfg_default(fmt, fmt == "console", _cfg.get("format"))
    output = _cfg_default(output, output is None, _cfg.get("output"), Path)
    project_name = _cfg_default(project_name, project_name is None, _cfg.get("project_name"))
    history = _cfg_default(history, not history, _cfg.get("include_git_history"), bool)
    fail_on = _cfg_default(fail_on, fail_on is None, _cfg.get("fail_on"))
    show_secrets = _cfg_default(show_secrets, not show_secrets, _cfg.get("show_secrets"), bool)
    skip_comments = _cfg_default(skip_comments, not skip_comments, _cfg.get("skip_comments"), bool)
    suppress = _cfg_default(suppress, suppress is None, _cfg.get("suppress"), _join_suppress_value)

    _persistent_suppress, _suppress_by_scanner = _load_suppress_config(target, _cfg)
    extra_dir_excludes, extra_patterns, excluded_files = _collect_exclusion_lists(
        target, _cfg, exclude, output
    )

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

    _print_scan_summary(report)
    _apply_cli_suppression(report, suppress, _persistent_suppress)
    _emit_scan_report(report, fmt, output, per_file, output_dir, session_file, show_confidence)
    _apply_fail_on(report, fail_on)


def _status_binary_lines() -> list[str]:
    """Status lines for the managed scanner binaries (gitleaks etc.)."""
    from scanners.binary_manager import SPECS, is_installed
    lines: list[str] = []
    for name in SPECS:
        ok = is_installed(name)
        mark = "✅" if ok else "⬇ "
        note = "" if ok else "  (auto-downloaded on first scan)"
        lines.append(f"  {mark} {name}{note}")
    return lines


def _status_semgrep_line() -> str:
    import shutil
    semgrep = shutil.which("semgrep")
    if semgrep:
        return f"  ✅ semgrep  {semgrep}"
    return "  ❌ semgrep  not found — run: pip install semgrep"


def _status_sonarqube_lines(sq_home, java) -> list[str]:
    from scanners.sonarqube_scanner import _find_sonar_scanner
    if sq_home and java:
        sc = _find_sonar_scanner()
        return [
            f"  ✅ SonarQube (native)  {sq_home}",
            f"  {'✅' if sc else '⚠ '} sonar-scanner  {sc or 'not found'}",
        ]
    if sq_home:
        return [f"  ⚠  SonarQube found at {sq_home} but Java not on PATH"]
    return ["  ℹ  SonarQube (native)  not installed"]


def _status_spacy_line() -> str:
    try:
        import spacy  # type: ignore
    except ImportError:
        return "  ℹ  spaCy NLP  not installed (optional — pip install spacy)"
    try:
        spacy.load("en_core_web_sm")
        return "  ✅ spaCy NLP  en_core_web_sm loaded"
    except OSError:
        return "  ⚠  spaCy installed but model missing — run: python -m spacy download en_core_web_sm"


def _status_presidio_line() -> str:
    try:
        from presidio_analyzer import AnalyzerEngine  # type: ignore  # noqa: F401
        return "  ✅ Presidio NER  installed (best name/entity detection)"
    except ImportError:
        return "  ℹ  Presidio NER  not installed (optional — pip install presidio-analyzer presidio-anonymizer)"


def _status_nlp_lines() -> list[str]:
    return [_status_spacy_line(), _status_presidio_line()]


def _compute_tier(sq_home, java, runtime) -> int:
    import os
    if os.environ.get("SONAR_TOKEN") and "sonarcloud.io" in os.environ.get("SONAR_HOST_URL", ""):
        return 3
    if (sq_home and java) or runtime:
        return 2
    return 1


@app.command()
def status() -> None:
    """Show which scanner backends are available and the active tier."""
    import shutil
    from scanners.constants import detect_container_runtime
    from scanners.sonarqube_scanner import _find_native_sonarqube

    sq_home = _find_native_sonarqube()
    java = shutil.which("java")
    runtime = detect_container_runtime()

    lines: list[str] = []
    lines.extend(_status_binary_lines())
    lines.append(_status_semgrep_line())
    lines.append("")
    lines.extend(_status_sonarqube_lines(sq_home, java))
    lines.append(f"  ✅ container runtime  {runtime}" if runtime else "  ℹ  Docker / Podman  not found")
    lines.extend(_status_nlp_lines())

    tier = _compute_tier(sq_home, java, runtime)
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


# ── setup helpers ─────────────────────────────────────────────────────────────

_SetupRow = tuple[str, str, str]  # (component, emoji_markup, note)

_SR_OK   = "[bold green]✅[/bold green]"
_SR_WARN = "[bold yellow]⚠ [/bold yellow]"
_SR_FAIL = "[bold red]✗ [/bold red]"
_SR_SKIP = "[dim]–[/dim]"


def _run_gitleaks_setup(check: bool, results: list) -> None:
    """Append Gitleaks status row(s) to *results*."""
    from scanners.binary_manager import ensure_binary, is_installed
    from rich.status import Status
    if is_installed("gitleaks"):
        results.append(("Gitleaks", _SR_OK, "already installed" if not check else "installed"))
        return
    if check:
        results.append(("Gitleaks", _SR_WARN, "not downloaded (auto-downloads on first scan)"))
        return
    with Status("Downloading Gitleaks...", console=_console):
        try:
            path = asyncio.run(ensure_binary("gitleaks"))
            if path:
                results.append(("Gitleaks", _SR_OK, f"downloaded → {path}"))
            else:
                results.append(("Gitleaks", _SR_WARN, "no binary for this platform (uses system PATH)"))
        except Exception as exc:
            results.append(("Gitleaks", _SR_FAIL, f"download failed: {exc}"))


def _run_semgrep_setup(check: bool, results: list) -> None:
    """Append Semgrep status row(s) to *results*."""
    import subprocess
    import shutil
    import sys as _sys
    from rich.status import Status
    semgrep_path = shutil.which("semgrep")
    if semgrep_path:
        results.append(("Semgrep", _SR_OK, semgrep_path))
        return
    if check:
        results.append(("Semgrep", _SR_WARN, "not found — run: pip install semgrep"))
        return
    with Status("Installing Semgrep via pip...", console=_console):
        try:
            r = subprocess.run(
                [_sys.executable, "-m", "pip", "install", "--quiet", "semgrep"],
                capture_output=True, text=True, timeout=300,
            )
            if r.returncode == 0:
                results.append(("Semgrep", _SR_OK, "installed"))
            else:
                err = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "pip failed"
                results.append(("Semgrep", _SR_FAIL, err))
        except Exception as exc:
            results.append(("Semgrep", _SR_FAIL, str(exc)))


def _spacy_report_existing(results: list) -> None:
    """Report spaCy status without installing (the --spacy flag was not given)."""
    try:
        import spacy as _spacy  # type: ignore
    except ImportError:
        results.append(("spaCy", _SR_SKIP, "optional — add --spacy to install"))
        return
    try:
        _spacy.load("en_core_web_sm")
        results.append(("spaCy", _SR_OK, "en_core_web_sm ready"))
    except OSError:
        results.append(("spaCy", _SR_WARN, "model missing — run: sensitive-scanner setup --spacy"))


def _ensure_spacy_installed(check: bool, results: list) -> bool:
    """Ensure the spaCy package is importable; pip-install it if needed. Returns availability."""
    import subprocess
    import sys as _sys
    from rich.status import Status

    try:
        import spacy  # type: ignore  # noqa: F401
        return True
    except ImportError:
        pass

    if check:
        results.append(("spaCy", _SR_WARN, "not installed — run: pip install spacy"))
        return False

    with Status("Installing spaCy via pip...", console=_console):
        try:
            r = subprocess.run(
                [_sys.executable, "-m", "pip", "install", "--quiet", "spacy"],
                capture_output=True, text=True, timeout=300,
            )
        except Exception as exc:
            results.append(("spaCy", _SR_FAIL, str(exc)))
            return False

    if r.returncode != 0:
        results.append(("spaCy", _SR_FAIL, "pip install failed"))
        return False
    return True


def _ensure_spacy_model(check: bool, results: list) -> None:
    """Ensure the en_core_web_sm model is present; download it if needed."""
    import subprocess
    import sys as _sys
    from rich.status import Status

    try:
        import spacy as _spacy  # type: ignore
        _spacy.load("en_core_web_sm")
        results.append(("spaCy", _SR_OK, "en_core_web_sm ready"))
        return
    except OSError:
        pass

    if check:
        results.append(("spaCy", _SR_WARN, "installed but en_core_web_sm model missing"))
        return

    with Status("Downloading en_core_web_sm model...", console=_console):
        try:
            r = subprocess.run(
                [_sys.executable, "-m", "spacy", "download", "en_core_web_sm"],
                capture_output=True, text=True, timeout=300,
            )
        except Exception as exc:
            results.append(("spaCy", _SR_FAIL, str(exc)))
            return

    if r.returncode == 0:
        results.append(("spaCy", _SR_OK, "en_core_web_sm downloaded"))
    else:
        results.append(("spaCy", _SR_FAIL, "model download failed"))


def _run_spacy_setup(check: bool, do_spacy: bool, results: list) -> None:
    """Append spaCy status row(s) to *results*."""
    if not do_spacy:
        _spacy_report_existing(results)
        return
    if not _ensure_spacy_installed(check, results):
        return
    _ensure_spacy_model(check, results)


def _setup_sonar_scanner_cli(check: bool, results: list) -> None:
    """Install (or report) the sonar-scanner-cli."""
    from rich.status import Status
    from scanners.sonarqube_manager import ensure_sonar_scanner, sonar_scanner_installed, _SCANNER_DIR

    if sonar_scanner_installed():
        results.append(("sonar-scanner-cli", _SR_OK, f"{_SCANNER_DIR}"))
        return
    if check:
        results.append(("sonar-scanner-cli", _SR_WARN, "not installed"))
        return
    with Status("Downloading sonar-scanner-cli...", console=_console):
        try:
            path = asyncio.run(ensure_sonar_scanner())
        except Exception as exc:
            results.append(("sonar-scanner-cli", _SR_FAIL, str(exc)))
            return
    if path:
        results.append(("sonar-scanner-cli", _SR_OK, f"installed → {path}"))
    else:
        results.append(("sonar-scanner-cli", _SR_FAIL, "download failed"))


def _setup_sonarqube_ce(check: bool, non_interactive: bool, results: list) -> None:
    """Download (or report) SonarQube Community Edition."""
    from rich.status import Status
    from scanners.sonarqube_manager import SONAR_PORT, ensure_sonarqube, patch_sonar_port, _SQ_DIR
    from scanners.sonarqube_scanner import _find_native_sonarqube

    sq_home = _find_native_sonarqube()
    if sq_home:
        if not check:
            patch_sonar_port(sq_home)
        results.append((_LABEL_SONARQUBE_CE, _SR_OK, f"port {SONAR_PORT} — {sq_home}"))
        return
    if check:
        results.append((_LABEL_SONARQUBE_CE, _SR_WARN, "not installed"))
        return
    if not non_interactive:
        _console.print(f"\n  [dim]SonarQube CE is ~500 MB.  Downloading to {_SQ_DIR}[/dim]")
    with Status("Downloading SonarQube CE (~500 MB, this may take a few minutes)...", console=_console):
        try:
            path = asyncio.run(ensure_sonarqube())
        except Exception as exc:
            results.append((_LABEL_SONARQUBE_CE, _SR_FAIL, str(exc)))
            return
    if path:
        results.append((_LABEL_SONARQUBE_CE, _SR_OK, f"port {SONAR_PORT} — {path}"))
    else:
        results.append((_LABEL_SONARQUBE_CE, _SR_FAIL, "download failed — check internet connection"))


def _persist_sonar_token(host_url: str, token: str, results: list) -> None:
    """Persist the generated admin token + host URL and print guidance."""
    from scanners.sonarqube_manager import persist_env_var
    tok_ok = persist_env_var("SONAR_TOKEN", token)
    url_ok = persist_env_var("SONAR_HOST_URL", host_url)
    env_note = "saved to user environment" if (tok_ok and url_ok) else "shown below — save manually"
    results.append(("Admin token", _SR_OK, env_note))
    results.append(("SONAR_HOST_URL", _SR_OK, host_url))
    _console.print(
        "\n  [bold green]✔ SONAR_TOKEN[/bold green] and "
        "[bold green]SONAR_HOST_URL[/bold green] have been written "
        "to your user environment automatically."
    )
    _console.print("  Open a [bold]new[/bold] terminal window for them to take effect in future sessions.")
    _console.print(f"\n  [dim]SONAR_TOKEN=[/dim][bold]{token}[/bold]")
    _console.print(f"  [dim](Change the admin password at {host_url} when convenient.)[/dim]")


def _setup_sonarqube_token(host_url: str, results: list) -> None:
    """Generate and persist an admin token (or print manual instructions)."""
    from scanners.sonarqube_manager import ensure_admin_token, persist_env_var
    try:
        token, token_reason = asyncio.run(ensure_admin_token(host_url))
    except Exception as exc:
        token, token_reason = None, str(exc)

    if token:
        _persist_sonar_token(host_url, token, results)
        return

    results.append(("Admin token", _SR_WARN, token_reason))
    persist_env_var("SONAR_HOST_URL", host_url)
    results.append(("SONAR_HOST_URL", _SR_OK, f"{host_url} — saved to user environment"))
    _console.print(f"\n  Generate a token at: [link]{host_url}/account/security[/link]")
    _console.print(
        "  Then run:\n"
        "  [bold]sensitive-scanner setup --sonarqube[/bold]\n"
        "  — or set it manually in a new terminal:\n"
        '  [dim][Environment]::SetEnvironmentVariable("SONAR_TOKEN", "<your-token>", "User")[/dim]'
    )


def _setup_sonarqube_start(check: bool, results: list) -> None:
    """Start SonarQube and provision an admin token."""
    from scanners.sonarqube_manager import SONAR_PORT, start_and_wait
    from scanners.sonarqube_scanner import _find_native_sonarqube

    sq_home = _find_native_sonarqube()
    if not sq_home or check:
        return

    _console.print(f"\n  Starting SonarQube on port {SONAR_PORT} (first start can take ~2 min)...")
    host_url = f"http://localhost:{SONAR_PORT}"
    try:
        up = asyncio.run(start_and_wait(sq_home, port=SONAR_PORT, max_wait=180))
    except Exception as exc:
        results.append((_LABEL_SONARQUBE_START, _SR_FAIL, str(exc)))
        return

    if not up:
        results.append((_LABEL_SONARQUBE_START, _SR_WARN, "did not become UP within 3 min — try starting manually"))
        return

    results.append((_LABEL_SONARQUBE_START, _SR_OK, f"running at {host_url}"))
    _setup_sonarqube_token(host_url, results)


def _run_sonarqube_setup(
    check: bool, do_sonarqube: bool, non_interactive: bool, results: list
) -> None:
    """Append SonarQube status row(s) to *results*."""
    from scanners.sonarqube_manager import check_java
    from scanners.sonarqube_scanner import _find_native_sonarqube

    if not do_sonarqube:
        sq_home = _find_native_sonarqube()
        if sq_home:
            results.append((_LABEL_SONARQUBE_CE, _SR_OK, f"installed at {sq_home}"))
        else:
            results.append((_LABEL_SONARQUBE_CE, _SR_SKIP, "optional — add --sonarqube to auto-download"))
        return

    java_ok, java_msg = check_java()
    if not java_ok:
        results.append(("Java 17+", _SR_FAIL, java_msg))
        results.append(("sonar-scanner-cli", _SR_SKIP, "skipped — Java required"))
        results.append((_LABEL_SONARQUBE_CE, _SR_SKIP, "skipped — Java required"))
        return

    results.append(("Java 17+", _SR_OK, java_msg))

    _setup_sonar_scanner_cli(check, results)
    _setup_sonarqube_ce(check, non_interactive, results)
    _setup_sonarqube_start(check, results)


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
    import sys as _sys
    from rich.table import Table
    from scanners.sonarqube_manager import _SQ_DIR

    do_sonarqube = sonarqube or all_deps
    do_spacy = spacy_nlp or all_deps

    _console.print("\n[bold]sensitive-scanner setup[/bold]\n")
    (_SQ_DIR.parent / "bin").mkdir(parents=True, exist_ok=True)

    results: list[_SetupRow] = []

    # 1. Python version
    v = _sys.version_info
    if v >= (3, 11):
        results.append(("Python", _SR_OK, f"{v.major}.{v.minor}.{v.micro}"))
    else:
        results.append(("Python", _SR_WARN, f"{v.major}.{v.minor} — 3.11+ recommended"))

    _run_gitleaks_setup(check, results)
    _run_semgrep_setup(check, results)
    _run_spacy_setup(check, do_spacy, results)
    _run_sonarqube_setup(check, do_sonarqube, non_interactive, results)

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

def _obf_load_suppress(target: Path) -> tuple[set[str], dict[str, list[str]]]:
    """Merge global + target suppress files. Returns (global_set, by_scanner)."""
    persistent: set[str] = set()
    by_scanner: dict[str, list[str]] = {}
    for sup_path in (_ROOT / "config" / _SUPPRESS_FILE, target / _SUPPRESS_FILE):
        if not sup_path.exists():
            continue
        g, per = parse_suppress_file(sup_path)
        persistent.update(g)
        for sc, rules in per.items():
            by_scanner.setdefault(sc, []).extend(rules)
    return persistent, by_scanner


def _obf_apply_saved_session(
    resolved: Path, target: Path, backup_dir: Path, dry_run: bool,
    report_path: Path | None, show_secrets: bool, persistent: set[str],
) -> None:
    """Apply a previously saved review session without re-scanning or running the TUI."""
    from obfuscation.session import ReviewSession
    from obfuscation.engine import apply_session as _apply_session

    if not resolved.exists():
        _console.print(f"[bold red]Session file not found:[/bold red] {resolved}")
        _console.print(f"[dim]Expected at: {resolved.resolve()}[/dim]")
        raise typer.Exit(code=1)
    _console.print(f"[dim]Loading session: {resolved}[/dim]")
    session = ReviewSession.load(resolved)
    # Filter any session items whose finding has since been suppressed
    if persistent:
        before = len(session.items)
        session.items = [i for i in session.items if i.rule_id not in persistent]
        dropped = before - len(session.items)
        if dropped:
            _console.print(f"[dim]Suppressed {dropped} session item(s) matching suppress rules.[/dim]")
    _apply_session(session, target, backup_dir, dry_run=dry_run, console=_console)
    if report_path:
        _write_obfuscation_report(None, session, report_path, dry_run=dry_run, show_secrets=show_secrets)


def _obf_parse_scanners(scanners: str | None) -> list[str] | None:
    """Parse and validate a comma-separated scanner list."""
    if not scanners:
        return None
    scanner_list = [s.strip().lower() for s in scanners.split(",")]
    unknown = set(scanner_list) - _VALID_SCANNERS
    if unknown:
        _console.print(f"[bold red]Unknown scanner(s):[/bold red] {', '.join(unknown)}")
        raise typer.Exit(code=1)
    return scanner_list


def _obf_print_summary(report) -> None:
    """Print the post-scan severity summary line."""
    s = report.summary
    _console.print(
        f"\n[bold]Scan complete[/bold] — "
        f"Total: [bold]{s.total}[/bold]  "
        f"[bold red]Critical: {s.critical}[/bold red]  "
        f"[bold dark_orange]High: {s.high}[/bold dark_orange]  "
        f"[bold yellow]Medium: {s.medium}[/bold yellow]  "
        f"[bold cyan]Low: {s.low}[/bold cyan]"
    )


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
    from obfuscation.reviewer import run_review

    target = _validate_path(path)
    _ts = _dt.now().strftime("%Y%m%d_%H%M%S")
    _backup_dir   = backup_dir   or (target / ".pii-backups" / _ts)
    _session_path = session_file or (target / "pii-review-session.json")

    # ── Load suppress files (must happen before any early return) ─────────────
    _persistent_suppress, _suppress_by_scanner = _obf_load_suppress(target)

    # ── --apply / --apply-session shortcut (no scan, no TUI) ─────────────────
    _resolved_session = apply_session_file or (_session_path if apply_default else None)
    if _resolved_session is not None:
        _obf_apply_saved_session(
            _resolved_session, target, _backup_dir, dry_run,
            report_path, show_secrets, _persistent_suppress,
        )
        return

    # ── Parse scanners ────────────────────────────────────────────────────────
    scanner_list = _obf_parse_scanners(scanners)

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

    _obf_print_summary(_report)

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

    _obf_apply_and_finalize(
        session, _report, target, _backup_dir, dry_run, report_path, show_secrets,
    )


def _obf_apply_and_finalize(
    session: "object",
    report: "Report | None",
    target: Path,
    backup_dir: Path,
    dry_run: bool,
    report_path: Optional[Path],
    show_secrets: bool,
) -> None:
    """Apply approved replacements and optionally write the HTML report."""
    from obfuscation.engine import apply_session as _apply_session

    approved_count = len(session.approved())
    if approved_count == 0:
        _console.print(
            "\n[dim]No findings approved for obfuscation — no files modified.[/dim]"
        )
        if report_path:
            _write_obfuscation_report(report, session, report_path, dry_run=dry_run, show_secrets=show_secrets)
        return

    # ── Apply replacements ────────────────────────────────────────────────────
    _console.print(
        f"\n[bold]Applying[/bold] {approved_count} replacement(s)…"
        + ("  [dim](dry-run — no files written)[/dim]" if dry_run else "")
    )
    apply_result = _apply_session(session, target, backup_dir, dry_run=dry_run, console=_console)

    _console.print(
        f"\n[bold green]Done.[/bold green]  "
        f"Applied: {apply_result.applied_count}  "
        f"Failed: {apply_result.failed_count}"
    )

    if not dry_run and apply_result.applied_count:
        _console.print(
            f"[dim]Backups in: {backup_dir}[/dim]\n"
            f"[dim]To undo:   sensitive-scanner rollback {target} "
            f"--backup-dir {backup_dir}[/dim]"
        )

    # ── HTML report ───────────────────────────────────────────────────────────
    if report_path:
        _write_obfuscation_report(report, session, report_path, dry_run=dry_run, show_secrets=show_secrets)


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

_VALID_DECISIONS = {"approved", "skipped", "pending"}


def _edit_show_current(item) -> None:
    """Print the current state of a session item."""
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


def _edit_update_decision(item, decision: str | None) -> None:
    """Update the item decision from a flag or interactive prompt."""
    if decision is not None:
        if decision not in _VALID_DECISIONS:
            _console.print(f"[bold red]Invalid decision:[/bold red] '{decision}'. Must be one of: {', '.join(sorted(_VALID_DECISIONS))}")
            raise typer.Exit(code=1)
        item.decision = decision  # type: ignore[assignment]
        return
    from rich.prompt import Prompt
    new_decision = Prompt.ask(
        f"  [bold]Decision[/bold] (current: [dim]{item.decision}[/dim] — press Enter to keep)",
        console=_console,
        default=item.decision,
    ).strip()
    if new_decision in _VALID_DECISIONS:
        item.decision = new_decision  # type: ignore[assignment]


def _edit_update_replacement(item, replacement: str | None) -> None:
    """Update the replacement token from a flag or interactive prompt."""
    if replacement is not None:
        item.replacement = replacement
        return
    from rich.prompt import Prompt
    new_rep = Prompt.ask(
        f"  [bold]Replacement token[/bold] (current: [green]{item.replacement}[/green] — press Enter to keep)",
        console=_console,
        default=item.replacement,
    ).strip()
    if new_rep:
        item.replacement = new_rep


def _edit_update_skip_reason(item, skip_reason: str | None) -> None:
    """Update or clear the skip reason based on the current decision."""
    if item.decision != "skipped":
        item.skip_reason = ""
        return
    if skip_reason is not None:
        item.skip_reason = skip_reason
        return
    from rich.prompt import Prompt
    new_reason = Prompt.ask(
        r"  [bold]Skip reason[/bold] (optional \[press Enter to keep])",
        console=_console,
        default=item.skip_reason or "",
    ).strip()
    if new_reason.lower() not in {"a", "s", "q", "e"}:
        item.skip_reason = new_reason


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
    _edit_show_current(item)

    # ── Apply changes (interactive if flags not supplied) ─────────────────────
    _edit_update_decision(item, decision)
    _edit_update_replacement(item, replacement)
    _edit_update_skip_reason(item, skip_reason)

    # ── Save session ──────────────────────────────────────────────────────────
    session.save(_session_path)
    _console.print(f"\n[bold green]Saved.[/bold green]  Session updated at [dim]{_session_path}[/dim]")

    # ── Regenerate report ─────────────────────────────────────────────────────
    if report_path:
        _write_obfuscation_report(None, session, Path(report_path))
        _console.print(f"[dim]Report regenerated: {report_path}[/dim]")


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
