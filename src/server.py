"""
sensitive-code-scanner MCP server
----------------------------------
Exposes five tools to VS Code Copilot Chat (or any MCP client):

  scan_codebase       — Run all scanners against a local directory
  get_report          — Return the last scan report in a chosen format
  list_findings       — Filter the cached report findings
  get_remediation     — Return detailed remediation for a specific finding
  check_scanner_status — Show what scanner backends are available / start SonarQube
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on sys.path when run directly
_ROOT = Path(__file__).parent.resolve()
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mcp.server.fastmcp import FastMCP

from models.finding import ScanConfig
from models.report import Report
from reporting.console import render_console
from reporting.html_reporter import render_html
from reporting.json_reporter import render_json
from reporting.markdown_reporter import render_markdown
from scanners.binary_manager import SPECS, binary_path, is_installed
from scanners.orchestrator import load_cached_report, run_scan
from scanners.sonarqube_scanner import SonarQubeScanner, _find_native_sonarqube, _find_sonar_scanner, _read_sonar_port

import asyncio
import os
import shutil

mcp = FastMCP("sensitive-code-scanner")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _validate_path(path: str) -> Path:
    """Resolve and validate that a scan path exists and is a directory."""
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise ValueError(f"Path does not exist: {path}")
    if not resolved.is_dir():
        raise ValueError(f"Path is not a directory: {path}")
    return resolved


def _render(report: Report, fmt: str) -> str:
    fmt = fmt.lower().strip()
    if fmt == "json":
        return render_json(report)
    if fmt == "html":
        return render_html(report)
    if fmt == "console":
        return render_console(report)
    return render_markdown(report)  # default


# ─── Tools ────────────────────────────────────────────────────────────────────

@mcp.tool()
async def scan_codebase(
    path: str,
    scanners: list[str] | None = None,
    project_name: str = "project",
    include_git_history: bool = False,
) -> str:
    """
    Scan a local codebase for PII, API keys, secrets, and security vulnerabilities.

    Runs Gitleaks (secrets), Semgrep (SAST + security rules), and a custom PII
    regex/NLP scanner in parallel. SonarQube is included automatically if Docker,
    Podman, or a SONAR_TOKEN environment variable is available.

    Args:
        path: Absolute path to the directory or git repository to scan.
        scanners: Subset of scanners to use — ["gitleaks", "semgrep", "pii", "sonarqube"].
                  Omit to use all available scanners.
        project_name: Human-readable name for the project (used in reports).
        include_git_history: Scan the full git commit history for secrets (slower).

    Returns:
        A markdown-formatted summary of findings with counts by severity and
        the top critical/high issues with file locations and remediation pointers.
    """
    try:
        scan_path = _validate_path(path)
    except ValueError as exc:
        return f"**Error:** {exc}"

    requested = scanners or ["gitleaks", "semgrep", "pii", "sonarqube"]

    config = ScanConfig(
        path=str(scan_path),
        scanners=requested,
        project_name=project_name,
        include_git_history=include_git_history,
    )

    try:
        report = await run_scan(config)
    except Exception as exc:
        return f"**Scan error:** {exc}"

    return render_markdown(report)


@mcp.tool()
async def get_report(format: str = "markdown") -> str:
    """
    Return the last scan report in the requested format.

    Args:
        format: Output format — "markdown" (default), "json", "html", or "console".

    Returns:
        The full report in the requested format.
        Returns an error message if no scan has been run yet.
    """
    report = load_cached_report()
    if report is None:
        return "No scan report found. Run `scan_codebase` first."
    return _render(report, format)


@mcp.tool()
async def list_findings(
    severity: str | None = None,
    category: str | None = None,
    file_pattern: str | None = None,
) -> str:
    """
    Filter and list findings from the last scan.

    Args:
        severity:     Filter by severity — "critical", "high", "medium", "low", or "info".
        category:     Filter by category — e.g. "pii_ssn", "api_key_aws_access",
                      "hardcoded_password".  Partial matches are supported.
        file_pattern: Filter by file path substring — e.g. "config" or ".env".

    Returns:
        A markdown table of matching findings with file, line, category, severity,
        and the redacted match value.
    """
    report = load_cached_report()
    if report is None:
        return "No scan report found. Run `scan_codebase` first."

    findings = report.findings

    if severity:
        findings = [f for f in findings if f.severity == severity.lower()]
    if category:
        findings = [f for f in findings if category.lower() in f.category]
    if file_pattern:
        findings = [f for f in findings if file_pattern.lower() in f.file.lower()]

    if not findings:
        return "No findings match the specified filters."

    lines = [
        f"**{len(findings)} finding(s)** matching filters\n",
        "| Severity | File | Line | Category | Match | Scanners |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        badge = f.severity.upper()
        scanners_str = ", ".join(f.scanners)
        lines.append(f"| {badge} | `{f.file}` | {f.line} | `{f.category}` | `{f.match}` | {scanners_str} |")

    return "\n".join(lines)


@mcp.tool()
async def get_remediation(finding_id: str) -> str:
    """
    Return full remediation guidance for a specific finding.

    Args:
        finding_id: The 16-character finding ID shown in the scan report.

    Returns:
        Step-by-step remediation instructions, relevant standards (CWE, OWASP,
        GDPR), and the file + line where the issue was detected.
    """
    report = load_cached_report()
    if report is None:
        return "No scan report found. Run `scan_codebase` first."

    match = next((f for f in report.findings if f.id == finding_id), None)
    if not match:
        return f"Finding `{finding_id}` not found in the last report."

    lines = [
        f"## Remediation: `{match.category}` ({match.severity.upper()})",
        "",
        f"**File:** `{match.file}` — Line {match.line}",
        f"**Detected by:** {', '.join(match.scanners)}",
        f"**Redacted match:** `{match.match}`",
        "",
        f"### What was found",
        match.remediation_description or match.message or "_No description available._",
        "",
    ]

    if match.fix_steps:
        lines += ["### How to fix", ""]
        for i, step in enumerate(match.fix_steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

    if match.references:
        lines += ["### References", ""]
        for ref in match.references:
            if ref.startswith("http"):
                lines.append(f"- [{ref}]({ref})")
            else:
                lines.append(f"- {ref}")

    return "\n".join(lines)


@mcp.tool()
async def check_scanner_status(start_sonarqube: bool = False) -> str:
    """
    Check which scanner backends are available in the current environment.

    Reports on: managed binaries (Gitleaks, Semgrep), container runtime
    (Docker/Podman), SonarQube reachability, and spaCy NLP model.
    Optionally starts the SonarQube Docker Compose stack.

    Args:
        start_sonarqube: If True and a container runtime is present, start the
                         SonarQube Docker Compose stack and wait for it to be ready.

    Returns:
        A status table showing which scanners are ready and the active tier.
    """
    lines: list[str] = ["## Scanner Status\n"]

    # Managed binaries
    for name in SPECS:
        ok = is_installed(name)
        status = "✅ installed" if ok else "⬇️  not downloaded (will auto-download on first scan)"
        lines.append(f"- **{name}**: {status}")

    # System PATH binaries
    for tool in ("gitleaks", "semgrep", "docker", "podman", "sonar-scanner"):
        found = shutil.which(tool)
        if found:
            lines.append(f"- **{tool}** (system): ✅ `{found}`")

    # Native Java SonarQube
    lines.append("")
    sq_home = _find_native_sonarqube()
    java = shutil.which("java")
    if sq_home and java:
        lines.append(f"**Native SonarQube:** ✅ found at `{sq_home}` (java: `{java}`) — Tier 2 available without Docker")
        native_scanner = _find_sonar_scanner()
        if native_scanner:
            lines.append(f"**sonar-scanner CLI:** ✅ `{native_scanner}`")
        else:
            lines.append(
                "**sonar-scanner CLI:** ⚠️  not found — "
                "extract the sonar-scanner zip to `~/.sensitive-scanner/sonar-scanner/` "
                "or set `SONAR_SCANNER_HOME`"
            )
    elif sq_home:
        lines.append(
            f"**Native SonarQube:** ⚠️  found at `{sq_home}` but Java is not on PATH — "
            "install Java 17+ to use it"
        )
    else:
        lines.append(
            "**Native SonarQube:** ℹ️  not found — to use without Docker, extract the "
            "SonarQube CE zip to `~/.sensitive-scanner/sonarqube/` or set `SONARQUBE_HOME`"
        )

    # Container runtime
    runtime = shutil.which("docker") or shutil.which("podman")
    if runtime:
        rt_name = Path(runtime).name
        lines.append(f"**Container runtime:** ✅ `{rt_name}` found — Docker-based Tier 2 also available")
    else:
        lines.append("**Container runtime:** ℹ️  not found (not required if native SonarQube is installed)")

    # spaCy NLP
    try:
        import spacy  # type: ignore
        try:
            spacy.load("en_core_web_sm")
            lines.append("**spaCy NLP (unstructured PII):** ✅ en_core_web_sm loaded")
        except OSError:
            lines.append(
                "**spaCy NLP:** ⚠️  spaCy installed but model missing — "
                "run `python -m spacy download en_core_web_sm`"
            )
    except ImportError:
        lines.append(
            "**spaCy NLP:** ℹ️  not installed (optional) — "
            "run `pip install spacy && python -m spacy download en_core_web_sm`"
        )

    # SonarQube
    sq = SonarQubeScanner()
    if start_sonarqube:
        native_available = bool(sq_home and java)
        docker_available = bool(runtime)
        if not native_available and not docker_available:
            lines.append("\n**SonarQube:** ❌ cannot start — no native install or container runtime found")
        else:
            mode = "native Java" if native_available else "Docker"
            lines.append(f"\n**Starting SonarQube ({mode})...** (this may take up to 90 seconds)")
            ok = await sq.start_sonarqube()
            sq_port = _read_sonar_port(sq_home) if sq_home else 9000
            sq_url = f"http://localhost:{sq_port}"
            lines.append(
                f"**SonarQube:** ✅ ready at {sq_url}"
                if ok
                else "**SonarQube:** ❌ failed to start — check installation or `docker/docker-compose.yml`"
            )
    else:
        sq_port = _read_sonar_port(sq_home) if sq_home else 9000
        sq_url = f"http://localhost:{sq_port}"
        ready = await sq._is_ready(sq_url)  # noqa: SLF001
        if ready:
            lines.append(f"**SonarQube:** ✅ running at {sq_url}")
        elif sq_home or runtime:
            lines.append(
                "**SonarQube:** ⏸ not running — "
                "call `check_scanner_status(start_sonarqube=True)` to start it"
            )
        else:
            lines.append("**SonarQube:** ℹ️  install SonarQube CE or Docker/Podman to enable Tier 2")

    # Active tier summary
    tier = 1
    if (sq_home and java) or runtime:
        tier = 2
    if os.environ.get("SONAR_TOKEN") and "sonarcloud.io" in os.environ.get("SONAR_HOST_URL", ""):
        tier = 3
    lines += [
        "",
        f"**Active tier:** {tier}",
        "- Tier 1 = Gitleaks + Semgrep + PII scanner (native binaries, no infrastructure)",
        "- Tier 2a = Tier 1 + SonarQube as native Java process (requires SonarQube CE zip + Java 17+, no Docker)",
        "- Tier 2b = Tier 1 + SonarQube via Docker/Podman",
        "- Tier 3 = Tier 2 + SonarCloud REST API (no local container needed)",
    ]

    return "\n".join(lines)


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
