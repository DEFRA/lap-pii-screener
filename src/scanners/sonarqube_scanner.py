from __future__ import annotations

import asyncio
import os
import platform
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import httpx

from models.finding import Finding, ScanConfig
from remediation.engine import RemediationEngine
from scanners.base import AbstractScanner
from scanners.constants import detect_container_runtime

_ENGINE = RemediationEngine()

_DOCKER_COMPOSE_FILE = Path(__file__).parent.parent / "docker" / "docker-compose.yml"
_SONAR_SCANNER_IMAGE = "sonarsource/sonar-scanner-cli:latest"

# Default paths for native (non-Docker) installs
_NATIVE_SQ_DEFAULT = Path.home() / ".sensitive-scanner" / "sonarqube"
_NATIVE_SCANNER_DEFAULT = Path.home() / ".sensitive-scanner" / "sonar-scanner"


def _find_native_sonarqube() -> Optional[Path]:
    """Return the SonarQube installation root if a native install is found."""
    env = os.environ.get("SONARQUBE_HOME")
    if env and Path(env).exists():
        return Path(env)
    # Exact default path
    if _NATIVE_SQ_DEFAULT.exists():
        return _NATIVE_SQ_DEFAULT
    # Versioned directory: ~/.sensitive-scanner/sonarqube-26.x.x.xxxxx/
    parent = _NATIVE_SQ_DEFAULT.parent
    if parent.exists():
        matches = sorted(
            (p for p in parent.glob("sonarqube-*") if p.is_dir() and (p / "bin").exists()),
            reverse=True,  # newest version first
        )
        if matches:
            return matches[0]
    for candidate in [  # pragma: no cover - Windows fixed-path discovery fallback
        Path("C:/sonarqube"),
        Path("C:/tools/sonarqube"),
        Path("C:/Program Files/SonarQube"),
    ]:
        if candidate.exists():
            return candidate
    return None


def _read_sonar_port(sq_home: Path) -> int:
    """Read sonar.web.port from sonar.properties, defaulting to 9100.
    9100 is the team standard port — avoids the ZScaler conflict on 9000.
    """
    props = sq_home / "conf" / "sonar.properties"
    if not props.exists():
        return 9100
    for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("sonar.web.port") and "=" in line:
            try:
                return int(line.split("=", 1)[1].strip())
            except ValueError:
                pass
    return 9100


def _resolve_host_url() -> str:
    """Return the SonarQube base URL, preferring SONAR_HOST_URL env var.
    Falls back to reading sonar.web.port from sonar.properties so a port
    change (e.g. 9100 to avoid ZScaler) is picked up automatically.
    """
    env = os.environ.get("SONAR_HOST_URL", "")
    if env:
        return env.rstrip("/")
    sq_home = _find_native_sonarqube()
    port = _read_sonar_port(sq_home) if sq_home else 9100
    return f"http://localhost:{port}"


def _find_sonar_scanner() -> Optional[str]:
    """Return path to sonar-scanner CLI executable, or None."""
    env = os.environ.get("SONAR_SCANNER_HOME")
    if env:
        exe = "sonar-scanner.bat" if sys.platform == "win32" else "sonar-scanner"
        p = Path(env) / "bin" / exe
        if p.exists():
            return str(p)
    exe = "sonar-scanner.bat" if sys.platform == "win32" else "sonar-scanner"
    p = _NATIVE_SCANNER_DEFAULT / "bin" / exe
    if p.exists():
        return str(p)
    return shutil.which("sonar-scanner")


def _native_start_script(sq_home: Path) -> Optional[Path]:
    """Return the OS-appropriate SonarQube start script, or None if not found."""
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Windows":
        script = sq_home / "bin" / "windows-x86-64" / "StartSonar.bat"
    elif system == "Linux":
        arch = "aarch64" if ("arm" in machine or "aarch" in machine) else "x86-64"
        script = sq_home / "bin" / f"linux-{arch}" / "sonar.sh"
    else:  # macOS
        script = sq_home / "bin" / "macosx-universal-64" / "sonar.sh"
    return script if script.exists() else None

# SonarQube severity → our model
_SEVERITY_MAP = {
    "BLOCKER": "critical",
    "CRITICAL": "critical",
    "MAJOR": "high",
    "MINOR": "medium",
    "INFO": "low",
}

# Issue types for api/issues/search — SECURITY_HOTSPOT was removed in SonarQube 10
# and now lives at api/hotspots/search
_TYPES = "VULNERABILITY,BUG"

# SonarQube securityCategory field → our internal category.
# Used for hotspots where securityCategory is the most reliable signal.
# Categories that have no PII/secret relevance (injections, CSRF, DoS etc.)
# are intentionally omitted — hotspots in those categories will be dropped.
_SONAR_SECURITY_CATEGORY_MAP: dict[str, str] = {
    "credentials":              "hardcoded_password",
    "auth":                     "hardcoded_password",  # NOSONAR - SonarQube securityCategory name, not a secret
    "encrypt-data":             "encryption_key",
    "weak-cryptography":        "encryption_key",
    "sql-injection":            "db_connection_string",
}


# Rule-ID prefixes that are purely code-quality / style rules with no
# security or PII relevance.  Findings from these are silently dropped so
# they never appear as false-positive 'generic_secret' findings.
_NON_SECURITY_RULE_PREFIXES: tuple[str, ...] = (
    "css:",
    "html:",
    "web:",
    "xml:",
    "jsp:",
    "plsql:",
)


def _is_non_security_rule(rule_id: str) -> bool:
    rl = rule_id.lower()
    return any(rl.startswith(p) for p in _NON_SECURITY_RULE_PREFIXES)


def _apply_windows_sonar_props(sonar_props: Path, port: int = 9100) -> None:
    """
    Patch sonar.properties for Windows: set a non-default web port to avoid
    conflicts with other software (e.g. ZScaler) on port 9000.

    Note: bootstrap.system_call_filter was removed in Elasticsearch 8.x
    (bundled with SonarQube 10+). Do NOT pass it — ES 8 will fatal-error.
    """
    if not sonar_props.exists():
        return

    text = sonar_props.read_text(encoding="utf-8", errors="replace")
    # Only consider active (non-commented) lines for "already set" checks
    active_lines = [
        l.strip() for l in text.splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]

    # Remove the old ES 7.x setting if it was previously added by us
    if "bootstrap.system_call_filter" in text:
        lines = text.splitlines(keepends=True)
        text = "".join(l for l in lines if "bootstrap.system_call_filter" not in l)
        # Path is built from the operator-set SONARQUBE_HOME (or fixed discovery
        # locations) plus the hardcoded "conf/sonar.properties" filename, and is
        # confirmed to exist above — not untrusted/remote input.
        sonar_props.write_text(text, encoding="utf-8")  # NOSONAR
        print("[sonarqube] Removed obsolete bootstrap.system_call_filter (not valid in ES 8.x)", file=sys.stderr)
        active_lines = [
            l.strip() for l in text.splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]

    # Set web port only if no active (uncommented) sonar.web.port line exists
    if not any(l.startswith("sonar.web.port") for l in active_lines):
        patched = text.rstrip("\n") + "\n\n# Added by sensitive-scanner for Windows compatibility\n"
        patched += f"sonar.web.port={port}\n"
        # Trusted, operator-controlled path (see note above).
        sonar_props.write_text(patched, encoding="utf-8")  # NOSONAR
        print(f"[sonarqube] Set sonar.web.port={port} in sonar.properties", file=sys.stderr)


def _print_startup_diagnostics(log_dir: Path) -> None:
    """Print the last lines of es.log and sonar.log to help diagnose startup failures."""
    for log_name in ("es.log", "sonar.log"):
        log_file = log_dir / log_name
        if not log_file.exists():
            continue
        try:
            lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
            tail = lines[-30:] if len(lines) > 30 else lines
            # Find ERROR/WARN lines for a concise summary
            errors = [l for l in tail if "ERROR" in l or "WARN" in l or "Exception" in l]
            print(f"\n[sonarqube] ── {log_name} (last errors) ──", file=sys.stderr)
            for line in (errors or tail[-10:]):
                print(f"  {line}", file=sys.stderr)
        except OSError:  # pragma: no cover - defensive log read
            pass
    print(
        "\n[sonarqube] Common fixes:\n"
        "  1. Run CMD as Administrator (first run only — SQ needs to create data directories)\n"
        "  2. Check port 9000/9001 not in use:  netstat -ano | findstr ':9000'\n"
        "  3. Ensure at least 3 GB of free RAM\n"
        "  4. Shorten the SonarQube install path if it exceeds ~100 chars (Windows MAX_PATH)\n"
        "  5. Full logs:  " + str(log_dir),
        file=sys.stderr,
    )


class SonarQubeScanner(AbstractScanner):
    @property
    def name(self) -> str:
        return "sonarqube"

    async def is_available(self) -> bool:
        # Native Java SonarQube (no container runtime needed)
        if _find_native_sonarqube() and shutil.which("java"):
            return True
        # Docker/Podman
        if detect_container_runtime() is not None:
            return True
        # SonarCloud — token + external URL provided
        host = os.environ.get("SONAR_HOST_URL", "")
        token = os.environ.get("SONAR_TOKEN", "")
        if token and host and "sonarcloud.io" in host:
            return True
        return False

    # ─── Public helpers ────────────────────────────────────────────────────

    async def start_sonarqube(self) -> bool:
        """
        Start SonarQube — tries native Java process first, then Docker/Podman.
        Returns True when the server is ready at http://localhost:9000.
        """
        sq_home = _find_native_sonarqube()
        if sq_home and shutil.which("java"):
            return await self._start_native(sq_home)

        runtime = detect_container_runtime()
        if not runtime:
            print("[sonarqube] No native SonarQube install or container runtime found.", file=sys.stderr)
            return False
        return await self._start_docker(runtime)

    async def scan(self, config: ScanConfig) -> list[Finding]:
        try:
            return await self._run(config)
        except (OSError, RuntimeError, httpx.HTTPError, ValueError) as exc:
            print(f"[sonarqube] Scan failed: {exc}", file=sys.stderr)
            return []

    # ─── Internal ──────────────────────────────────────────────────────────

    async def _start_native(self, sq_home: Path) -> bool:
        """Start SonarQube as a native Java process and wait for readiness."""
        script = _native_start_script(sq_home)
        if not script:
            print(f"[sonarqube] No start script found under {sq_home}/bin/ — "
                  "check your SonarQube installation.", file=sys.stderr)
            return False

        log_dir = sq_home / "logs"
        sonar_props = sq_home / "conf" / "sonar.properties"

        # ── Pre-flight: apply Windows first-run fixes if not already set ──
        if sys.platform == "win32":
            _apply_windows_sonar_props(sonar_props)

        configured_port = _read_sonar_port(sq_home)
        print(f"[sonarqube] Starting native SonarQube from {script}", file=sys.stderr)
        print(f"[sonarqube] Web port: {configured_port}  |  Startup logs: {log_dir}", file=sys.stderr)

        if sys.platform == "win32":
            # StartSonar.bat runs SonarQube in the FOREGROUND — it never exits while SQ is running.
            # We must start it in its own detached console so our process does not block.
            # cwd must be the script's own directory — StartSonar.bat uses relative paths internally.
            import subprocess
            try:
                await asyncio.create_subprocess_exec(
                    "cmd", "/c", script.name,
                    cwd=str(script.parent),
                    creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.CREATE_NEW_PROCESS_GROUP,
                )
            except OSError as exc:
                print(f"[sonarqube] Could not launch SonarQube start script: {exc}", file=sys.stderr)
                print(
                    "[sonarqube] Try running CMD as Administrator for the first launch, "
                    "or start SonarQube manually before scanning.",
                    file=sys.stderr,
                )
                return False
        else:
            # On Linux/macOS, sonar.sh start daemonises and returns immediately.
            proc = await asyncio.create_subprocess_exec(
                str(script), "start",
                cwd=str(script.parent),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

        # Prefer explicit env var; fall back to the port configured in sonar.properties
        host = os.environ.get("SONAR_HOST_URL") or f"http://localhost:{configured_port}"
        print(f"[sonarqube] Waiting for SonarQube at {host} (up to 120 s)...", file=sys.stderr)
        ready = await self._wait_ready(host)
        if not ready:
            print("[sonarqube] Timed out waiting for SonarQube.", file=sys.stderr)
            _print_startup_diagnostics(log_dir)
        return ready

    async def _start_docker(self, runtime: str) -> bool:
        """Bring up the Docker Compose SonarQube stack."""
        compose_cmd = self._compose_cmd(runtime)
        proc = await asyncio.create_subprocess_exec(
            *compose_cmd,
            "-f", str(_DOCKER_COMPOSE_FILE),
            "up", "-d",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        if proc.returncode != 0:
            print("[sonarqube] docker compose up failed.", file=sys.stderr)
            return False
        return await self._wait_ready(_resolve_host_url())

    @staticmethod
    def _compose_cmd(runtime: str) -> list[str]:
        return [runtime, "compose"]

    async def _ensure_server_running(self, host: str) -> bool:
        """Return True if server is reachable, auto-starting it if needed."""
        if await self._is_ready(host):
            return True
        sq_home = _find_native_sonarqube()
        if sq_home and shutil.which("java"):
            print("[sonarqube] Server not running — auto-starting native Java SonarQube...", file=sys.stderr)
            return await self._start_native(sq_home)
        runtime = detect_container_runtime()
        if runtime:
            print("[sonarqube] No native Java install found — auto-starting via Docker...", file=sys.stderr)
            return await self._start_docker(runtime)
        print(
            f"[sonarqube] Server at {host} is not reachable and no native Java install "
            "or container runtime was found.",
            file=sys.stderr,
        )
        return False

    async def _run(self, config: ScanConfig) -> list[Finding]:
        host = config.sonar_host_url or _resolve_host_url()
        token = config.sonar_token or os.environ.get("SONAR_TOKEN", "")
        project_key = config.sonar_project_key or re.sub(r"[^a-z0-9_\-.]", "_", config.project_name.lower())
        source_path = str(Path(config.path).resolve())

        if not token:
            print("[sonarqube] SONAR_TOKEN not set — skipping SonarQube scan.", file=sys.stderr)
            return []

        if not await self._ensure_server_running(host):
            return []

        # Create project if it doesn't already exist
        await self._ensure_project(host, token, project_key, config.project_name)

        # Run sonar-scanner
        ok = await self._run_scanner(host, token, project_key, source_path)
        if not ok:
            return []

        # Poll until analysis task completes
        await self._poll_task(host, token, project_key)

        # Fetch issues via REST API
        show = config.show_secrets
        excluded_files = set(config.exclude_files)
        issues = await self._fetch_issues(host, token, project_key, source_path, show)
        hotspots = await self._fetch_hotspots(host, token, project_key, source_path, show)
        return [f for f in issues + hotspots if f.file not in excluded_files]

    async def _run_scanner(
        self, host: str, token: str, project_key: str, source_path: str
    ) -> bool:
        # Prefer native sonar-scanner CLI (works with both native SQ and Docker SQ)
        native_scanner = _find_sonar_scanner()
        if native_scanner:
            # Use a per-user working directory (under the home dir, which is not
            # world-writable) rather than a shared, predictably-named directory in
            # the public temp space — that would be vulnerable to symlink/TOCTOU
            # attacks. Kept reasonably short to limit Windows MAX_PATH issues with
            # the AnalysisTempFolder bean in the scanner engine.
            work_dir = str(Path.home() / ".sensitive-scanner" / "sonar-work")
            Path(work_dir).mkdir(parents=True, exist_ok=True)
            cmd = [
                native_scanner,
                f"-Dsonar.projectKey={project_key}",
                f"-Dsonar.sources={source_path}",
                f"-Dsonar.host.url={host}",
                f"-Dsonar.token={token}",
                "-Dsonar.scm.disabled=true",
                f"-Dsonar.working.directory={work_dir}",
            ]
        else:
            # Fall back to Docker sonar-scanner image
            runtime = detect_container_runtime()
            if not runtime:
                print(
                    "[sonarqube] sonar-scanner CLI not found and no container runtime available. "
                    "Install sonar-scanner to ~/.sensitive-scanner/sonar-scanner/ or set SONAR_SCANNER_HOME.",
                    file=sys.stderr,
                )
                return False
            cmd = [
                runtime, "run", "--rm",
                "--network", "host",
                "-e", f"SONAR_HOST_URL={host}",
                "-e", f"SONAR_TOKEN={token}",
                "-v", f"{source_path}:/usr/src",
                _SONAR_SCANNER_IMAGE,
                f"-Dsonar.projectKey={project_key}",
                "-Dsonar.sources=/usr/src",
                "-Dsonar.scm.disabled=true",
            ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            print(
                f"[sonarqube] Scanner exited {proc.returncode}: "
                f"{stderr.decode(errors='replace')[:500]}",
                file=sys.stderr,
            )
            return False
        return True

    async def _is_ready(self, host: str) -> bool:
        url = urljoin(host, "/api/system/status")
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(url)
                data = resp.json()
                return data.get("status") == "UP"
        except (httpx.HTTPError, ValueError):
            return False

    async def _wait_ready(self, host: str, max_wait: int = 120) -> bool:
        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline:
            if await self._is_ready(host):
                return True
            await asyncio.sleep(5)
        return False

    async def _ensure_project(
        self, host: str, token: str, project_key: str, name: str
    ) -> None:
        url = urljoin(host, "/api/projects/create")
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    url,
                    data={"project": project_key, "name": name},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )
        except httpx.HTTPError:
            pass  # Project may already exist; scanner will handle it.

    async def _poll_task(
        self, host: str, token: str, project_key: str, max_wait: int = 300
    ) -> None:
        """Wait for the most recent CE analysis task to finish."""
        url = urljoin(host, "/api/ce/activity")
        deadline = time.monotonic() + max_wait
        async with httpx.AsyncClient() as client:
            while time.monotonic() < deadline:
                try:
                    resp = await client.get(
                        url,
                        params={"component": project_key, "status": "IN_PROGRESS,PENDING", "ps": "1"},
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=10,
                    )
                    data = resp.json()
                    if not data.get("tasks"):
                        return  # No pending tasks — analysis is done
                except (httpx.HTTPError, ValueError):
                    pass
                await asyncio.sleep(5)

    @staticmethod
    def _source_line(base_path: str, file_rel: str, line: int) -> str:
        """Return the stripped source line from disk, or '****' if unreadable."""
        try:
            full = Path(base_path) / file_rel
            lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
            if 1 <= line <= len(lines):
                return lines[line - 1].strip()
        except OSError:
            pass
        return "****"

    async def _fetch_issues(
        self, host: str, token: str, project_key: str, base_path: str,
        show_secrets: bool = False,
    ) -> list[Finding]:
        findings: list[Finding] = []
        page = 1
        page_size = 500

        async with httpx.AsyncClient(timeout=30) as client:
            while True:
                try:
                    resp = await client.get(
                        urljoin(host, "/api/issues/search"),
                        params={
                            "components": project_key,   # 'componentKeys' deprecated since SQ 10.2
                            "types": _TYPES,
                            "ps": page_size,
                            "p": page,
                        },
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except (httpx.HTTPError, ValueError) as exc:
                    print(f"[sonarqube] Failed to fetch issues: {exc}", file=sys.stderr)
                    break

                issues = data.get("issues", [])
                for issue in issues:
                    f = self._normalise_issue(issue, project_key, base_path, show_secrets)
                    if f:
                        findings.append(f)

                total = data.get("paging", {}).get("total", 0)
                if page * page_size >= total:
                    break
                page += 1

        return findings

    @staticmethod
    def _normalise_hotspot(
        hs: dict, project_key: str, base_path: str, show_secrets: bool
    ) -> Optional["Finding"]:
        """Convert a raw hotspot dict from the API into a Finding, or None to skip."""
        _HOTSPOT_SEVERITY = {"HIGH": "critical", "MEDIUM": "high", "LOW": "medium"}
        _PROB_CONF = {"HIGH": 0.82, "MEDIUM": 0.65, "LOW": 0.48}

        component: str = hs.get("component", "")
        file_rel = component.replace(f"{project_key}:", "", 1) if ":" in component else component
        text_range: dict = hs.get("textRange", {})
        line: int = text_range.get("startLine", 0) or 0
        rule_id: str = hs.get("ruleKey", "security_hotspot")
        raw_message: str = hs.get("message", "")
        prob: str = hs.get("vulnerabilityProbability", "MEDIUM").upper()
        severity = _HOTSPOT_SEVERITY.get(prob, "high")
        sonar_sec_cat: str = hs.get("securityCategory", "").lower()

        if sonar_sec_cat and sonar_sec_cat in _SONAR_SECURITY_CATEGORY_MAP:
            category = _SONAR_SECURITY_CATEGORY_MAP[sonar_sec_cat]
            rule = _ENGINE.lookup(category)
        else:
            category, rule = _ENGINE.resolve(rule_id)

        if category == "generic_secret":
            return None

        if rule:
            severity = rule.severity

        confidence = _PROB_CONF.get(prob, 0.65)
        sec_label = sonar_sec_cat.replace("-", " ").title() if sonar_sec_cat else "Security Hotspot"
        message = (
            f"[{sec_label}] {raw_message}" if raw_message
            else f"[{sec_label}] Security hotspot — review required"
        )
        match = SonarQubeScanner._source_line(base_path, file_rel, line) if show_secrets else "****"

        return Finding(
            id=Finding.make_id(file_rel, line, rule_id),
            scanners=["sonarqube"],
            category=category,
            severity=severity,
            confidence=confidence,
            file=file_rel,
            line=line,
            match=match,
            rule_id=rule_id,
            message=message,
            remediation_description=rule.description if rule else "",
            fix_steps=rule.fix_steps if rule else [],
            references=rule.references if rule else [],
        )

    async def _fetch_hotspots(
        self, host: str, token: str, project_key: str, base_path: str,
        show_secrets: bool = False,
    ) -> list[Finding]:
        """Fetch security hotspots via api/hotspots/search (SonarQube 10+ endpoint)."""
        findings: list[Finding] = []
        page = 1
        page_size = 500

        async with httpx.AsyncClient(timeout=30) as client:
            while True:
                try:
                    resp = await client.get(
                        urljoin(host, "/api/hotspots/search"),
                        params={
                            "project": project_key,
                            "status": "TO_REVIEW",
                            "ps": page_size,
                            "p": page,
                        },
                        headers={"Authorization": f"Bearer {token}"},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except (httpx.HTTPError, ValueError) as exc:
                    print(f"[sonarqube] Failed to fetch hotspots: {exc}", file=sys.stderr)
                    break

                for hs in data.get("hotspots", []):
                    f = self._normalise_hotspot(hs, project_key, base_path, show_secrets)
                    if f:
                        findings.append(f)

                paging = data.get("paging", {})
                if page * page_size >= paging.get("total", 0):
                    break
                page += 1

        return findings

    def _normalise_issue(
        self, issue: dict, project_key: str, base_path: str,
        show_secrets: bool = False,
    ) -> Optional[Finding]:
        rule_id: str = issue.get("rule", "unknown")

        # Drop non-security language rules (CSS, HTML, XML etc.) that have no
        # PII/secret relevance and would otherwise fall through to generic_secret.
        if _is_non_security_rule(rule_id):
            return None
        # component looks like "project_key:path/to/file.py"
        component: str = issue.get("component", "")
        file_rel = component.replace(f"{project_key}:", "", 1) if ":" in component else component

        text_range: dict = issue.get("textRange", {})
        line: int = text_range.get("startLine", issue.get("line", 0)) or 0
        message: str = issue.get("message", "")
        raw_severity: str = issue.get("severity", "MAJOR").upper()
        severity = _SEVERITY_MAP.get(raw_severity, "medium")

        category, rule = _ENGINE.resolve(rule_id)

        # Drop anything that fell through to the generic_secret fallback — it
        # means neither the rule ID nor any keyword matched a known category.
        # Such findings carry no match text and no useful category, making them
        # noise.  Only surface SonarQube issues that map to a real category.
        if category == "generic_secret":
            return None

        if rule:
            severity = rule.severity

        _SEV_CONF = {"critical": 0.82, "high": 0.70, "medium": 0.58, "low": 0.48}
        confidence = _SEV_CONF.get(severity, 0.65)

        return Finding(
            id=Finding.make_id(file_rel, line, rule_id),
            scanners=["sonarqube"],
            category=category,
            severity=severity,
            confidence=confidence,
            file=file_rel,
            line=line,
            match=self._source_line(base_path, file_rel, line) if show_secrets else "****",  # SonarQube API does not expose raw matched text
            rule_id=rule_id,
            message=message,
            remediation_description=rule.description if rule else "",
            fix_steps=rule.fix_steps if rule else [],
            references=rule.references if rule else [],
        )
