from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import sys
import time
from pathlib import Path
from typing import Optional

import httpx

from models.finding import Finding, ScanConfig
from remediation.engine import RemediationEngine
from remediation.regulation_engine import RegulationEngine
from scanners.base import AbstractScanner
from scanners.constants import detect_container_runtime

_ENGINE = RemediationEngine()
_REG_ENGINE = RegulationEngine()

# Semgrep exits 1 when findings exist — expected, not an error.
_EXPECTED_EXIT_CODES = {0, 1}

# Rulesets to run.
# p/secrets   — 150+ service-specific secret/credential patterns (fast, high signal)
# p/owasp-top-ten — SQL injection, XSS, broken auth, etc.
# p/default is intentionally excluded: 500+ broad rules with high scan overhead
# and low marginal signal for secrets/PII use cases.
_RULESETS = [
    "p/secrets",
    "p/owasp-top-ten",
]

# Local ruleset cache — avoids hitting semgrep.dev on every scan.
_RULES_CACHE_DIR = Path.home() / ".sensitive-scanner" / "semgrep-rules"
# How long a cached ruleset file is considered fresh (seconds). Default 24 h.
_RULES_CACHE_TTL: int = int(os.environ.get("SEMGREP_RULES_TTL", str(24 * 3600)))
# Base URL for downloading semgrep registry packs as YAML.
_SEMGREP_REGISTRY_URL = "https://semgrep.dev/c/{ruleset}"


def _ruleset_cache_path(ruleset: str) -> Path:
    """Return the local cache path for a registry ruleset (e.g. 'p/secrets')."""
    safe_name = ruleset.replace("/", "_") + ".yaml"
    return _RULES_CACHE_DIR / safe_name


def _is_cache_fresh(path: Path) -> bool:
    """True if *path* exists and was modified within the TTL window."""
    try:
        return (time.time() - path.stat().st_mtime) < _RULES_CACHE_TTL
    except OSError:
        return False


async def _download_ruleset(ruleset: str, dest: Path) -> bool:
    """Download *ruleset* from the semgrep registry and save to *dest*.

    Returns True on success.  On any network/HTTP error the existing cached
    file (if present) is left untouched so the scan can still proceed offline.
    """
    import ssl as _ssl

    url = _SEMGREP_REGISTRY_URL.format(ruleset=ruleset)

    # Build an explicit SSL context so corporate proxy CA certs (ZScaler, etc.)
    # are handled correctly regardless of httpx version or env var precedence.
    # Priority: SEMGREP_RULES_SSL_VERIFY=false > REQUESTS_CA_BUNDLE / SSL_CERT_FILE > default.
    if os.environ.get("SEMGREP_RULES_SSL_VERIFY", "").lower() == "false":
        # Build a no-verification context — more reliable than passing verify=False
        # to httpx, which can be overridden by REQUESTS_CA_BUNDLE in some versions.
        _ssl_ctx = _ssl.create_default_context()
        _ssl_ctx.check_hostname = False
        _ssl_ctx.verify_mode = _ssl.CERT_NONE
        print(
            "[semgrep] WARNING: SSL verification disabled via SEMGREP_RULES_SSL_VERIFY=false",
            file=sys.stderr,
        )
        _verify: bool | str | _ssl.SSLContext = _ssl_ctx
    else:
        _ca_bundle = (
            os.environ.get("REQUESTS_CA_BUNDLE")
            or os.environ.get("SSL_CERT_FILE")
        )
        _verify = _ca_bundle if _ca_bundle else True

    try:
        async with httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            verify=_verify,
            trust_env=(_verify is not False and not isinstance(_verify, _ssl.SSLContext)),
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(resp.content)
            return True
    except Exception as exc:
        print(
            f"[semgrep] Could not refresh ruleset cache for '{ruleset}': {exc}",
            file=sys.stderr,
        )
        return False


async def _ensure_cached_rulesets() -> list[str]:
    """Return a list of --config values for the configured rulesets.

    For each ruleset:
    - If a fresh local copy exists, return its path (no network call).
    - If the copy is stale *or* absent, attempt a download; fall back to the
      stale copy if the download fails, and fall back to the registry name
      (original behaviour) if no copy exists at all.
    """
    config_values: list[str] = []
    for ruleset in _RULESETS:
        cache_path = _ruleset_cache_path(ruleset)
        if _is_cache_fresh(cache_path):
            config_values.append(str(cache_path))
            continue
        # Attempt refresh
        ok = await _download_ruleset(ruleset, cache_path)
        if ok:
            config_values.append(str(cache_path))
        elif cache_path.exists():
            # Stale but usable — beats another network hop
            print(
                f"[semgrep] Using stale cache for '{ruleset}' (download failed)",
                file=sys.stderr,
            )
            config_values.append(str(cache_path))
        else:
            # No cache at all — fall back to registry name so semgrep handles it
            config_values.append(ruleset)
    return config_values

_SEVERITY_MAP = {
    "ERROR": "critical",
    "WARNING": "high",
    "INFO": "medium",
}


def _find_semgrep() -> Optional[str]:
    """
    Locate the semgrep executable.  Checks (in order):
    1. The Python Scripts directory alongside the running interpreter
       (where `pip install semgrep` places semgrep.exe on Windows)
    2. System PATH
    """
    exe = "semgrep.exe" if platform.system() == "Windows" else "semgrep"

    # Scripts dir sits next to the Python executable (or one level up on some layouts)
    for candidate_dir in (
        Path(sys.executable).parent / "Scripts",  # Windows venv / user install
        Path(sys.executable).parent,              # Unix venv
    ):
        candidate = candidate_dir / exe
        if candidate.exists():
            return str(candidate)

    return shutil.which("semgrep")  # fall back to PATH


class SemgrepScanner(AbstractScanner):
    @property
    def name(self) -> str:
        return "semgrep"

    async def is_available(self) -> bool:
        # Use asyncio.sleep(0) to yield to the event loop — this method is
        # intentionally async to satisfy the AbstractScanner interface contract.
        await asyncio.sleep(0)
        if _find_semgrep():
            return True
        return detect_container_runtime() is not None

    async def _resolve_binary(self) -> list[str]:
        path = _find_semgrep()
        if path:
            return [path]
        runtime = detect_container_runtime() or "docker"
        return [runtime, "run", "--rm", "-v", "{source}:/src", "-w", "/src", "semgrep/semgrep:latest"]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        try:
            return await self._run(config)
        except Exception as exc:
            print(f"[semgrep] Scan failed: {exc}", file=sys.stderr)
            return []

    async def _run(self, config: ScanConfig) -> list[Finding]:
        cmd_prefix = await self._resolve_binary()
        source_path = str(Path(config.path).resolve())
        cmd_prefix = [p.replace("{source}", source_path) for p in cmd_prefix]
        scan_target = "/src" if "{source}" in " ".join(cmd_prefix) else source_path

        # Resolve rulesets — prefer locally cached YAML files to avoid a
        # semgrep.dev network round-trip on every scan.
        resolved_rulesets = await _ensure_cached_rulesets()

        # Build config flags — one --config per ruleset
        config_flags: list[str] = []
        for rs in resolved_rulesets:
            config_flags += ["--config", rs]

        exclude_flags: list[str] = []
        for excluded in config.exclude_paths:
            # Use glob pattern so the directory is excluded at any depth in the tree
            exclude_flags += ["--exclude", f"*/{excluded}", "--exclude", excluded]
        for pattern in config.exclude_patterns:
            exclude_flags += ["--exclude", pattern]

        args = [
            *cmd_prefix,
            "scan",
            *config_flags,
            "--json",
            "--no-git-ignore",   # respect nothing — full scan of target
            "--quiet",
            "--metrics=off",     # disable telemetry / registry auth checks
            "--oss-only",        # avoid Pro engine requirements
            "--jobs", str(max(1, (os.cpu_count() or 2) // 2)),  # use half logical cores
            *exclude_flags,
            scan_target,
        ]

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={
                **os.environ,
                "SEMGREP_SEND_METRICS": "off",  # suppress telemetry network calls
                "SEMGREP_SETTINGS_FILE": str(
                    Path.home() / ".sensitive-scanner" / "semgrep-settings.yml"
                ),
            },
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            print("[semgrep] Scan timed out after 300 s — skipping.", file=sys.stderr)
            return []

        if proc.returncode not in _EXPECTED_EXIT_CODES:
            err_text = stderr.decode(errors="replace")
            hint = ""
            if proc.returncode == 2:
                hint = " (hint: run 'semgrep login' if registry rules require authentication)"
            print(
                f"[semgrep] Unexpected exit code {proc.returncode}{hint}: "
                f"{err_text[:500]}",
                file=sys.stderr,
            )
            return []

        raw = stdout.decode(errors="replace").strip()
        if not raw:
            return []

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"[semgrep] JSON parse error: {exc}", file=sys.stderr)
            return []

        findings: list[Finding] = []
        excluded_files = set(config.exclude_files)
        for result in data.get("results", []):
            f = self._normalise(result, source_path, config.show_secrets)
            if f and f.file not in excluded_files:
                findings.append(f)
        return findings

    def _normalise(self, item: dict, base_path: str, show_secrets: bool = False) -> Finding | None:
        check_id: str = item.get("check_id", "unknown")
        path_raw: str = item.get("path", "")

        try:
            file_rel = str(Path(path_raw).relative_to(Path(base_path).resolve()))
        except ValueError:
            file_rel = path_raw

        start: dict = item.get("start", {})
        line: int = start.get("line", 0) or 0

        extra: dict = item.get("extra", {})
        message: str = extra.get("message", "")
        raw_severity: str = extra.get("severity", "WARNING").upper()
        severity = _SEVERITY_MAP.get(raw_severity, "medium")

        # Extract a snippet to redact
        lines_snippet: str = extra.get("lines", "").strip()
        if show_secrets:
            match_redacted = lines_snippet if lines_snippet else "****"
        else:
            match_redacted = Finding.redact(lines_snippet) if lines_snippet else "****"

        category, rule = _ENGINE.resolve(check_id)
        if rule:
            severity = rule.severity  # rule catalogue overrides semgrep severity

        # Confidence: prefer metadata.confidence, fall back to severity proxy
        _META_CONF = {"HIGH": 0.88, "MEDIUM": 0.70, "LOW": 0.50}
        _SEV_CONF  = {"ERROR": 0.85, "WARNING": 0.70, "INFO": 0.50}
        meta_conf: str = extra.get("metadata", {}).get("confidence", "").upper()
        confidence = _META_CONF.get(meta_conf) or _SEV_CONF.get(raw_severity, 0.70)

        return Finding(
            id=Finding.make_id(file_rel, line, check_id),
            scanners=["semgrep"],
            category=category,
            severity=severity,
            confidence=confidence,
            file=file_rel,
            line=line,
            match=match_redacted,
            rule_id=check_id,
            message=message,
            remediation_description=rule.description if rule else "",
            fix_steps=rule.fix_steps if rule else [],
            references=rule.references if rule else [],
            regulations=_REG_ENGINE.lookup(category),
        )
