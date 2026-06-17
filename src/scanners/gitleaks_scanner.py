from __future__ import annotations

import asyncio
import fnmatch
import json
import shutil
import sys
import tempfile
from pathlib import Path

from models.finding import Finding, ScanConfig
from remediation.engine import RemediationEngine
from remediation.regulation_engine import RegulationEngine
from scanners.base import AbstractScanner
from scanners.binary_manager import ensure_binary
from scanners.constants import detect_container_runtime

_CONFIG_PATH = Path(__file__).parent.parent / "config" / "gitleaks.toml"
_ENGINE = RemediationEngine()
_REG_ENGINE = RegulationEngine()

# Gitleaks exits 1 when leaks are found — that is expected, not an error.
_EXPECTED_EXIT_CODES = {0, 1}


class GitleaksScanner(AbstractScanner):
    @property
    def name(self) -> str:
        return "gitleaks"

    async def is_available(self) -> bool:
        # Prefer the managed binary; fall back to system PATH; then Docker/Podman.
        if (await ensure_binary("gitleaks")) is not None:
            return True
        if shutil.which("gitleaks"):
            return True
        return detect_container_runtime() is not None

    async def _resolve_binary(self) -> list[str]:
        """Return the command prefix to invoke gitleaks."""
        bin_path = await ensure_binary("gitleaks")
        if bin_path:
            return [str(bin_path)]
        if shutil.which("gitleaks"):
            return ["gitleaks"]
        # Container fallback
        runtime = detect_container_runtime() or "docker"
        return [runtime, "run", "--rm", "-v", "{source}:/code", "zricethezav/gitleaks:latest"]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        try:
            return await self._run(config)
        except Exception as exc:
            print(f"[gitleaks] Scan failed: {exc}", file=sys.stderr)
            return []

    async def _run(self, config: ScanConfig) -> list[Finding]:
        cmd_prefix = await self._resolve_binary()
        source_path = str(Path(config.path).resolve())

        # Substitute {source} placeholder used in the Docker invocation form
        cmd_prefix = [p.replace("{source}", source_path) for p in cmd_prefix]

        # If running via container the source arg is /code, else the real path
        scan_source = "/code" if "{source}" in " ".join(cmd_prefix) else source_path

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        try:
            args = [
                *cmd_prefix,
                "detect",
                "--source", scan_source,
                "--report-format", "json",
                "--report-path", report_path,
            ]

            if _CONFIG_PATH.exists():
                args += ["--config", str(_CONFIG_PATH)]

            if not config.include_git_history:
                args.append("--no-git")

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()

            if proc.returncode not in _EXPECTED_EXIT_CODES:
                print(
                    f"[gitleaks] Unexpected exit code {proc.returncode}: "
                    f"{stderr.decode(errors='replace')}",
                    file=sys.stderr,
                )
                return []

            try:
                raw = Path(report_path).read_text(encoding="utf-8")
                data = json.loads(raw) if raw.strip() else []
            except (json.JSONDecodeError, FileNotFoundError):
                return []

            # Post-filter: drop any finding whose path contains an excluded directory
            # or matches a specifically excluded file (compare as relative paths).
            excluded = set(config.exclude_paths)
            excluded_files = set(config.exclude_files)
            scan_root = Path(config.path).resolve()

            def _rel(raw: str) -> str:
                try:
                    return str(Path(raw).relative_to(scan_root)).replace("\\", "/")
                except ValueError:
                    return raw.replace("\\", "/")

            exclude_patterns = config.exclude_patterns
            findings = [
                self._normalise(item, config.path, config.show_secrets)
                for item in (data or [])
                if not any(part in excluded for part in Path(item.get("File", "")).parts)
                and _rel(item.get("File", "")) not in excluded_files
                and not (exclude_patterns and any(
                    fnmatch.fnmatch(_rel(item.get("File", "")), pat) for pat in exclude_patterns
                ))
            ]
            return findings
        finally:
            Path(report_path).unlink(missing_ok=True)

    def _normalise(self, item: dict, base_path: str, show_secrets: bool = False) -> Finding:
        rule_id: str = item.get("RuleID", "unknown")
        file_raw: str = item.get("File", "")

        # Make the file path relative to the scan root
        try:
            file_rel = str(Path(file_raw).relative_to(Path(base_path).resolve()))
        except ValueError:
            file_rel = file_raw

        secret: str = item.get("Secret", "") or item.get("Match", "")
        line: int = item.get("StartLine", item.get("Line", 0)) or 0

        category, rule = _ENGINE.resolve(rule_id)
        severity = rule.severity if rule else "high"

        _SEV_CONF = {"critical": 0.90, "high": 0.82, "medium": 0.70, "low": 0.55}
        confidence = _SEV_CONF.get(severity, 0.70)

        return Finding(
            id=Finding.make_id(file_rel, line, rule_id),
            scanners=["gitleaks"],
            category=category,
            severity=severity,
            confidence=confidence,
            file=file_rel,
            line=line,
            match=secret if show_secrets else Finding.redact(secret),
            rule_id=rule_id,
            message=item.get("Description", ""),
            remediation_description=rule.description if rule else "",
            fix_steps=rule.fix_steps if rule else [],
            references=rule.references if rule else [],
            regulations=_REG_ENGINE.lookup(category),
        )
