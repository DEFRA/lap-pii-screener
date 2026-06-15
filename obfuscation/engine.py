"""Apply approved obfuscation replacements to source files, with backup/rollback."""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from obfuscation.session import ReviewItem, ReviewSession
    from rich.console import Console


@dataclass
class ItemResult:
    finding_id: str
    file: str
    line: int
    replacement: str
    applied: bool
    reason: str = ""


@dataclass
class ApplyResult:
    item_results: list[ItemResult] = field(default_factory=list)
    backed_up: list[str] = field(default_factory=list)

    @property
    def applied_count(self) -> int:
        return sum(1 for r in self.item_results if r.applied)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.item_results if not r.applied)


def _backup_file(src: Path, backup_dir: Path, target_root: Path) -> Path:
    """Copy *src* into *backup_dir* preserving its path relative to *target_root*."""
    try:
        rel = src.resolve().relative_to(target_root.resolve())
    except ValueError:
        rel = Path(src.name)
    dest = backup_dir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return dest


def apply_session(
    session: "ReviewSession",
    target_root: Path,
    backup_dir: Path,
    dry_run: bool = False,
    console: Optional["Console"] = None,
) -> ApplyResult:
    """Apply all *approved* items in *session* to files under *target_root*.

    Files are backed up to *backup_dir* before modification.  When *dry_run*
    is True no files are written but the result still reports what would change.
    """
    from collections import defaultdict

    result = ApplyResult()
    approved = session.approved()
    if not approved:
        return result

    if not dry_run:
        backup_dir.mkdir(parents=True, exist_ok=True)

    # Group approved items by file; process each file once
    by_file: dict[str, list["ReviewItem"]] = defaultdict(list)
    for item in approved:
        by_file[item.file].append(item)

    for rel_path, items in by_file.items():
        file_path = target_root / rel_path

        if not file_path.exists():
            for item in items:
                result.item_results.append(ItemResult(
                    finding_id=item.finding_id,
                    file=rel_path,
                    line=item.line,
                    replacement=item.replacement,
                    applied=False,
                    reason="File not found",
                ))
            continue

        # Backup before any modification
        if not dry_run:
            backed_up = _backup_file(file_path, backup_dir, target_root)
            result.backed_up.append(str(backed_up))

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        except OSError as exc:
            for item in items:
                result.item_results.append(ItemResult(
                    finding_id=item.finding_id,
                    file=rel_path,
                    line=item.line,
                    replacement=item.replacement,
                    applied=False,
                    reason=str(exc),
                ))
            continue

        # Process lines bottom-up to avoid offset shifts from multi-line edits
        items_sorted = sorted(items, key=lambda i: i.line, reverse=True)
        file_changed = False

        for item in items_sorted:
            idx = item.line - 1  # convert 1-based to 0-based
            if idx < 0 or idx >= len(lines):
                result.item_results.append(ItemResult(
                    finding_id=item.finding_id,
                    file=rel_path,
                    line=item.line,
                    replacement=item.replacement,
                    applied=False,
                    reason=f"Line {item.line} out of range (file has {len(lines)} lines)",
                ))
                continue

            if item.raw_match and item.raw_match in lines[idx]:
                if not dry_run:
                    lines[idx] = lines[idx].replace(item.raw_match, item.replacement, 1)
                    file_changed = True
                applied = True
                prefix = "[dry-run] " if dry_run else ""
                if console:
                    style = "dim" if dry_run else "green"
                    console.print(
                        f"  [{style}]{prefix}{rel_path}:{item.line} "
                        f"→ {item.replacement}[/{style}]"
                    )
            else:
                applied = False
                reason = (
                    f"'{item.raw_match}' not found on line {item.line}"
                    if item.raw_match
                    else "raw_match is empty"
                )
                if console:
                    console.print(
                        f"  [yellow]skip[/yellow] {rel_path}:{item.line} — {reason}"
                    )

            result.item_results.append(ItemResult(
                finding_id=item.finding_id,
                file=rel_path,
                line=item.line,
                replacement=item.replacement,
                applied=applied,
                reason="" if applied else reason,
            ))

        if file_changed:
            file_path.write_text("".join(lines), encoding="utf-8")

    if not dry_run:
        session.applied_at = datetime.now(timezone.utc)

    return result


def rollback(
    backup_dir: Path,
    target_root: Path,
    console: Optional["Console"] = None,
) -> int:
    """Restore all files from *backup_dir* back to *target_root*.

    Returns the number of files restored.
    """
    count = 0
    for backed_up in backup_dir.rglob("*"):
        if not backed_up.is_file():
            continue
        try:
            rel = backed_up.relative_to(backup_dir)
        except ValueError:
            continue
        dest = target_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backed_up, dest)
        count += 1
        if console:
            console.print(f"  [green]restored[/green] {rel}")
    return count
