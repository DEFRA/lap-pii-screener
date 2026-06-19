"""Interactive Rich TUI for reviewing and approving PII obfuscation decisions."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from obfuscation.session import ReviewItem, ReviewSession
from reporting.constants import SEVERITY_COLOURS

_CONTEXT_LINES = 2
_SEV_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _read_context(
    file_path: Path,
    target_line: int,
) -> list[tuple[int, str, bool]]:
    """Return ±_CONTEXT_LINES lines around *target_line* as (lineno, text, is_target)."""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    start = max(0, target_line - 1 - _CONTEXT_LINES)
    end   = min(len(lines), target_line + _CONTEXT_LINES)
    return [(i + 1, lines[i], i + 1 == target_line) for i in range(start, end)]


def _clean_skip_reason(value: str) -> str:
    """Return an empty string when *value* looks like an accidental key-press."""
    return "" if value.lower() in {"a", "s", "q", "e"} else value


def _apply_category_action(
    session: ReviewSession,
    category: str,
    decision: str,
    skip_reason: str = "",
) -> int:
    """Set *decision* on all pending, obfuscatable items in *category*.

    Returns the number of items affected.
    """
    count = 0
    for other in session.items:
        if other.category == category and other.decision == "pending" and other.obfuscatable:
            other.decision = decision  # type: ignore[assignment]
            if decision == "skipped":
                other.skip_reason = skip_reason
            count += 1
    return count


def _build_info_grid(item: "ReviewItem", show_secrets: bool) -> "Table":
    """Build the Rich info grid for a single review item."""
    sev_colour = SEVERITY_COLOURS.get(item.severity.lower(), "white")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", min_width=14)
    grid.add_column()
    grid.add_row(
        "Finding",
        f"[{sev_colour}]{item.severity.upper()}[/{sev_colour}]  "
        f"[bold]{item.category}[/bold]",
    )
    grid.add_row("File", f"{item.file}:{item.line}")
    grid.add_row("Scanners", ", ".join(item.scanners))
    conf_pct = int(item.confidence * 100)
    if item.confidence >= 0.85:
        conf_str = f"[bold green]{conf_pct}%  High[/bold green]"
    elif item.confidence >= 0.65:
        conf_str = f"[bold yellow]{conf_pct}%  Medium[/bold yellow]"
    else:
        conf_str = f"[bold red]{conf_pct}%  Low — review carefully[/bold red]"
    grid.add_row("Confidence", conf_str)
    match_val = item.raw_match if (show_secrets and item.raw_match) else item.match_display
    grid.add_row("Match", f"[bold red]{match_val}[/bold red]")
    grid.add_row("Replace with", f"[green]{item.replacement}[/green]")
    if not item.obfuscatable:
        grid.add_row("Note", f"[yellow]{item.non_obfuscatable_reason}[/yellow]")
    return grid


def _render_source_context(
    item: "ReviewItem", target_path: Path, console: "Console"
) -> None:
    """Print a source-context window around the finding's line."""
    context = _read_context(target_path / item.file, item.line)
    if not context:
        return
    ctx_text = Text()
    for lineno, line_text, is_target in context:
        prefix = Text(f"  {lineno:>4} │ ", style="dim")
        if is_target and item.raw_match and item.raw_match in line_text:
            raw = item.raw_match
            i = line_text.find(raw)
            content = Text()
            content.append(line_text[:i])
            content.append(raw, style="bold red on default")
            content.append(line_text[i + len(raw):])
            ctx_text.append_text(prefix)
            ctx_text.append_text(content)
        else:
            ctx_text.append_text(prefix)
            ctx_text.append(line_text, style="bold white" if is_target else "dim")
        ctx_text.append("\n")
    console.print(ctx_text)


def _prompt_decision(
    item: "ReviewItem",
    session: "ReviewSession",
    session_path: Optional[Path],
    console: "Console",
) -> Optional["ReviewSession"]:
    """
    Prompt the user for a decision on *item*.
    Returns None to continue, or the session if the user quits.
    """
    while True:
        choice = Prompt.ask(
            r"  [bold]Decision[/bold] (\[a]pprove / \[e]dit+approve / \[s]kip / \[A]ll-approve / \[S]kip-all / \[q]uit)",
            console=console,
            default="s",
        ).strip()

        if choice == "a":
            item.decision = "approved"
            return None
        if choice == "e":
            current = item.replacement
            new_val = Prompt.ask(
                f"  [bold]Custom replacement[/bold] (current: [green]{current}[/green])",
                console=console,
                default=current,
            ).strip()
            if new_val:
                item.replacement = new_val
            item.decision = "approved"
            return None
        if choice == "s":
            skip_reason = Prompt.ask(
                r"  [bold]Skip reason[/bold] (optional \[press Enter to leave blank])",
                console=console,
                default="",
            ).strip()
            item.decision = "skipped"
            item.skip_reason = _clean_skip_reason(skip_reason)
            return None
        if choice == "A":
            count = _apply_category_action(session, item.category, "approved")
            item.decision = "approved"
            console.print(f"  [dim]Approved all {count} pending '{item.category}' finding(s).[/dim]")
            return None
        if choice == "S":
            skip_reason = Prompt.ask(
                f"  [bold]Skip reason for all '{item.category}'[/bold] "
                r"(optional \[press Enter to leave blank])",
                console=console,
                default="",
            ).strip()
            skip_reason = _clean_skip_reason(skip_reason)
            count = _apply_category_action(session, item.category, "skipped", skip_reason)
            item.decision = "skipped"
            item.skip_reason = skip_reason
            console.print(f"  [dim]Skipped all {count} pending '{item.category}' finding(s).[/dim]")
            return None
        if choice == "q":
            if session_path:
                session.save(session_path)
            console.print("\n[dim]Review paused — re-run with --apply-session to resume.[/dim]")
            return session
        console.print("  [red]Invalid choice — enter a, e, s, A, S, or q.[/red]")


def run_review(
    session: ReviewSession,
    target_path: Path,
    session_path: Optional[Path] = None,
    auto_approve_severity: Optional[str] = None,
    show_secrets: bool = False,
    console: Optional[Console] = None,
) -> ReviewSession:
    """Run the interactive TUI review loop.

    The user is shown each pending finding in turn and prompted to:
      [a] approve   — mark for obfuscation
      [s] skip      — leave as-is
      [A] approve all in this category
      [q] quit      — save progress and exit

    Returns the updated *session*.
    """
    console = console or Console()

    # ── Auto-approve by severity ──────────────────────────────────────────────
    if auto_approve_severity:
        threshold = _SEV_RANK.get(auto_approve_severity.lower(), -1)
        auto_count = 0
        for item in session.items:
            if (
                item.decision == "pending"
                and item.obfuscatable
                and _SEV_RANK.get(item.severity.lower(), 0) >= threshold
            ):
                item.decision = "approved"
                auto_count += 1
        if auto_count:
            console.print(
                f"[dim]Auto-approved {auto_count} finding(s) at or above "
                f"'{auto_approve_severity}'.[/dim]"
            )
        if session_path:
            session.save(session_path)

    pending = [i for i in session.items if i.decision == "pending"]
    if not pending:
        console.print("[dim]No pending items to review.[/dim]")
        return session

    console.print(
        f"\n[bold]Reviewing {len(pending)} finding(s)[/bold]  "
        "[dim]a[/dim]=approve  [dim]e[/dim]=edit+approve  [dim]s[/dim]=skip  "
        "[dim]A[/dim]=approve-all  [dim]S[/dim]=skip-all  [dim]q[/dim]=quit\n"
    )

    for idx, item in enumerate(pending, 1):
        if item.decision != "pending":
            continue

        grid = _build_info_grid(item, show_secrets)
        console.print(Panel(grid, title=f"[dim]{idx}/{len(pending)}[/dim]", border_style="dim"))
        _render_source_context(item, target_path, console)

        if not item.obfuscatable:
            console.print("[dim]  ↳ marked manual — skipping prompt[/dim]\n")
            continue

        quit_session = _prompt_decision(item, session, session_path, console)
        if quit_session is not None:
            return quit_session

        if session_path:
            session.save(session_path)
        console.print()

    return session
