from __future__ import annotations

from pathlib import Path

# Shared Rich colour styles keyed by lower-case severity name.
SEVERITY_COLOURS: dict[str, str] = {
    "critical": "bold red",
    "high":     "bold dark_orange",
    "medium":   "bold yellow",
    "low":      "bold cyan",
    "info":     "dim",
}

# Absolute path to the Jinja2 template directory, resolved relative to this
# file so it works regardless of the current working directory.
TEMPLATE_DIR: Path = Path(__file__).parent.parent / "templates"
