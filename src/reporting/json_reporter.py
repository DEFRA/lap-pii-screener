from __future__ import annotations

from models.report import Report


def render_json(report: Report) -> str:
    """Serialize the full Report to indented JSON."""
    return report.model_dump_json(indent=2)
