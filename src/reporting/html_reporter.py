from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from jinja2 import Environment, FileSystemLoader

from models.report import Report
from reporting.constants import TEMPLATE_DIR

if TYPE_CHECKING:
    from obfuscation.session import ReviewSession
    from remediation.regulation_engine import RegulationEngine


@lru_cache(maxsize=1)
def _reg_engine() -> "RegulationEngine":
    """Lazy singleton — only loads regulations.yaml when render_html() is first called."""
    from remediation.regulation_engine import RegulationEngine
    return RegulationEngine()


_HTML_ENV = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)


def render_html(report: Report, session: Optional["ReviewSession"] = None, dry_run: bool = False, show_secrets: bool = False, show_confidence: bool = False) -> str:
    """Render the report as a self-contained HTML file using the Jinja2 template.

    Args:
        report: The scan report to render.
        session: Optional obfuscation review session.  When provided, an
            "Obfuscation" column is added to each findings table showing the
            decision (approved / skipped / manual / pending) for every finding.
        dry_run: When True, a prominent banner is added to the report indicating
            that no files were actually modified.
    """
    env = _HTML_ENV
    template = env.get_template("report.html.j2")
    regulations_meta = {
        r.id: {"name": r.name, "article": r.article, "statutory_ref": r.statutory_ref}
        for r in _reg_engine().all_regulations
    }

    # Build a map of finding_id -> ReviewItem for template access
    obfuscation_items: dict[str, dict] = {}
    if session is not None:
        for item in session.items:
            obfuscation_items[item.finding_id] = {
                "decision": item.decision,
                "replacement": item.replacement,
                "reason": item.non_obfuscatable_reason,
                "skip_reason": item.skip_reason,
                "raw_match": item.raw_match if show_secrets else None,
            }

    return template.render(
        report=report,
        regulations_meta=regulations_meta,
        obfuscation_items=obfuscation_items,
        dry_run=dry_run,
        show_secrets=show_secrets,
        show_confidence=show_confidence,
    )
