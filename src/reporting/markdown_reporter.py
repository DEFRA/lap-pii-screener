from __future__ import annotations

from jinja2 import Environment, FileSystemLoader

from models.report import Report
from reporting.constants import TEMPLATE_DIR

_MD_ENV = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=False)


def render_markdown(report: Report) -> str:
    """Render the report as a Markdown document using the Jinja2 template."""
    template = _MD_ENV.get_template("report.md.j2")
    return template.render(report=report)
