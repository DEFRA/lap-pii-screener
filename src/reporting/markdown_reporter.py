from __future__ import annotations

from jinja2 import Environment, FileSystemLoader, select_autoescape

from models.report import Report
from reporting.constants import TEMPLATE_DIR

# Markdown is plain text — auto-escaping HTML entities would corrupt the output.
# select_autoescape restricts escaping to HTML/XML templates only, which is
# safer than a blanket autoescape=False.
_MD_ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(enabled_extensions=("html", "xml")),
)


def render_markdown(report: Report) -> str:
    """Render the report as a Markdown document using the Jinja2 template."""
    template = _MD_ENV.get_template("report.md.j2")
    return template.render(report=report)
