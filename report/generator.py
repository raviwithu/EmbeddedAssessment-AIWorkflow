"""Generate HTML and Markdown reports from assessment results."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from collector.models import AssessmentResult

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )


def render_html(result: AssessmentResult) -> str:
    """Render assessment result to an HTML string."""
    template = _env().get_template("report.html.j2")
    return template.render(r=result)


def render_markdown(result: AssessmentResult) -> str:
    """Render assessment result to a Markdown string."""
    template = _env().get_template("report.md.j2")
    return template.render(r=result)


def save_reports(result: AssessmentResult, output_dir: str | Path, formats: list[str]) -> list[Path]:
    """Write reports in the requested formats and return file paths."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    base = f"{result.target_name}_{result.timestamp:%Y%m%d_%H%M%S}"
    paths: list[Path] = []

    if "html" in formats:
        p = out / f"{base}.html"
        p.write_text(render_html(result))
        paths.append(p)

    if "markdown" in formats:
        p = out / f"{base}.md"
        p.write_text(render_markdown(result))
        paths.append(p)

    return paths
