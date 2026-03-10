"""Generate HTML and Markdown reports from assessment results."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from collector.models import AssessmentResult

_TEMPLATE_DIR = Path(__file__).parent / "templates"

# Cache Environment instances — one per autoescape mode.
_html_env: Environment | None = None
_md_env: Environment | None = None


def _get_html_env() -> Environment:
    global _html_env
    if _html_env is None:
        _html_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=True,
        )
    return _html_env


def _get_md_env() -> Environment:
    global _md_env
    if _md_env is None:
        _md_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=False,
        )
    return _md_env


def render_html(result: AssessmentResult) -> str:
    """Render assessment result to an HTML string."""
    template = _get_html_env().get_template("report.html.j2")
    return template.render(r=result)


def render_markdown(result: AssessmentResult) -> str:
    """Render assessment result to a Markdown string."""
    template = _get_md_env().get_template("report.md.j2")
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
