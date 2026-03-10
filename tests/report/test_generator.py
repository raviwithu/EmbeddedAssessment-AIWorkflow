"""Tests for report generation (report/generator.py)."""

from __future__ import annotations

from pathlib import Path

from report.generator import _md_escape, render_html, render_markdown, save_reports
from tests.conftest import make_assessment_result, make_process_info


class TestRenderHtml:
    def test_returns_string(self):
        result = make_assessment_result()
        html = render_html(result)
        assert isinstance(html, str)
        assert len(html) > 0

    def test_contains_target_name(self):
        result = make_assessment_result(target_name="my-router")
        html = render_html(result)
        assert "my-router" in html

    def test_contains_html_tags(self):
        result = make_assessment_result()
        html = render_html(result)
        assert "<" in html  # basic HTML structure


class TestRenderMarkdown:
    def test_returns_string(self):
        result = make_assessment_result()
        md = render_markdown(result)
        assert isinstance(md, str)
        assert len(md) > 0

    def test_contains_target_name(self):
        result = make_assessment_result(target_name="my-router")
        md = render_markdown(result)
        assert "my-router" in md


class TestSaveReports:
    def test_save_html(self, tmp_path: Path):
        result = make_assessment_result()
        paths = save_reports(result, tmp_path, ["html"])
        assert len(paths) == 1
        assert paths[0].suffix == ".html"
        assert paths[0].exists()
        content = paths[0].read_text()
        assert "test-target" in content

    def test_save_markdown(self, tmp_path: Path):
        result = make_assessment_result()
        paths = save_reports(result, tmp_path, ["markdown"])
        assert len(paths) == 1
        assert paths[0].suffix == ".md"
        assert paths[0].exists()

    def test_save_both(self, tmp_path: Path):
        result = make_assessment_result()
        paths = save_reports(result, tmp_path, ["html", "markdown"])
        assert len(paths) == 2
        suffixes = {p.suffix for p in paths}
        assert suffixes == {".html", ".md"}

    def test_creates_output_dir(self, tmp_path: Path):
        out = tmp_path / "reports" / "nested"
        result = make_assessment_result()
        paths = save_reports(result, out, ["html"])
        assert out.exists()
        assert len(paths) == 1


# ---------------------------------------------------------------------------
# Markdown escaping (H5)
# ---------------------------------------------------------------------------

class TestMdEscape:
    def test_escapes_pipes(self):
        assert _md_escape("foo|bar") == "foo\\|bar"

    def test_escapes_newlines(self):
        assert _md_escape("line1\nline2") == "line1 line2"

    def test_escapes_link_injection(self):
        """Brackets and parens must be escaped to prevent markdown link injection."""
        malicious = "[evil](http://evil.com)"
        escaped = _md_escape(malicious)
        assert "[" not in escaped or "\\[" in escaped
        assert "]" not in escaped or "\\]" in escaped
        assert "(" not in escaped or "\\(" in escaped
        assert ")" not in escaped or "\\)" in escaped

    def test_combined(self):
        result = _md_escape("a|b\n[c](d)")
        assert "|" not in result or "\\|" in result
        assert "\n" not in result


class TestXssProtection:
    def test_html_escapes_script_tags(self):
        """HTML autoescape should prevent XSS via script tags."""
        result = make_assessment_result(target_name="<script>alert('xss')</script>")
        html = render_html(result)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_markdown_escapes_pipe_in_data(self):
        """Pipe chars in process commands should not break markdown tables."""
        proc = make_process_info(command="cat /etc/passwd | grep root")
        result = make_assessment_result(processes=[proc])
        md = render_markdown(result)
        # The pipe should be escaped so the table doesn't break
        assert "\\|" in md
