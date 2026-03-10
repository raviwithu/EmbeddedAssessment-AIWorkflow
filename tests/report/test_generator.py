"""Tests for report generation (report/generator.py)."""

from __future__ import annotations

from pathlib import Path

from report.generator import render_html, render_markdown, save_reports
from tests.conftest import make_assessment_result


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
