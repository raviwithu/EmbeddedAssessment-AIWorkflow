"""Tests for JSON serialization (parsers/normalize.py)."""

from __future__ import annotations

import json
from pathlib import Path

from collector.models import AssessmentResult
from parsers.normalize import load_json, save_json, to_json
from tests.conftest import make_assessment_result


class TestToJson:
    def test_returns_valid_json(self):
        result = make_assessment_result()
        j = to_json(result)
        parsed = json.loads(j)
        assert parsed["target_name"] == "test-target"

    def test_includes_all_fields(self):
        result = make_assessment_result()
        parsed = json.loads(to_json(result))
        assert "system_info" in parsed
        assert "processes" in parsed
        assert "services" in parsed
        assert "open_ports" in parsed
        assert "hardening" in parsed
        assert "hardware_interfaces" in parsed


class TestSaveAndLoadJson:
    def test_round_trip(self, tmp_path: Path):
        original = make_assessment_result()
        path = save_json(original, tmp_path)
        assert path.exists()
        assert path.suffix == ".json"

        loaded = load_json(path)
        assert loaded.target_name == original.target_name
        assert loaded.platform == original.platform
        assert len(loaded.processes) == len(original.processes)
        assert len(loaded.hardening) == len(original.hardening)

    def test_creates_output_dir(self, tmp_path: Path):
        out = tmp_path / "deep" / "dir"
        result = make_assessment_result()
        path = save_json(result, out)
        assert out.exists()
        assert path.exists()

    def test_filename_contains_target_name(self, tmp_path: Path):
        result = make_assessment_result(target_name="router-01")
        path = save_json(result, tmp_path)
        assert "router-01" in path.name

    def test_load_preserves_types(self, tmp_path: Path):
        original = make_assessment_result()
        path = save_json(original, tmp_path)
        loaded = load_json(path)
        assert isinstance(loaded, AssessmentResult)
        assert isinstance(loaded.system_info.hostname, str)
        assert isinstance(loaded.processes[0].pid, int)
