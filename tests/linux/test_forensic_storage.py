"""Tests for per-host forensic storage (collector/linux/forensic_storage.py)."""

from __future__ import annotations

import json
from pathlib import Path

from collector.common.sanitize import sanitize_hostname as _sanitize
from collector.linux.forensic_storage import save_snapshot, load_manifest
from collector.models import BaselineSnapshot, ForensicArtifact, Phase0Snapshot


class TestSaveSnapshot:
    def test_creates_directory_and_files(self, tmp_path: Path):
        snapshot = BaselineSnapshot(
            hostname="test-device",
            artifacts=[
                ForensicArtifact(filename="uname.txt", content="Linux 5.15.0", command="uname -a"),
                ForensicArtifact(filename="ps.txt", content="PID CMD\n1 init", command="ps aux"),
            ],
        )
        result_dir = save_snapshot(snapshot, tmp_path, "baseline")
        assert result_dir == tmp_path / "test-device" / "baseline"
        assert (result_dir / "uname.txt").read_text() == "Linux 5.15.0"
        assert (result_dir / "ps.txt").read_text() == "PID CMD\n1 init"

    def test_creates_manifest(self, tmp_path: Path):
        snapshot = BaselineSnapshot(
            hostname="host-01",
            artifacts=[ForensicArtifact(filename="a.txt", content="data", command="cmd")],
        )
        result_dir = save_snapshot(snapshot, tmp_path, "baseline")
        manifest = json.loads((result_dir / "manifest.json").read_text())
        assert manifest["hostname"] == "host-01"
        assert len(manifest["runs"]) == 1
        assert manifest["runs"][0]["artifact_count"] == 1

    def test_updates_existing_data(self, tmp_path: Path):
        snap1 = BaselineSnapshot(
            hostname="host-01",
            artifacts=[ForensicArtifact(filename="a.txt", content="old", command="cmd")],
        )
        snap2 = BaselineSnapshot(
            hostname="host-01",
            artifacts=[ForensicArtifact(filename="a.txt", content="new", command="cmd")],
        )
        save_snapshot(snap1, tmp_path, "baseline")
        result_dir = save_snapshot(snap2, tmp_path, "baseline")

        # File content should be updated
        assert (result_dir / "a.txt").read_text() == "new"
        # Manifest should have two runs
        manifest = json.loads((result_dir / "manifest.json").read_text())
        assert len(manifest["runs"]) == 2

    def test_different_phases_separate_dirs(self, tmp_path: Path):
        snap_base = BaselineSnapshot(
            hostname="host-01",
            artifacts=[ForensicArtifact(filename="a.txt", content="baseline", command="cmd")],
        )
        snap_phase0 = Phase0Snapshot(
            hostname="host-01",
            artifacts=[ForensicArtifact(filename="b.txt", content="phase0", command="cmd")],
        )
        dir1 = save_snapshot(snap_base, tmp_path, "baseline")
        dir2 = save_snapshot(snap_phase0, tmp_path, "phase0")

        assert dir1 != dir2
        assert (dir1 / "a.txt").read_text() == "baseline"
        assert (dir2 / "b.txt").read_text() == "phase0"


class TestLoadManifest:
    def test_returns_empty_when_missing(self, tmp_path: Path):
        assert load_manifest(tmp_path) == {}

    def test_returns_saved_manifest(self, tmp_path: Path):
        snapshot = BaselineSnapshot(
            hostname="host-01",
            artifacts=[ForensicArtifact(filename="a.txt", content="x", command="c")],
        )
        result_dir = save_snapshot(snapshot, tmp_path, "baseline")
        manifest = load_manifest(result_dir)
        assert manifest["hostname"] == "host-01"


class TestSanitize:
    def test_removes_path_separators(self):
        assert _sanitize("host/name") == "host_name"
        assert _sanitize("host\\name") == "host_name"

    def test_removes_double_dots(self):
        assert _sanitize("..host..") == "host"

    def test_strips_whitespace(self):
        assert _sanitize("  host  ") == "host"

    def test_removes_special_chars(self):
        assert _sanitize("host*name?:test") == "host_name__test"

    def test_empty_becomes_unknown(self):
        assert _sanitize("") == "unknown"
        assert _sanitize("...") == "unknown"
