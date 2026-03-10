"""Tests for Phase 1 memory acquisition (collector/linux/phase1_memory.py)."""

from __future__ import annotations

from collector.linux.phase1_memory import collect_phase1, _parse_mem_total
from tests.conftest import MockTransport


def _setup_phase1_transport(t: MockTransport, *, lime_found: bool = False, kcore_available: bool = True) -> None:
    t.register("hostname", stdout="target-01\n")
    t.register_substring("/proc/meminfo", stdout="MemTotal: 4096000 kB\nMemFree: 2048000 kB\n")
    t.register_substring("mkdir -p", stdout="")
    t.register("uname -r", stdout="5.15.0-generic\n")
    t.register_substring("System.map", stdout="not found\n")

    if lime_found:
        t.register_substring("lime-$(uname -r)", stdout="/tmp/lime-5.15.0-generic.ko\n")
        t.register_substring("insmod", stdout="", exit_code=0)
        t.register_substring("sha256sum", stdout="abcdef1234567890 /tmp/forensic/memory.lime\n")
        t.register_substring("stat -c", stdout="4096000000\n")
    else:
        t.register_substring("lime-$(uname -r)", stdout="")
        t.register_substring("lime-*.ko", stdout="")

    if kcore_available:
        t.register_substring("test -r /proc/kcore", stdout="yes\n")
        t.register_substring("ls -l /proc/kcore", stdout="-r-------- 1 root root 140737477881856 Jan 15 /proc/kcore\n")
    else:
        t.register_substring("test -r /proc/kcore", stdout="no\n")


class TestCollectPhase1:
    def test_lime_acquisition(self, mock_transport: MockTransport):
        _setup_phase1_transport(mock_transport, lime_found=True)
        snapshot = collect_phase1(mock_transport)
        assert snapshot.hostname == "target-01"
        filenames = {a.filename for a in snapshot.artifacts}
        assert "meminfo.txt" in filenames
        assert "kernel_version.txt" in filenames
        assert "lime_load.txt" in filenames
        assert "memory_sha256.txt" in filenames

    def test_kcore_fallback(self, mock_transport: MockTransport):
        _setup_phase1_transport(mock_transport, lime_found=False, kcore_available=True)
        snapshot = collect_phase1(mock_transport)
        filenames = {a.filename for a in snapshot.artifacts}
        assert "kcore_available.txt" in filenames
        assert "lime_search.txt" in filenames

    def test_no_memory_source(self, mock_transport: MockTransport):
        _setup_phase1_transport(mock_transport, lime_found=False, kcore_available=False)
        snapshot = collect_phase1(mock_transport)
        assert any("Neither LiME nor /proc/kcore" in e for e in snapshot.errors)
        assert snapshot.memory_dump_path == ""

    def test_hostname_fallback(self, mock_transport: MockTransport):
        mock_transport.register("hostname", stdout="")
        snapshot = collect_phase1(mock_transport)
        assert snapshot.hostname == "unknown"

    def test_parse_mem_total(self):
        assert _parse_mem_total("MemTotal: 4096000 kB\nMemFree: 2048000 kB\n") == "4096000 kB"
        assert _parse_mem_total("nothing useful") == "unknown"
