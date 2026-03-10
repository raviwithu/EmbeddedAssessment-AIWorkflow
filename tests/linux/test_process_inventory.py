"""Tests for process inventory (collector/linux/process_inventory.py)."""

from __future__ import annotations

from collector.linux.process_inventory import (
    _parse_fallback_ps,
    _parse_gnu_ps,
    collect_processes,
)
from tests.conftest import MockTransport
from tests.linux.conftest import BUSYBOX_PS_OUTPUT, GNU_PS_OUTPUT


# ---------------------------------------------------------------------------
# GNU ps parsing
# ---------------------------------------------------------------------------

class TestParseGnuPs:
    def test_parses_all_lines(self):
        procs = _parse_gnu_ps(GNU_PS_OUTPUT)
        assert len(procs) == 5

    def test_extracts_fields(self):
        procs = _parse_gnu_ps(GNU_PS_OUTPUT)
        init = procs[0]
        assert init.user == "root"
        assert init.pid == 1
        assert init.cpu_percent == 0.0
        assert init.mem_percent == 0.1
        assert init.command == "/sbin/init"

    def test_nonroot_user(self):
        procs = _parse_gnu_ps(GNU_PS_OUTPUT)
        nginx = procs[3]
        assert nginx.user == "www-data"
        assert nginx.pid == 456

    def test_empty_output(self):
        assert _parse_gnu_ps("") == []

    def test_short_lines_skipped(self):
        assert _parse_gnu_ps("short line") == []


# ---------------------------------------------------------------------------
# BusyBox / fallback ps parsing
# ---------------------------------------------------------------------------

class TestParseFallbackPs:
    def test_parses_with_header_skip(self):
        procs = _parse_fallback_ps(BUSYBOX_PS_OUTPUT)
        assert len(procs) == 4

    def test_extracts_fields(self):
        procs = _parse_fallback_ps(BUSYBOX_PS_OUTPUT)
        init = procs[0]
        assert init.pid == 1
        assert init.user == "root"
        assert init.command == "/sbin/init"

    def test_empty_output(self):
        assert _parse_fallback_ps("") == []


# ---------------------------------------------------------------------------
# collect_processes — integration with MockTransport
# ---------------------------------------------------------------------------

class TestCollectProcesses:
    def test_gnu_ps_path(self, mock_transport: MockTransport):
        mock_transport.register("ps aux --no-headers 2>/dev/null", stdout=GNU_PS_OUTPUT)
        procs = collect_processes(mock_transport)
        assert len(procs) == 5
        assert procs[0].user == "root"

    def test_fallback_to_busybox(self, mock_transport: MockTransport):
        mock_transport.register("ps aux --no-headers 2>/dev/null", exit_code=1)
        mock_transport.register(
            "ps -o pid,user,stat,args 2>/dev/null || ps -ef 2>/dev/null",
            stdout=BUSYBOX_PS_OUTPUT,
        )
        procs = collect_processes(mock_transport)
        assert len(procs) == 4

    def test_both_fail_returns_empty(self, mock_transport: MockTransport):
        mock_transport.register("ps aux --no-headers 2>/dev/null", exit_code=1)
        mock_transport.register(
            "ps -o pid,user,stat,args 2>/dev/null || ps -ef 2>/dev/null",
            exit_code=1,
        )
        procs = collect_processes(mock_transport)
        assert procs == []
