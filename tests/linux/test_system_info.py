"""Tests for collect_system_info (collector/linux/system_info.py)."""

from __future__ import annotations

from collector.linux.system_info import collect_system_info
from tests.conftest import MockTransport


class TestCollectSystemInfo:
    def test_all_fields_populated(self, mock_transport: MockTransport):
        mock_transport.register("hostname", stdout="router-01\n")
        mock_transport.register("uname -r", stdout="5.15.0-generic\n")
        mock_transport.register_substring("os-release", stdout='NAME="Ubuntu"\n')
        mock_transport.register("uname -m", stdout="aarch64\n")
        mock_transport.register_substring("uptime", stdout="up 2 days\n")

        info = collect_system_info(mock_transport)
        assert info.hostname == "router-01"
        assert info.kernel == "5.15.0-generic"
        assert "Ubuntu" in info.os_release
        assert info.architecture == "aarch64"
        assert "2 days" in info.uptime

    def test_command_failure_returns_empty(self, mock_transport: MockTransport):
        mock_transport.register("hostname", exit_code=1)
        mock_transport.register("uname -r", exit_code=1)
        mock_transport.register_substring("os-release", exit_code=1)
        mock_transport.register("uname -m", exit_code=1)
        mock_transport.register_substring("uptime", exit_code=1)

        info = collect_system_info(mock_transport)
        assert info.hostname == ""
        assert info.kernel == ""

    def test_partial_failure(self, mock_transport: MockTransport):
        mock_transport.register("hostname", stdout="myhost\n")
        mock_transport.register("uname -r", exit_code=1)
        mock_transport.register_substring("os-release", exit_code=1)
        mock_transport.register("uname -m", stdout="x86_64\n")
        mock_transport.register_substring("uptime", exit_code=1)

        info = collect_system_info(mock_transport)
        assert info.hostname == "myhost"
        assert info.kernel == ""
        assert info.architecture == "x86_64"

    def test_commands_are_recorded(self, mock_transport: MockTransport):
        collect_system_info(mock_transport)
        assert "hostname" in mock_transport.commands_run
        assert "uname -r" in mock_transport.commands_run
        assert "uname -m" in mock_transport.commands_run
