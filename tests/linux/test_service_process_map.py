"""Tests for service-to-process mapping (collector/linux/service_process_map.py)."""

from __future__ import annotations

from collector.linux.service_process_map import (
    _get_service_pids,
    _match_ports,
    collect_service_process_map,
)
from collector.models import OpenPort, ProcessInfo
from tests.conftest import MockTransport
from tests.linux.conftest import (
    GNU_PS_OUTPUT,
    SS_OUTPUT,
    SYSTEMCTL_LIST_UNIT_FILES,
    SYSTEMCTL_LIST_UNITS,
    SYSTEMCTL_SHOW_EMPTY,
    SYSTEMCTL_SHOW_OUTPUT,
)


def _setup_service_map_transport(t: MockTransport) -> None:
    """Register all commands needed for a full service-process map collection."""
    t.register(
        "systemctl list-units --type=service --all --no-pager --no-legend",
        stdout=SYSTEMCTL_LIST_UNITS,
    )
    t.register(
        "systemctl list-unit-files --type=service --no-pager --no-legend",
        stdout=SYSTEMCTL_LIST_UNIT_FILES,
    )
    t.register_substring("systemctl show", stdout=SYSTEMCTL_SHOW_OUTPUT)
    t.register("ps aux --no-headers 2>/dev/null", stdout=GNU_PS_OUTPUT)
    t.register("ss -tulnp", stdout=SS_OUTPUT)


# ---------------------------------------------------------------------------
# _get_service_pids
# ---------------------------------------------------------------------------

class TestGetServicePids:
    def test_parses_batch_output(self, mock_transport: MockTransport):
        mock_transport.register_substring("systemctl show", stdout=SYSTEMCTL_SHOW_OUTPUT)
        pid_map = _get_service_pids(mock_transport, ["sshd", "nginx", "cron", "bluetooth"])
        assert pid_map["sshd"] == 123
        assert pid_map["nginx"] == 456
        assert pid_map["cron"] == 500
        assert pid_map["bluetooth"] == 0

    def test_empty_input(self, mock_transport: MockTransport):
        assert _get_service_pids(mock_transport, []) == {}

    def test_failure_returns_empty(self, mock_transport: MockTransport):
        mock_transport.register_substring("systemctl show", exit_code=1)
        assert _get_service_pids(mock_transport, ["sshd"]) == {}


# ---------------------------------------------------------------------------
# _match_ports
# ---------------------------------------------------------------------------

class TestMatchPorts:
    def test_matches_by_service_name(self):
        ports = [
            OpenPort(protocol="tcp", port=22, address="0.0.0.0", process="sshd"),
            OpenPort(protocol="tcp", port=80, address="0.0.0.0", process="nginx"),
        ]
        proc = ProcessInfo(pid=123, user="root", command="/usr/sbin/sshd")
        matched = _match_ports(ports, 123, proc, "sshd")
        assert len(matched) == 1
        assert matched[0].port == 22

    def test_no_match(self):
        ports = [
            OpenPort(protocol="tcp", port=80, address="0.0.0.0", process="nginx"),
        ]
        proc = ProcessInfo(pid=123, user="root", command="/usr/sbin/sshd")
        matched = _match_ports(ports, 123, proc, "sshd")
        assert matched == []

    def test_empty_ports(self):
        proc = ProcessInfo(pid=123, user="root", command="/usr/sbin/sshd")
        assert _match_ports([], 123, proc, "sshd") == []


# ---------------------------------------------------------------------------
# collect_service_process_map — full integration
# ---------------------------------------------------------------------------

class TestCollectServiceProcessMap:
    def test_maps_services_to_processes(self, mock_transport: MockTransport):
        _setup_service_map_transport(mock_transport)
        mappings = collect_service_process_map(mock_transport)
        assert len(mappings) == 5  # sshd, nginx, cron, bluetooth, avahi-daemon (from unit-files)

        by_name = {m.service_name: m for m in mappings}

        # sshd: PID 123 matches ps output, has port 22
        sshd = by_name["sshd"]
        assert sshd.main_pid == 123
        assert sshd.process is not None
        assert sshd.process.pid == 123
        assert sshd.enabled is True
        assert sshd.service_state == "active"
        assert any(p.port == 22 for p in sshd.listening_ports)

        # nginx: PID 456 matches ps output, has port 80
        nginx = by_name["nginx"]
        assert nginx.main_pid == 456
        assert nginx.process is not None
        assert any(p.port == 80 for p in nginx.listening_ports)

    def test_inactive_service_has_no_process(self, mock_transport: MockTransport):
        _setup_service_map_transport(mock_transport)
        mappings = collect_service_process_map(mock_transport)
        by_name = {m.service_name: m for m in mappings}

        bt = by_name["bluetooth"]
        assert bt.main_pid == 0
        assert bt.process is None
        assert bt.service_state == "inactive"
        assert bt.enabled is False

    def test_systemctl_failure_returns_empty(self, mock_transport: MockTransport):
        mock_transport.register(
            "systemctl list-units --type=service --all --no-pager --no-legend",
            exit_code=1,
        )
        assert collect_service_process_map(mock_transport) == []
