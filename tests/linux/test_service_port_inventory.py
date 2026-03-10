"""Tests for service and port inventory (collector/linux/service_port_inventory.py)."""

from __future__ import annotations

from collector.linux.service_port_inventory import (
    _parse_local_address,
    collect_open_ports,
    collect_services,
)
from tests.conftest import MockTransport
from tests.linux.conftest import (
    SS_OUTPUT,
    SS_OUTPUT_IPV6_TRIPLE_COLON,
    SYSTEMCTL_LIST_UNIT_FILES,
    SYSTEMCTL_LIST_UNITS,
)


# ---------------------------------------------------------------------------
# _parse_local_address
# ---------------------------------------------------------------------------

class TestParseLocalAddress:
    def test_ipv4(self):
        addr, port = _parse_local_address("0.0.0.0:22")
        assert addr == "0.0.0.0"
        assert port == "22"

    def test_ipv6_bracket(self):
        addr, port = _parse_local_address("[::]:22")
        assert addr == "::"
        assert port == "22"

    def test_ipv6_bracket_loopback(self):
        addr, port = _parse_local_address("[::1]:8080")
        assert addr == "::1"
        assert port == "8080"

    def test_triple_colon(self):
        addr, port = _parse_local_address(":::22")
        assert addr == "::"
        assert port == "22"

    def test_wildcard(self):
        addr, port = _parse_local_address("*:53")
        assert addr == "*"
        assert port == "53"

    def test_localhost(self):
        addr, port = _parse_local_address("127.0.0.1:3306")
        assert addr == "127.0.0.1"
        assert port == "3306"


# ---------------------------------------------------------------------------
# collect_services
# ---------------------------------------------------------------------------

class TestCollectServices:
    def test_parses_units_and_files(self, mock_transport: MockTransport):
        mock_transport.register(
            "systemctl list-units --type=service --all --no-pager --no-legend",
            stdout=SYSTEMCTL_LIST_UNITS,
        )
        mock_transport.register(
            "systemctl list-unit-files --type=service --no-pager --no-legend",
            stdout=SYSTEMCTL_LIST_UNIT_FILES,
        )
        services = collect_services(mock_transport)
        names = {s.name for s in services}
        assert "sshd" in names
        assert "nginx" in names
        assert "bluetooth" in names

    def test_enabled_flag_from_unit_files(self, mock_transport: MockTransport):
        mock_transport.register(
            "systemctl list-units --type=service --all --no-pager --no-legend",
            stdout=SYSTEMCTL_LIST_UNITS,
        )
        mock_transport.register(
            "systemctl list-unit-files --type=service --no-pager --no-legend",
            stdout=SYSTEMCTL_LIST_UNIT_FILES,
        )
        services = collect_services(mock_transport)
        by_name = {s.name: s for s in services}
        assert by_name["sshd"].enabled is True
        assert by_name["bluetooth"].enabled is False

    def test_unit_file_only_service(self, mock_transport: MockTransport):
        mock_transport.register(
            "systemctl list-units --type=service --all --no-pager --no-legend",
            stdout="",
        )
        mock_transport.register(
            "systemctl list-unit-files --type=service --no-pager --no-legend",
            stdout="avahi-daemon.service                   static\n",
        )
        services = collect_services(mock_transport)
        assert len(services) == 1
        assert services[0].name == "avahi-daemon"
        assert services[0].state == "inactive"

    def test_systemctl_failure_returns_empty(self, mock_transport: MockTransport):
        mock_transport.register(
            "systemctl list-units --type=service --all --no-pager --no-legend",
            exit_code=1,
        )
        assert collect_services(mock_transport) == []


# ---------------------------------------------------------------------------
# collect_open_ports
# ---------------------------------------------------------------------------

class TestCollectOpenPorts:
    def test_parses_ss_output(self, mock_transport: MockTransport):
        mock_transport.register("ss -tulnp", stdout=SS_OUTPUT)
        ports = collect_open_ports(mock_transport)
        assert len(ports) == 4

    def test_tcp_port(self, mock_transport: MockTransport):
        mock_transport.register("ss -tulnp", stdout=SS_OUTPUT)
        ports = collect_open_ports(mock_transport)
        tcp22 = [p for p in ports if p.port == 22 and p.address == "0.0.0.0"]
        assert len(tcp22) == 1
        assert tcp22[0].protocol == "tcp"
        assert tcp22[0].process == "sshd"

    def test_udp_port(self, mock_transport: MockTransport):
        mock_transport.register("ss -tulnp", stdout=SS_OUTPUT)
        ports = collect_open_ports(mock_transport)
        udp68 = [p for p in ports if p.port == 68]
        assert len(udp68) == 1
        assert udp68[0].protocol == "udp"
        assert udp68[0].process == "dhclient"

    def test_ipv6_port(self, mock_transport: MockTransport):
        mock_transport.register("ss -tulnp", stdout=SS_OUTPUT)
        ports = collect_open_ports(mock_transport)
        ipv6_22 = [p for p in ports if p.port == 22 and p.address == "::"]
        assert len(ipv6_22) == 1

    def test_triple_colon_ipv6(self, mock_transport: MockTransport):
        mock_transport.register("ss -tulnp", stdout=SS_OUTPUT_IPV6_TRIPLE_COLON)
        ports = collect_open_ports(mock_transport)
        assert len(ports) == 1
        assert ports[0].port == 8080
        assert ports[0].address == "::"

    def test_fallback_to_netstat(self, mock_transport: MockTransport):
        mock_transport.register("ss -tulnp", exit_code=1)
        mock_transport.register("netstat -tulnp", stdout=SS_OUTPUT)
        ports = collect_open_ports(mock_transport)
        assert len(ports) == 4

    def test_both_fail_returns_empty(self, mock_transport: MockTransport):
        mock_transport.register("ss -tulnp", exit_code=1)
        mock_transport.register("netstat -tulnp", exit_code=1)
        assert collect_open_ports(mock_transport) == []
