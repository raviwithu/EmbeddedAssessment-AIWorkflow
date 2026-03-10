"""Tests for the Linux runner orchestrator (collector/linux/runner.py)."""

from __future__ import annotations

from unittest.mock import patch

from collector.common.transport import TransportError
from collector.config import ConnectionConfig, ModulesConfig, ModuleToggle, TargetConfig
from collector.linux.runner import (
    collect_hwcomms_domain,
    collect_security_domain,
    collect_system_domain,
    run_linux_assessment,
)
from collector.models import HardeningCheck, HardwareInterface
from tests.conftest import MockTransport
from tests.linux.conftest import (
    GNU_PS_OUTPUT,
    IPTABLES_WITH_RULES,
    LSUSB_OUTPUT,
    SERIAL_DEVICES,
    SSHD_PASSWORD_AUTH_NO,
    SSHD_ROOT_LOGIN_NO,
    SS_OUTPUT,
    SUID_FILES_FEW,
    SYSTEMCTL_LIST_UNIT_FILES,
    SYSTEMCTL_LIST_UNITS,
)


def _setup_full_transport(t: MockTransport) -> None:
    """Set up responses for all Linux collectors."""
    # system_info
    t.register("hostname", stdout="router-01\n")
    t.register("uname -r", stdout="5.15.0\n")
    t.register_substring("os-release", stdout='NAME="Ubuntu"\n')
    t.register("uname -m", stdout="aarch64\n")
    t.register_substring("uptime", stdout="up 2 days\n")
    # processes
    t.register("ps aux --no-headers 2>/dev/null", stdout=GNU_PS_OUTPUT)
    # services
    t.register(
        "systemctl list-units --type=service --all --no-pager --no-legend",
        stdout=SYSTEMCTL_LIST_UNITS,
    )
    t.register(
        "systemctl list-unit-files --type=service --no-pager --no-legend",
        stdout=SYSTEMCTL_LIST_UNIT_FILES,
    )
    # ports
    t.register("ss -tulnp", stdout=SS_OUTPUT)
    # hardening
    t.register_substring("PermitRootLogin", stdout=SSHD_ROOT_LOGIN_NO)
    t.register_substring("PasswordAuthentication", stdout=SSHD_PASSWORD_AUTH_NO)
    t.register_substring("iptables", stdout=IPTABLES_WITH_RULES)
    t.register_substring("getenforce", stdout="Enforcing\n")
    t.register_substring("randomize_va_space", stdout="2\n")
    t.register_substring("suid_dumpable", stdout="0\n")
    t.register_substring("find /usr /bin /sbin /opt", stdout=SUID_FILES_FEW)
    # hardware
    t.register_substring("ls /dev/ttyS*", stdout=SERIAL_DEVICES)
    t.register_substring("ls /dev/spidev*", stdout="")
    t.register_substring("ls /dev/i2c-*", stdout="")
    t.register_substring("ls /sys/class/gpio/gpiochip*", stdout="")
    t.register("lsusb 2>/dev/null", stdout=LSUSB_OUTPUT)
    t.register_substring("test -r", stdout="")


# ---------------------------------------------------------------------------
# collect_system_domain
# ---------------------------------------------------------------------------

class TestCollectSystemDomain:
    def test_collects_all(self, mock_transport: MockTransport):
        _setup_full_transport(mock_transport)
        resp = collect_system_domain(mock_transport, "10.0.0.1")
        assert resp.target_host == "10.0.0.1"
        assert resp.system_info.hostname == "router-01"
        assert len(resp.processes) > 0
        assert len(resp.services) > 0
        assert len(resp.open_ports) > 0
        assert resp.errors == []

    def test_skip_processes(self, mock_transport: MockTransport):
        _setup_full_transport(mock_transport)
        resp = collect_system_domain(mock_transport, "10.0.0.1", processes=False)
        assert resp.processes == []

    def test_skip_services(self, mock_transport: MockTransport):
        _setup_full_transport(mock_transport)
        resp = collect_system_domain(mock_transport, "10.0.0.1", services=False)
        assert resp.services == []

    def test_skip_ports(self, mock_transport: MockTransport):
        _setup_full_transport(mock_transport)
        resp = collect_system_domain(mock_transport, "10.0.0.1", ports=False)
        assert resp.open_ports == []

    def test_transport_error_captured(self, mock_transport: MockTransport):
        """TransportError in a sub-collector is recorded in errors, not raised."""
        with patch(
            "collector.linux.runner.collect_system_info",
            side_effect=TransportError("connection lost"),
        ):
            resp = collect_system_domain(mock_transport, "10.0.0.1")
        assert any("system_info" in e for e in resp.errors)


# ---------------------------------------------------------------------------
# collect_security_domain
# ---------------------------------------------------------------------------

class TestCollectSecurityDomain:
    def test_returns_all_checks(self, mock_transport: MockTransport):
        _setup_full_transport(mock_transport)
        resp = collect_security_domain(mock_transport, "10.0.0.1")
        assert len(resp.hardening) == 7
        assert "pass" in resp.summary

    def test_filter_by_check_ids(self, mock_transport: MockTransport):
        _setup_full_transport(mock_transport)
        resp = collect_security_domain(
            mock_transport, "10.0.0.1", check_ids=["H-001", "H-005"],
        )
        assert len(resp.hardening) == 2
        ids = {c.check_id for c in resp.hardening}
        assert ids == {"H-001", "H-005"}

    def test_transport_error_captured(self, mock_transport: MockTransport):
        with patch(
            "collector.linux.runner.run_hardening_checks",
            side_effect=TransportError("fail"),
        ):
            resp = collect_security_domain(mock_transport, "10.0.0.1")
        assert any("hardening" in e for e in resp.errors)
        assert resp.hardening == []


# ---------------------------------------------------------------------------
# collect_hwcomms_domain
# ---------------------------------------------------------------------------

class TestCollectHwcommsDomain:
    def test_returns_interfaces(self, mock_transport: MockTransport):
        _setup_full_transport(mock_transport)
        resp = collect_hwcomms_domain(mock_transport, "10.0.0.1")
        assert len(resp.hardware_interfaces) > 0

    def test_filter_by_type(self, mock_transport: MockTransport):
        _setup_full_transport(mock_transport)
        resp = collect_hwcomms_domain(
            mock_transport, "10.0.0.1", interface_types=["usb"],
        )
        assert all(i.type == "usb" for i in resp.hardware_interfaces)

    def test_transport_error_captured(self, mock_transport: MockTransport):
        with patch(
            "collector.linux.runner.collect_hardware_interfaces",
            side_effect=TransportError("fail"),
        ):
            resp = collect_hwcomms_domain(mock_transport, "10.0.0.1")
        assert any("hardware" in e for e in resp.errors)


# ---------------------------------------------------------------------------
# run_linux_assessment (full assessment)
# ---------------------------------------------------------------------------

class TestRunLinuxAssessment:
    def test_full_assessment(self):
        t = MockTransport()
        _setup_full_transport(t)
        target = TargetConfig(
            name="test-router",
            connection=ConnectionConfig(host="10.0.0.1"),
        )
        modules = ModulesConfig()

        with patch("collector.linux.runner.create_transport", return_value=t):
            result = run_linux_assessment(target, modules)

        assert result.target_name == "test-router"
        assert result.system_info.hostname == "router-01"
        assert len(result.processes) > 0
        assert len(result.hardening) == 7

    def test_disabled_modules_skipped(self):
        t = MockTransport()
        _setup_full_transport(t)
        target = TargetConfig(
            name="test-router",
            connection=ConnectionConfig(host="10.0.0.1"),
        )
        modules = ModulesConfig(
            process_inventory=ModuleToggle(enabled=False),
            hardening_checks=ModuleToggle(enabled=False),
        )

        with patch("collector.linux.runner.create_transport", return_value=t):
            result = run_linux_assessment(target, modules)

        assert result.processes == []
        assert result.hardening == []
        assert len(result.services) > 0
