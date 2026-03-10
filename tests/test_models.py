"""Tests for Pydantic model validation (collector/models.py)."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from pydantic import SecretStr, ValidationError

from collector.models import (
    AssessmentResult,
    HardeningCheck,
    HardwareInterface,
    HwCommsCollectRequest,
    OpenPort,
    ProcessInfo,
    ReportFormat,
    ReportRenderRequest,
    SecurityCollectRequest,
    ServiceInfo,
    SystemCollectRequest,
    SystemInfo,
    TargetConnectionRequest,
)


# ---------------------------------------------------------------------------
# Collection result models
# ---------------------------------------------------------------------------

class TestProcessInfo:
    def test_valid(self):
        p = ProcessInfo(pid=1, user="root", command="/sbin/init")
        assert p.pid == 1
        assert p.cpu_percent == 0.0

    def test_invalid_pid(self):
        with pytest.raises(ValidationError):
            ProcessInfo(pid="abc", user="root", command="/sbin/init")

    def test_missing_required(self):
        with pytest.raises(ValidationError):
            ProcessInfo(pid=1, user="root")


class TestServiceInfo:
    def test_valid(self):
        s = ServiceInfo(name="sshd", state="running")
        assert s.enabled is False

    def test_missing_state(self):
        with pytest.raises(ValidationError):
            ServiceInfo(name="sshd")


class TestOpenPort:
    def test_defaults(self):
        p = OpenPort(protocol="tcp", port=22)
        assert p.address == "0.0.0.0"
        assert p.process == ""

    def test_invalid_port(self):
        with pytest.raises(ValidationError):
            OpenPort(protocol="tcp", port="abc")


class TestHardeningCheck:
    def test_valid_statuses(self):
        for status in ("pass", "fail", "warn", "info"):
            c = HardeningCheck(
                check_id="H-001", category="SSH",
                description="test", status=status,
            )
            assert c.status == status

    def test_invalid_status(self):
        with pytest.raises(ValidationError):
            HardeningCheck(
                check_id="H-001", category="SSH",
                description="test", status="unknown",
            )


class TestHardwareInterface:
    def test_valid_types(self):
        for t in ("uart", "spi", "i2c", "gpio", "usb", "other"):
            hw = HardwareInterface(type=t, device_path="/dev/test")
            assert hw.type == t

    def test_invalid_type(self):
        with pytest.raises(ValidationError):
            HardwareInterface(type="jtag", device_path="/dev/test")


class TestSystemInfo:
    def test_all_defaults(self):
        si = SystemInfo()
        assert si.hostname == ""
        assert si.kernel == ""


class TestAssessmentResult:
    def test_minimal(self):
        r = AssessmentResult(target_name="t1", platform="linux")
        assert r.target_name == "t1"
        assert isinstance(r.timestamp, datetime)
        assert r.processes == []
        assert r.errors == []

    def test_timestamp_default_is_utc(self):
        r = AssessmentResult(target_name="t", platform="linux")
        assert r.timestamp.tzinfo is not None


# ---------------------------------------------------------------------------
# API request / response models
# ---------------------------------------------------------------------------

class TestTargetConnectionRequest:
    def test_explicit_values(self, clean_ssh_env):
        req = TargetConnectionRequest(
            host="10.0.0.1", port=2222, username="admin",
            auth="password", password=SecretStr("secret"),
        )
        assert req.host == "10.0.0.1"
        assert req.port == 2222
        assert req.username == "admin"

    def test_env_fallback(self, monkeypatch, clean_ssh_env):
        monkeypatch.setenv("SSH_HOST", "192.168.1.1")
        monkeypatch.setenv("SSH_PORT", "2222")
        monkeypatch.setenv("SSH_USERNAME", "pi")
        req = TargetConnectionRequest()
        assert req.host == "192.168.1.1"
        assert req.port == 2222
        assert req.username == "pi"

    def test_missing_host_raises(self, clean_ssh_env):
        with pytest.raises(ValidationError, match="target.host is required"):
            TargetConnectionRequest()

    def test_defaults_without_env(self, clean_ssh_env):
        req = TargetConnectionRequest(host="10.0.0.1")
        assert req.port == 22
        assert req.username == "root"
        assert req.auth == "key"
        assert req.timeout_seconds == 10
        assert req.command_timeout == 30

    def test_password_from_env(self, monkeypatch, clean_ssh_env):
        monkeypatch.setenv("SSH_HOST", "10.0.0.1")
        monkeypatch.setenv("SSH_PASSWORD", "envpass")
        req = TargetConnectionRequest()
        assert req.password.get_secret_value() == "envpass"


class TestSystemCollectRequest:
    def test_defaults(self, clean_ssh_env):
        req = SystemCollectRequest(target=TargetConnectionRequest(host="10.0.0.1"))
        assert req.collect_processes is True
        assert req.collect_services is True
        assert req.collect_ports is True


class TestSecurityCollectRequest:
    def test_default_checks_none(self, clean_ssh_env):
        req = SecurityCollectRequest(target=TargetConnectionRequest(host="10.0.0.1"))
        assert req.checks is None


class TestReportFormat:
    def test_values(self):
        assert ReportFormat.html.value == "html"
        assert ReportFormat.markdown.value == "markdown"
