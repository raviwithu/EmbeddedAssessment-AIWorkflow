"""Tests for FastAPI endpoints and timeout middleware (collector/api.py)."""

from __future__ import annotations

from unittest.mock import patch

import pytest
import httpx

from collector.api import app
from collector.common.transport import ConnectionFailed
from tests.conftest import MockTransport, make_assessment_result
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_transport() -> MockTransport:
    """Create a MockTransport with full Linux collector responses."""
    t = MockTransport()
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
    return t


def _patch_transport():
    """Patch create_transport to return a MockTransport."""
    mock_t = _make_mock_transport()

    def fake_create_transport(cfg):
        return mock_t

    return patch("collector.api.create_transport", side_effect=fake_create_transport)


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

class TestHealth:
    async def test_health_ok(self, client: httpx.AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# POST /collect/linux/system
# ---------------------------------------------------------------------------

class TestCollectLinuxSystem:
    async def test_success(self, client: httpx.AsyncClient):
        with _patch_transport():
            resp = await client.post("/collect/linux/system", json={
                "target": {"host": "10.0.0.1"},
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["target_host"] == "10.0.0.1"
        assert data["system_info"]["hostname"] == "router-01"
        assert len(data["processes"]) > 0

    async def test_skip_processes(self, client: httpx.AsyncClient):
        with _patch_transport():
            resp = await client.post("/collect/linux/system", json={
                "target": {"host": "10.0.0.1"},
                "collect_processes": False,
            })
        assert resp.status_code == 200
        assert resp.json()["processes"] == []

    async def test_missing_host_returns_422(self, client: httpx.AsyncClient):
        resp = await client.post("/collect/linux/system", json={
            "target": {},
        })
        assert resp.status_code == 422

    async def test_connection_failure_returns_502(self, client: httpx.AsyncClient):
        with patch(
            "collector.api.create_transport",
            side_effect=lambda cfg: _raise_on_connect(),
        ):
            resp = await client.post("/collect/linux/system", json={
                "target": {"host": "10.0.0.1"},
            })
        assert resp.status_code == 502


# ---------------------------------------------------------------------------
# POST /collect/linux/security
# ---------------------------------------------------------------------------

class TestCollectLinuxSecurity:
    async def test_success(self, client: httpx.AsyncClient):
        with _patch_transport():
            resp = await client.post("/collect/linux/security", json={
                "target": {"host": "10.0.0.1"},
            })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["hardening"]) == 7
        assert "pass" in data["summary"]

    async def test_filter_checks(self, client: httpx.AsyncClient):
        with _patch_transport():
            resp = await client.post("/collect/linux/security", json={
                "target": {"host": "10.0.0.1"},
                "checks": ["H-001"],
            })
        assert resp.status_code == 200
        assert len(resp.json()["hardening"]) == 1

    async def test_missing_host_returns_422(self, client: httpx.AsyncClient):
        resp = await client.post("/collect/linux/security", json={
            "target": {},
        })
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /collect/linux/hwcomms
# ---------------------------------------------------------------------------

class TestCollectLinuxHwcomms:
    async def test_success(self, client: httpx.AsyncClient):
        with _patch_transport():
            resp = await client.post("/collect/linux/hwcomms", json={
                "target": {"host": "10.0.0.1"},
            })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["hardware_interfaces"]) > 0

    async def test_filter_types(self, client: httpx.AsyncClient):
        with _patch_transport():
            resp = await client.post("/collect/linux/hwcomms", json={
                "target": {"host": "10.0.0.1"},
                "interface_types": ["usb"],
            })
        assert resp.status_code == 200
        data = resp.json()
        assert all(i["type"] == "usb" for i in data["hardware_interfaces"])

    async def test_missing_host_returns_422(self, client: httpx.AsyncClient):
        resp = await client.post("/collect/linux/hwcomms", json={
            "target": {},
        })
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /report/render
# ---------------------------------------------------------------------------

class TestReportRender:
    async def test_render_html(self, client: httpx.AsyncClient):
        result = make_assessment_result()
        resp = await client.post("/report/render", json={
            "result": result.model_dump(mode="json"),
            "formats": ["html"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["target_name"] == "test-target"
        assert len(data["reports"]) == 1
        assert data["reports"][0]["format"] == "html"

    async def test_render_markdown(self, client: httpx.AsyncClient):
        result = make_assessment_result()
        resp = await client.post("/report/render", json={
            "result": result.model_dump(mode="json"),
            "formats": ["markdown"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["reports"]) == 1
        assert data["reports"][0]["format"] == "markdown"

    async def test_render_both(self, client: httpx.AsyncClient):
        result = make_assessment_result()
        resp = await client.post("/report/render", json={
            "result": result.model_dump(mode="json"),
            "formats": ["html", "markdown"],
        })
        assert resp.status_code == 200
        assert len(resp.json()["reports"]) == 2

    async def test_render_default_formats(self, client: httpx.AsyncClient):
        result = make_assessment_result()
        resp = await client.post("/report/render", json={
            "result": result.model_dump(mode="json"),
        })
        assert resp.status_code == 200
        assert len(resp.json()["reports"]) == 2


# ---------------------------------------------------------------------------
# Helpers for error simulation
# ---------------------------------------------------------------------------

class _FailingTransport(MockTransport):
    def connect(self):
        raise ConnectionFailed("test connection failure")


def _raise_on_connect():
    return _FailingTransport()
