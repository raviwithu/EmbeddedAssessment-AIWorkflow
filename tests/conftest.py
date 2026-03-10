"""Shared test fixtures — MockTransport, sample data factories, FastAPI client."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import pytest

from collector.common.transport import CommandResult, Transport
from collector.models import (
    AssessmentResult,
    HardeningCheck,
    HardwareInterface,
    OpenPort,
    ProcessInfo,
    ServiceInfo,
    SystemInfo,
)


# ---------------------------------------------------------------------------
# MockTransport
# ---------------------------------------------------------------------------

class MockTransport(Transport):
    """In-memory transport for testing — no real SSH connections.

    Supports exact and substring command matching.  Records every command
    executed so tests can assert on the sequence of calls.
    """

    def __init__(self, responses: dict[str, CommandResult] | None = None) -> None:
        self._responses: dict[str, CommandResult] = responses or {}
        self._connected = False
        self.commands_run: list[str] = []

    # -- Registration helpers ------------------------------------------------

    def register(self, command: str, stdout: str = "", stderr: str = "",
                 exit_code: int = 0, timed_out: bool = False, error: str = "") -> None:
        """Register an exact-match response for *command*."""
        self._responses[command] = CommandResult(
            command=command, stdout=stdout, stderr=stderr,
            exit_code=exit_code, timed_out=timed_out, error=error,
        )

    def register_substring(self, substring: str, stdout: str = "", stderr: str = "",
                           exit_code: int = 0) -> None:
        """Register a response that matches any command containing *substring*."""
        self._responses[f"__sub__{substring}"] = CommandResult(
            command=substring, stdout=stdout, stderr=stderr, exit_code=exit_code,
        )

    # -- Transport ABC -------------------------------------------------------

    def connect(self) -> None:
        self._connected = True

    def run(self, command: str, timeout: int = 30) -> CommandResult:
        self.commands_run.append(command)

        # Exact match first
        if command in self._responses:
            r = self._responses[command]
            return CommandResult(
                command=command, stdout=r.stdout, stderr=r.stderr,
                exit_code=r.exit_code, timed_out=r.timed_out, error=r.error,
            )

        # Substring match
        for key, r in self._responses.items():
            if key.startswith("__sub__") and key[7:] in command:
                return CommandResult(
                    command=command, stdout=r.stdout, stderr=r.stderr,
                    exit_code=r.exit_code, timed_out=r.timed_out, error=r.error,
                )

        # Default: empty success
        return CommandResult(command=command, stdout="", stderr="", exit_code=0)

    def is_connected(self) -> bool:
        return self._connected

    def close(self) -> None:
        self._connected = False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_transport() -> MockTransport:
    """Return a fresh MockTransport instance."""
    t = MockTransport()
    t.connect()
    return t


@pytest.fixture
def clean_ssh_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove all SSH_* env vars so TargetConnectionRequest defaults are deterministic."""
    for key in list(os.environ):
        if key.startswith("SSH_"):
            monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------------------
# Sample data factories
# ---------------------------------------------------------------------------

def make_system_info(**overrides: Any) -> SystemInfo:
    defaults = dict(
        hostname="test-device",
        kernel="5.15.0",
        os_release='NAME="Ubuntu"\nVERSION="22.04"',
        architecture="aarch64",
        uptime="up 2 days, 3 hours",
    )
    defaults.update(overrides)
    return SystemInfo(**defaults)


def make_process_info(**overrides: Any) -> ProcessInfo:
    defaults = dict(pid=1, user="root", command="/sbin/init", cpu_percent=0.1, mem_percent=0.5)
    defaults.update(overrides)
    return ProcessInfo(**defaults)


def make_service_info(**overrides: Any) -> ServiceInfo:
    defaults = dict(name="sshd", state="running", enabled=True)
    defaults.update(overrides)
    return ServiceInfo(**defaults)


def make_open_port(**overrides: Any) -> OpenPort:
    defaults = dict(protocol="tcp", port=22, address="0.0.0.0", process="sshd")
    defaults.update(overrides)
    return OpenPort(**defaults)


def make_hardening_check(**overrides: Any) -> HardeningCheck:
    defaults = dict(
        check_id="H-001", category="SSH",
        description="Test check", status="pass", detail="ok",
    )
    defaults.update(overrides)
    return HardeningCheck(**defaults)


def make_hardware_interface(**overrides: Any) -> HardwareInterface:
    defaults = dict(type="uart", device_path="/dev/ttyS0", description="Serial", accessible=True)
    defaults.update(overrides)
    return HardwareInterface(**defaults)


def make_assessment_result(**overrides: Any) -> AssessmentResult:
    defaults: dict[str, Any] = dict(
        target_name="test-target",
        platform="linux",
        timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        system_info=make_system_info(),
        processes=[make_process_info()],
        services=[make_service_info()],
        open_ports=[make_open_port()],
        hardening=[make_hardening_check()],
        hardware_interfaces=[make_hardware_interface()],
        errors=[],
        metadata={},
    )
    defaults.update(overrides)
    return AssessmentResult(**defaults)
