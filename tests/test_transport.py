"""Tests for CommandResult, Transport ABC, and create_transport factory."""

from __future__ import annotations

import pytest

from collector.common.transport import (
    ADBTransport,
    CommandFailed,
    CommandResult,
    CommandTimedOut,
    ConnectionFailed,
    SSHTransport,
    Transport,
    TransportError,
    create_transport,
)
from collector.config import ConnectionConfig
from tests.conftest import MockTransport


# ---------------------------------------------------------------------------
# CommandResult
# ---------------------------------------------------------------------------

class TestCommandResult:
    def test_ok_when_success(self):
        r = CommandResult(command="ls", stdout="file.txt", stderr="", exit_code=0)
        assert r.ok is True

    def test_not_ok_nonzero_exit(self):
        r = CommandResult(command="ls", stdout="", stderr="err", exit_code=1)
        assert r.ok is False

    def test_not_ok_timed_out(self):
        r = CommandResult(command="ls", stdout="", stderr="", exit_code=0, timed_out=True)
        assert r.ok is False

    def test_not_ok_error_string(self):
        r = CommandResult(command="ls", stdout="", stderr="", exit_code=0, error="bad")
        assert r.ok is False

    def test_fields(self):
        r = CommandResult(command="id", stdout="root", stderr="", exit_code=0)
        assert r.command == "id"
        assert r.stdout == "root"


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    def test_connection_failed_is_transport_error(self):
        assert issubclass(ConnectionFailed, TransportError)

    def test_command_timed_out_is_transport_error(self):
        assert issubclass(CommandTimedOut, TransportError)

    def test_command_failed_is_transport_error(self):
        assert issubclass(CommandFailed, TransportError)


# ---------------------------------------------------------------------------
# create_transport factory
# ---------------------------------------------------------------------------

class TestCreateTransport:
    def test_ssh_method(self):
        cfg = ConnectionConfig(method="ssh", host="10.0.0.1")
        t = create_transport(cfg)
        assert isinstance(t, SSHTransport)

    def test_adb_method(self):
        cfg = ConnectionConfig(method="adb", host="10.0.0.1")
        t = create_transport(cfg)
        assert isinstance(t, ADBTransport)

    def test_unknown_method_raises(self):
        cfg = ConnectionConfig(method="telnet", host="10.0.0.1")
        with pytest.raises(ValueError, match="Unknown connection method"):
            create_transport(cfg)


# ---------------------------------------------------------------------------
# Transport ABC — run_safe and context manager
# ---------------------------------------------------------------------------

class TestTransportRunSafe:
    def test_run_safe_catches_transport_error(self):
        t = MockTransport()
        t.connect()
        t.register("fail_cmd", exit_code=-1, error="boom")
        result = t.run_safe("fail_cmd")
        assert result.exit_code == -1

    def test_context_manager(self):
        t = MockTransport()
        with t:
            assert t.is_connected()
        assert not t.is_connected()
