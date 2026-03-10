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


# ---------------------------------------------------------------------------
# H6: Timeout simulation tests
# ---------------------------------------------------------------------------

class TestTimeoutHandling:
    def test_timed_out_command_result(self):
        """Verify that timed_out flag makes result not ok."""
        t = MockTransport()
        t.connect()
        t.register("slow_cmd", timed_out=True, exit_code=-1, error="Timed out")
        result = t.run("slow_cmd")
        assert result.timed_out is True
        assert result.ok is False
        assert result.exit_code == -1

    def test_run_safe_handles_timeout(self):
        """run_safe should return a result even for timeouts."""
        t = MockTransport()
        t.connect()
        t.register("slow_cmd", timed_out=True, exit_code=-1, error="Timed out")
        result = t.run_safe("slow_cmd")
        assert result.timed_out is True
        assert not result.ok


# ---------------------------------------------------------------------------
# H7: ConnectionFailed tests
# ---------------------------------------------------------------------------

class TestConnectionFailedHandling:
    def test_connection_failed_exception(self):
        """ConnectionFailed is a TransportError with descriptive message."""
        exc = ConnectionFailed("Auth failed for root@10.0.0.1")
        assert isinstance(exc, TransportError)
        assert "Auth failed" in str(exc)

    def test_transport_not_connected_raises(self):
        """Calling run on disconnected SSHTransport raises ConnectionFailed."""
        cfg = ConnectionConfig(host="10.0.0.1")
        t = SSHTransport(cfg)
        # Not connected — should raise
        with pytest.raises(ConnectionFailed, match="Not connected"):
            t.run("id")


# ---------------------------------------------------------------------------
# L5: Large output handling
# ---------------------------------------------------------------------------

class TestLargeOutput:
    def test_large_stdout_handled(self):
        """Transport should handle large command output without error."""
        t = MockTransport()
        t.connect()
        large_output = "x" * 100_000 + "\n" + "y" * 100_000
        t.register("big_cmd", stdout=large_output)
        result = t.run("big_cmd")
        assert len(result.stdout) == 200_001
        assert result.ok
