"""Abstraction for executing commands on a remote target."""

from __future__ import annotations

import abc
import logging
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Self

import paramiko

from collector.config import ConnectionConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class TransportError(Exception):
    """Base error for transport-level failures."""


class ConnectionFailed(TransportError):
    """Failed to establish a connection to the target."""


class CommandTimedOut(TransportError):
    """A remote command exceeded its timeout."""


class CommandFailed(TransportError):
    """A remote command encountered a transport-level error (not just non-zero exit)."""


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.error


# ---------------------------------------------------------------------------
# Abstract transport
# ---------------------------------------------------------------------------

class Transport(abc.ABC):
    """Base class for target transports."""

    @abc.abstractmethod
    def connect(self) -> None: ...

    @abc.abstractmethod
    def run(self, command: str, timeout: int = 30) -> CommandResult: ...

    @abc.abstractmethod
    def is_connected(self) -> bool: ...

    @abc.abstractmethod
    def close(self) -> None: ...

    def run_safe(self, command: str, timeout: int = 30) -> CommandResult:
        """Run a command, catching transport errors into the result."""
        try:
            return self.run(command, timeout=timeout)
        except TransportError as exc:
            return CommandResult(
                command=command, stdout="", stderr=str(exc),
                exit_code=-1, error=str(exc),
            )

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

class SSHTransport(Transport):
    """SSH-based command execution via paramiko."""

    def __init__(self, config: ConnectionConfig) -> None:
        self._config = config
        self._command_timeout = config.command_timeout
        self._client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        client = paramiko.SSHClient()

        # Load system known-hosts and optional custom file; reject unknown keys
        # by default (WarningPolicy logs + accepts for usability, but avoids
        # the silent-accept security hole of AutoAddPolicy).
        known_hosts = Path(self._config.known_hosts_path).expanduser()
        if known_hosts.exists():
            client.load_host_keys(str(known_hosts))
        system_known = Path("~/.ssh/known_hosts").expanduser()
        if system_known.exists():
            client.load_system_host_keys(str(system_known))
        client.set_missing_host_key_policy(paramiko.WarningPolicy())

        kw: dict = {
            "hostname": self._config.host,
            "port": self._config.port,
            "username": self._config.username,
            "timeout": self._config.timeout_seconds,
            "banner_timeout": self._config.timeout_seconds,
            "auth_timeout": self._config.timeout_seconds,
        }
        if self._config.auth == "key":
            key_path = Path(self._config.key_path).expanduser()
            if not key_path.exists():
                raise ConnectionFailed(f"SSH key not found: {key_path}")
            kw["key_filename"] = str(key_path)
        else:
            kw["password"] = self._config.password.get_secret_value()

        logger.info(
            "SSH connecting to %s:%d as %s",
            self._config.host, self._config.port, self._config.username,
        )
        try:
            client.connect(**kw)
        except paramiko.AuthenticationException as exc:
            raise ConnectionFailed(
                f"Authentication failed for {self._config.username}@"
                f"{self._config.host}: {exc}"
            ) from exc
        except (paramiko.SSHException, socket.error) as exc:
            raise ConnectionFailed(
                f"Connection failed to {self._config.host}:{self._config.port}: {exc}"
            ) from exc

        self._client = client
        logger.info("SSH connected to %s:%d", self._config.host, self._config.port)

    def run(self, command: str, timeout: int | None = None) -> CommandResult:
        if self._client is None:
            raise ConnectionFailed("Not connected — call connect() first")
        if timeout is None:
            timeout = self._command_timeout

        logger.debug("SSH exec (timeout=%ds): %s", timeout, command[:120])

        try:
            _, stdout_ch, stderr_ch = self._client.exec_command(
                command, timeout=timeout,
            )
            exit_code = stdout_ch.channel.recv_exit_status()
            stdout = stdout_ch.read().decode(errors="replace")
            stderr = stderr_ch.read().decode(errors="replace")
        except socket.timeout:
            msg = f"Timed out after {timeout}s"
            logger.warning("Command timed out: %s", command[:80])
            return CommandResult(
                command=command, stdout="", stderr=msg,
                exit_code=-1, timed_out=True, error=msg,
            )
        except (paramiko.SSHException, socket.error) as exc:
            raise CommandFailed(
                f"SSH error executing '{command[:80]}': {exc}"
            ) from exc

        if exit_code != 0:
            logger.debug("Non-zero exit (%d): %s", exit_code, command[:80])

        return CommandResult(
            command=command, stdout=stdout, stderr=stderr, exit_code=exit_code,
        )

    def is_connected(self) -> bool:
        if self._client is None:
            return False
        tp = self._client.get_transport()
        return tp is not None and tp.is_active()

    def close(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            logger.debug("SSH connection closed")


# ---------------------------------------------------------------------------
# ADB placeholder
# ---------------------------------------------------------------------------

class ADBTransport(Transport):
    """Placeholder for Android Debug Bridge transport (future implementation)."""

    def __init__(self, config: ConnectionConfig) -> None:
        self._config = config

    def connect(self) -> None:
        raise NotImplementedError("ADB transport is not yet implemented")

    def run(self, command: str, timeout: int = 30) -> CommandResult:
        raise NotImplementedError("ADB transport is not yet implemented")

    def is_connected(self) -> bool:
        return False

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_transport(config: ConnectionConfig) -> Transport:
    """Return the right transport for the connection method."""
    if config.method == "ssh":
        return SSHTransport(config)
    if config.method == "adb":
        return ADBTransport(config)
    raise ValueError(f"Unknown connection method: {config.method}")
