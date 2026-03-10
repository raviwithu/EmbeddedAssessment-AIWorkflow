"""Shared data models for collector output and API request/response schemas."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, SecretStr, model_validator


# ---------------------------------------------------------------------------
# Collection result models
# ---------------------------------------------------------------------------

class ProcessInfo(BaseModel):
    pid: int
    user: str
    command: str
    cpu_percent: float = 0.0
    mem_percent: float = 0.0
    state: str = ""


class ServiceInfo(BaseModel):
    name: str
    state: str  # running | stopped | unknown
    enabled: bool = False


class OpenPort(BaseModel):
    protocol: str  # tcp | udp
    port: int
    address: str = "0.0.0.0"
    process: str = ""


class HardeningCheck(BaseModel):
    check_id: str
    category: str
    description: str
    status: Literal["pass", "fail", "warn", "info"]
    detail: str = ""


class HardwareInterface(BaseModel):
    type: Literal["uart", "spi", "i2c", "gpio", "usb", "other"]
    device_path: str
    description: str = ""
    accessible: bool = False


class SystemInfo(BaseModel):
    hostname: str = ""
    kernel: str = ""
    os_release: str = ""
    architecture: str = ""
    uptime: str = ""


class AssessmentResult(BaseModel):
    """Top-level result container for a single target assessment."""

    target_name: str
    platform: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    system_info: SystemInfo = Field(default_factory=SystemInfo)
    processes: list[ProcessInfo] = Field(default_factory=list)
    services: list[ServiceInfo] = Field(default_factory=list)
    open_ports: list[OpenPort] = Field(default_factory=list)
    hardening: list[HardeningCheck] = Field(default_factory=list)
    hardware_interfaces: list[HardwareInterface] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# API request / response schemas
# ---------------------------------------------------------------------------

class TargetConnectionRequest(BaseModel):
    """SSH connection parameters.

    Every field falls back to an environment variable when not provided in
    the request body, so credentials never need to be sent over the wire:

        SSH_HOST, SSH_PORT, SSH_USERNAME, SSH_AUTH, SSH_KEY_PATH,
        SSH_PASSWORD, SSH_TIMEOUT, SSH_CMD_TIMEOUT
    """

    host: str = ""
    port: int = 0
    username: str = ""
    auth: Literal["key", "password"] | None = None
    key_path: str = ""
    password: SecretStr = SecretStr("")
    timeout_seconds: int = 0
    command_timeout: int = 0

    @model_validator(mode="after")
    def _apply_env_defaults(self) -> "TargetConnectionRequest":
        """Fill empty fields from SSH_* environment variables.

        Priority: request body value > env var > built-in default.
        """
        if not self.host:
            self.host = os.environ.get("SSH_HOST", "")
        if not self.host:
            raise ValueError(
                "target.host is required — set it in the request body "
                "or the SSH_HOST env var"
            )
        if self.port == 0:
            self.port = int(os.environ.get("SSH_PORT", "22"))
        if not self.username:
            self.username = os.environ.get("SSH_USERNAME", "root")
        if self.auth is None:
            env_auth = os.environ.get("SSH_AUTH", "key")
            self.auth = env_auth if env_auth in ("key", "password") else "key"
        if not self.key_path:
            self.key_path = os.environ.get("SSH_KEY_PATH", "~/.ssh/id_ed25519")
        if not self.password.get_secret_value():
            env_pw = os.environ.get("SSH_PASSWORD", "")
            self.password = SecretStr(env_pw)
        if self.timeout_seconds == 0:
            self.timeout_seconds = int(os.environ.get("SSH_TIMEOUT", "10"))
        if self.command_timeout == 0:
            self.command_timeout = int(os.environ.get("SSH_CMD_TIMEOUT", "30"))
        return self


class SystemCollectRequest(BaseModel):
    """Request body for POST /collect/linux/system."""

    target: TargetConnectionRequest
    collect_processes: bool = True
    collect_services: bool = True
    collect_ports: bool = True


class SystemCollectResponse(BaseModel):
    """Response from POST /collect/linux/system."""

    target_host: str
    timestamp: datetime
    system_info: SystemInfo
    processes: list[ProcessInfo] = Field(default_factory=list)
    services: list[ServiceInfo] = Field(default_factory=list)
    open_ports: list[OpenPort] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class SecurityCollectRequest(BaseModel):
    """Request body for POST /collect/linux/security."""

    target: TargetConnectionRequest
    checks: list[str] | None = None  # None = all; or list of check IDs to run


class SecurityCollectResponse(BaseModel):
    """Response from POST /collect/linux/security."""

    target_host: str
    timestamp: datetime
    hardening: list[HardeningCheck] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)  # pass/fail/warn/info counts
    errors: list[str] = Field(default_factory=list)


class HwCommsCollectRequest(BaseModel):
    """Request body for POST /collect/linux/hwcomms."""

    target: TargetConnectionRequest
    interface_types: list[str] | None = None  # None = all; or uart/spi/i2c/gpio/usb


class HwCommsCollectResponse(BaseModel):
    """Response from POST /collect/linux/hwcomms."""

    target_host: str
    timestamp: datetime
    hardware_interfaces: list[HardwareInterface] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ReportFormat(str, Enum):
    html = "html"
    markdown = "markdown"


class ReportRenderRequest(BaseModel):
    """Request body for POST /report/render."""

    result: AssessmentResult
    formats: list[ReportFormat] = Field(
        default_factory=lambda: [ReportFormat.html, ReportFormat.markdown]
    )


class RenderedReport(BaseModel):
    format: str
    content: str


class ReportRenderResponse(BaseModel):
    """Response from POST /report/render."""

    target_name: str
    reports: list[RenderedReport] = Field(default_factory=list)
