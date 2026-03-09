"""Configuration loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ConnectionConfig(BaseModel):
    method: str = "ssh"
    host: str = "127.0.0.1"
    port: int = 22
    username: str = "root"
    auth: str = "key"
    key_path: str = "~/.ssh/id_ed25519"
    password: str = ""
    timeout_seconds: int = 10


class TargetConfig(BaseModel):
    name: str
    platform: str = "linux"
    connection: ConnectionConfig = Field(default_factory=ConnectionConfig)


class ModulesConfig(BaseModel):
    process_inventory: dict[str, Any] = Field(default_factory=lambda: {"enabled": True})
    service_port_inventory: dict[str, Any] = Field(default_factory=lambda: {"enabled": True})
    hardening_checks: dict[str, Any] = Field(default_factory=lambda: {"enabled": True})
    hardware_comm: dict[str, Any] = Field(default_factory=lambda: {"enabled": True})


class OutputConfig(BaseModel):
    directory: str = "./output"
    formats: list[str] = Field(default_factory=lambda: ["json", "html", "markdown"])


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str = "./output/assessment.log"


class AppConfig(BaseModel):
    targets: list[TargetConfig] = Field(default_factory=list)
    modules: ModulesConfig = Field(default_factory=ModulesConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


def load_config(path: str | Path = "config/config.yaml") -> AppConfig:
    """Load and validate configuration from a YAML file."""
    config_path = Path(path).expanduser()
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path) as f:
        raw = yaml.safe_load(f)
    return AppConfig.model_validate(raw or {})
