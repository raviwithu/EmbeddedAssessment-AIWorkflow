"""Tests for YAML config loading (collector/config.py)."""

from __future__ import annotations

import pytest

from collector.config import (
    AppConfig,
    ConnectionConfig,
    LoggingConfig,
    ModulesConfig,
    ModuleToggle,
    OutputConfig,
    TargetConfig,
    load_config,
)


class TestConnectionConfig:
    def test_defaults(self):
        c = ConnectionConfig()
        assert c.method == "ssh"
        assert c.host == "127.0.0.1"
        assert c.port == 22
        assert c.username == "root"
        assert c.auth == "key"
        assert c.timeout_seconds == 10

    def test_custom_values(self):
        c = ConnectionConfig(host="10.0.0.1", port=2222, method="adb")
        assert c.host == "10.0.0.1"
        assert c.port == 2222
        assert c.method == "adb"

    def test_port_too_low_raises(self):
        with pytest.raises(ValueError, match="Port must be 1-65535"):
            ConnectionConfig(port=0)

    def test_port_too_high_raises(self):
        with pytest.raises(ValueError, match="Port must be 1-65535"):
            ConnectionConfig(port=70000)

    def test_valid_port_boundaries(self):
        assert ConnectionConfig(port=1).port == 1
        assert ConnectionConfig(port=65535).port == 65535


class TestTargetConfig:
    def test_defaults(self):
        t = TargetConfig(name="router")
        assert t.platform == "linux"
        assert t.connection.method == "ssh"

    def test_nested_connection(self):
        t = TargetConfig(
            name="router",
            connection=ConnectionConfig(host="192.168.1.1", port=22),
        )
        assert t.connection.host == "192.168.1.1"


class TestModulesConfig:
    def test_all_enabled_by_default(self):
        m = ModulesConfig()
        assert m.process_inventory.enabled is True
        assert m.service_port_inventory.enabled is True
        assert m.hardening_checks.enabled is True
        assert m.hardware_comm.enabled is True

    def test_disable_module(self):
        m = ModulesConfig(process_inventory=ModuleToggle(enabled=False))
        assert m.process_inventory.enabled is False


class TestLoadConfig:
    def test_valid_yaml(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""\
targets:
  - name: test-device
    platform: linux
    connection:
      host: 10.0.0.1
      port: 22
      username: root
modules:
  process_inventory:
    enabled: true
  hardening_checks:
    enabled: false
output:
  directory: ./out
  formats:
    - json
logging:
  level: DEBUG
""")
        cfg = load_config(str(config_file))
        assert len(cfg.targets) == 1
        assert cfg.targets[0].name == "test-device"
        assert cfg.targets[0].connection.host == "10.0.0.1"
        assert cfg.modules.hardening_checks.enabled is False
        assert cfg.output.directory == "./out"
        assert cfg.logging.level == "DEBUG"

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_path / "nonexistent.yaml"))

    def test_empty_yaml_uses_defaults(self, tmp_path):
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")
        cfg = load_config(str(config_file))
        assert isinstance(cfg, AppConfig)
        assert cfg.targets == []
        assert cfg.modules.process_inventory.enabled is True

    def test_minimal_yaml(self, tmp_path):
        config_file = tmp_path / "min.yaml"
        config_file.write_text("targets: []")
        cfg = load_config(str(config_file))
        assert cfg.targets == []
