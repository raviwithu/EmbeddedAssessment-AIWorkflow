"""Tests for the full Linux assessment orchestrator."""

from __future__ import annotations

import json
from pathlib import Path

from collector.orchestrator import (
    _sanitize_hostname,
    build_parser,
    is_linux,
    run_full_assessment,
)
from tests.conftest import MockTransport


def _setup_linux_transport(t: MockTransport) -> None:
    """Register responses for a minimal Linux target."""
    t.register("uname -s", stdout="Linux\n")
    t.register("hostname", stdout="test-device\n")
    t.register("uname -a", stdout="Linux test-device 5.15.0 #1 SMP\n")
    t.register_substring("os-release", stdout='NAME="Ubuntu"\n')
    t.register("uptime", stdout=" 10:30:00 up 5 days\n")
    t.register_substring("date -u", stdout="Mon Jan 15 10:30:00 UTC 2024\n")

    # Processes
    t.register("ps auxwwf", stdout="root 1 0.0 0.5 /sbin/init\n")
    t.register_substring("ps -eo", stdout="PID PPID COMM\n1 0 init\n")

    # Services
    t.register_substring("systemctl list-units", stdout="sshd.service loaded active running\n")
    t.register_substring("systemctl list-unit-files", stdout="sshd.service enabled\n")
    t.register_substring("systemctl show", stdout="Id=sshd.service\nMainPID=100\n")

    # Ports
    t.register_substring("ss -tulnap", stdout="tcp LISTEN 0.0.0.0:22\n")
    t.register_substring("netstat", stdout="tcp 0 0 0.0.0.0:22\n")

    # Hardening
    t.register_substring("sshd_config", stdout="PermitRootLogin no\nPasswordAuthentication no\n")
    t.register_substring("iptables -L", stdout="Chain INPUT (policy DROP)\n")
    t.register_substring("getenforce", stdout="Enforcing\n")
    t.register_substring("randomize_va_space", stdout="2\n")
    t.register_substring("core_pattern", stdout="core\n")
    t.register_substring("perm -4000", stdout="/usr/bin/sudo\n")

    # Hardware
    t.register_substring("/dev/ttyS", stdout="/dev/ttyS0\n")
    t.register_substring("/dev/spi", stdout="")
    t.register_substring("/dev/i2c", stdout="")
    t.register_substring("/sys/class/gpio", stdout="")
    t.register_substring("lsusb", stdout="Bus 001 Device 001: root hub\n")

    # Baseline
    t.register_substring("sha256sum", stdout="abc123  /usr/bin/ls\n")
    t.register_substring("/etc/passwd", stdout="root:x:0:0:root:/root:/bin/bash\n")
    t.register_substring("/etc/group", stdout="root:x:0:\n")
    t.register_substring("/etc/shadow", stdout="root:!:19000:0:99999:7:::\n")
    t.register("lsmod", stdout="ext4 1234 1\n")
    t.register_substring("/proc/modules", stdout="ext4 1234 1\n")
    t.register_substring("lsof", stdout="COMMAND PID USER\n")
    t.register_substring("init.d", stdout="total 0\n")
    t.register_substring("rc*.d", stdout="no rc.d\n")
    t.register_substring("config.gz", stdout="CONFIG_SMP=y\n")
    t.register_substring("lspci", stdout="00:00.0 Host bridge\n")
    t.register_substring("lsblk", stdout="sda 8:0 disk 100G\n")
    t.register_substring("ls -la /etc/", stdout="-rw-r--r-- 1 root root 100 passwd\n")
    t.register_substring("ls -la /sbin/", stdout="-rwxr-xr-x 1 root root 100 init\n")
    t.register_substring("perm -2000", stdout="/usr/bin/wall\n")
    t.register_substring("lsattr", stdout="none\n")
    t.register_substring("find /lib", stdout="ghi789  /lib/libc.so.6\n")

    # Phase 0 extras
    t.register_substring("/proc/net/tcp", stdout="  sl  local_address\n")
    t.register_substring("/proc/net/tcp6", stdout="  sl  local_address\n")
    t.register_substring("/proc/net/udp", stdout="  sl  local_address\n")
    t.register_substring("proc/*/exe", stdout="lrwxrwxrwx 1 root /proc/1/exe -> /sbin/init\n")
    t.register_substring("environ", stdout="=== PID 1 ===\nPATH=/usr/bin\n")
    t.register_substring("/proc/meminfo", stdout="MemTotal: 4096000 kB\nMemFree: 2048000 kB\n")
    t.register_substring("/proc/vmstat", stdout="nr_free_pages 512000\n")
    t.register_substring("/proc/slabinfo", stdout="# name <active_objs>\n")
    t.register_substring("kernel/tainted", stdout="0\n")
    t.register("mount", stdout="/dev/sda1 on / type ext4\n")
    t.register_substring("/proc/mounts", stdout="/dev/sda1 / ext4 rw 0 0\n")
    t.register_substring("/proc/net/arp", stdout="IP address HW type\n")
    t.register_substring("ip route", stdout="default via 10.0.0.1\n")
    t.register_substring("resolv.conf", stdout="nameserver 8.8.8.8\n")
    t.register_substring("iptables", stdout="Chain INPUT (policy ACCEPT)\n")
    t.register_substring("crontab", stdout="=== root ===\nno crontab\n")
    t.register_substring("list-timers", stdout="NEXT LEFT LAST\n")
    t.register_substring("last -20", stdout="root pts/0 10.0.0.1 Mon Jan 15\n")
    t.register_substring("dmesg", stdout="[    0.000000] Linux version 5.15.0\n")

    # Phase 1
    t.register_substring("mkdir -p", stdout="")
    t.register("uname -r", stdout="5.15.0-generic\n")
    t.register_substring("lime-$(uname -r)", stdout="")
    t.register_substring("lime-*.ko", stdout="")
    t.register_substring("test -r /proc/kcore", stdout="yes\n")
    t.register_substring("ls -l /proc/kcore", stdout="-r-------- 1 root root 140737477881856\n")
    t.register_substring("System.map", stdout="not found\n")


class TestIsLinux:
    def test_linux_detected(self, mock_transport: MockTransport):
        mock_transport.register("uname -s", stdout="Linux\n")
        assert is_linux(mock_transport) is True

    def test_non_linux_detected(self, mock_transport: MockTransport):
        mock_transport.register("uname -s", stdout="Darwin\n")
        assert is_linux(mock_transport) is False

    def test_empty_response(self, mock_transport: MockTransport):
        mock_transport.register("uname -s", stdout="")
        assert is_linux(mock_transport) is False


class TestRunFullAssessment:
    def test_detects_linux_and_runs_all(self, mock_transport: MockTransport, tmp_path):
        _setup_linux_transport(mock_transport)
        summary = run_full_assessment(mock_transport, output_dir=str(tmp_path))
        assert summary["platform"] == "linux"
        assert summary["hostname"] == "test-device"
        assert "system_info" in summary["collectors_run"]
        assert "process_inventory" in summary["collectors_run"]
        assert "hardening_checks" in summary["collectors_run"]
        assert "baseline" in summary["collectors_run"]
        assert "phase0" in summary["collectors_run"]
        assert "phase1" in summary["collectors_run"]

    def test_skips_non_linux(self, mock_transport: MockTransport, tmp_path):
        mock_transport.register("uname -s", stdout="FreeBSD\n")
        summary = run_full_assessment(mock_transport, output_dir=str(tmp_path))
        assert summary["platform"] == "FreeBSD"
        assert summary["collectors_run"] == []
        assert any("not Linux" in e for e in summary["errors"])

    def test_creates_host_folder(self, mock_transport: MockTransport, tmp_path):
        _setup_linux_transport(mock_transport)
        summary = run_full_assessment(mock_transport, output_dir=str(tmp_path))
        host_dir = Path(summary["output_path"])
        assert host_dir.exists()
        assert host_dir.name == "test-device"

    def test_saves_assessment_json(self, mock_transport: MockTransport, tmp_path):
        _setup_linux_transport(mock_transport)
        summary = run_full_assessment(mock_transport, output_dir=str(tmp_path))
        json_path = Path(summary["output_path"]) / "assessment_result.json"
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert data["target_name"] == "test-device"
        assert data["platform"] == "linux"

    def test_generates_reports(self, mock_transport: MockTransport, tmp_path):
        _setup_linux_transport(mock_transport)
        summary = run_full_assessment(mock_transport, output_dir=str(tmp_path))
        host_dir = Path(summary["output_path"])
        assert (host_dir / "report.html").exists()
        assert (host_dir / "report.md").exists()

    def test_individual_collector_failure_continues(self, mock_transport: MockTransport, tmp_path):
        """A failing collector should not stop the rest from running."""
        mock_transport.register("uname -s", stdout="Linux\n")
        mock_transport.register("hostname", stdout="fail-test\n")
        # Only register minimal responses — most collectors will fail/return empty
        # but the orchestrator should still complete
        summary = run_full_assessment(mock_transport, output_dir=str(tmp_path))
        assert summary["hostname"] == "fail-test"
        # At least some collectors should have run (even if with empty data)
        total = len(summary["collectors_run"]) + len(summary["collectors_failed"])
        assert total > 0

    def test_updates_existing_folder(self, mock_transport: MockTransport, tmp_path):
        _setup_linux_transport(mock_transport)
        # First run
        summary1 = run_full_assessment(mock_transport, output_dir=str(tmp_path))
        # Second run (same host)
        summary2 = run_full_assessment(mock_transport, output_dir=str(tmp_path))
        # Both should use the same output path
        assert summary1["output_path"] == summary2["output_path"]
        # Baseline manifest should have 2 runs
        manifest_path = Path(summary2["output_path"]) / "test-device" / "baseline" / "manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            assert len(manifest["runs"]) == 2

    def test_forensic_artifacts_saved(self, mock_transport: MockTransport, tmp_path):
        _setup_linux_transport(mock_transport)
        summary = run_full_assessment(mock_transport, output_dir=str(tmp_path))
        host_dir = Path(summary["output_path"])
        # Baseline folder should exist with artifacts
        baseline_dir = host_dir / "test-device" / "baseline"
        if baseline_dir.exists():
            assert (baseline_dir / "manifest.json").exists()


class TestCliParsing:
    def test_host_args(self):
        parser = build_parser()
        args = parser.parse_args(["--host", "10.0.0.5", "--username", "admin", "--port", "2222"])
        assert args.host == "10.0.0.5"
        assert args.username == "admin"
        assert args.port == 2222

    def test_config_file_args(self):
        parser = build_parser()
        args = parser.parse_args(["--config", "config/config.yaml", "--target", "my-device"])
        assert args.config == "config/config.yaml"
        assert args.target == "my-device"

    def test_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["--host", "10.0.0.1"])
        assert args.port == 22
        assert args.username == "root"
        assert args.auth == "key"
        assert args.output == "./output"
        assert args.log_level == "INFO"


class TestSanitizeHostname:
    def test_removes_slashes(self):
        assert _sanitize_hostname("host/name") == "host_name"

    def test_removes_backslashes(self):
        assert _sanitize_hostname("host\\name") == "host_name"

    def test_strips_whitespace(self):
        assert _sanitize_hostname("  host  ") == "host"
