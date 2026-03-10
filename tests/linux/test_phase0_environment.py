"""Tests for Phase 0 environment assessment (collector/linux/phase0_environment.py)."""

from __future__ import annotations

from collector.linux.phase0_environment import collect_phase0
from tests.conftest import MockTransport


def _setup_phase0_transport(t: MockTransport) -> None:
    t.register("hostname", stdout="target-01\n")
    t.register("uname -a", stdout="Linux target-01 5.15.0 #1 SMP\n")
    t.register_substring("os-release", stdout='NAME="Debian"\n')
    t.register("uptime", stdout=" 10:30:00 up 5 days\n")
    t.register_substring("date -u", stdout="Mon Jan 15 10:30:00 UTC 2024\n")
    t.register_substring("ss -tulnap", stdout="tcp LISTEN 0.0.0.0:22\n")
    t.register_substring("netstat", stdout="tcp 0 0 0.0.0.0:22\n")
    t.register_substring("/proc/net/tcp", stdout="  sl  local_address rem_address\n")
    t.register_substring("/proc/net/tcp6", stdout="  sl  local_address\n")
    t.register_substring("/proc/net/udp", stdout="  sl  local_address\n")
    t.register("ps auxwwf", stdout="root 1 /sbin/init\n")
    t.register_substring("ps -eo", stdout="PID PPID COMM\n1 0 init\n")
    t.register_substring("proc/*/exe", stdout="lrwxrwxrwx 1 root /proc/1/exe -> /sbin/init\n")
    t.register_substring("lsof", stdout="COMMAND PID USER\ninit 1 root\n")
    t.register("lsmod", stdout="ext4 1234 1\n")
    t.register_substring("/proc/modules", stdout="ext4 1234 1\n")
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


class TestCollectPhase0:
    def test_collects_volatile_data(self, mock_transport: MockTransport):
        _setup_phase0_transport(mock_transport)
        snapshot = collect_phase0(mock_transport)
        assert snapshot.hostname == "target-01"
        filenames = {a.filename for a in snapshot.artifacts}
        # System identification
        assert "uname.txt" in filenames
        assert "date_utc.txt" in filenames
        # Network (most volatile)
        assert "ss_connections.txt" in filenames
        assert "proc_net_tcp.txt" in filenames
        # Processes
        assert "ps_full.txt" in filenames
        # Kernel modules
        assert "lsmod.txt" in filenames
        # Memory info
        assert "meminfo.txt" in filenames
        # Taint status
        assert "kernel_tainted.txt" in filenames
        # Mounts
        assert "mount.txt" in filenames

    def test_artifact_count(self, mock_transport: MockTransport):
        _setup_phase0_transport(mock_transport)
        snapshot = collect_phase0(mock_transport)
        # Should capture all 30+ defined commands
        assert len(snapshot.artifacts) >= 28

    def test_handles_failures_gracefully(self, mock_transport: MockTransport):
        mock_transport.register("hostname", stdout="target-01\n")
        # Everything else uses default empty response
        snapshot = collect_phase0(mock_transport)
        assert snapshot.hostname == "target-01"
        assert len(snapshot.artifacts) > 0

    def test_hostname_fallback(self, mock_transport: MockTransport):
        mock_transport.register("hostname", stdout="")
        snapshot = collect_phase0(mock_transport)
        assert snapshot.hostname == "unknown"
