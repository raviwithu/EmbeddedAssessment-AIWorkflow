"""Tests for gold image baseline collector (collector/linux/baseline.py)."""

from __future__ import annotations

from collector.linux.baseline import collect_baseline
from tests.conftest import MockTransport


def _setup_baseline_transport(t: MockTransport) -> None:
    """Register responses for baseline collection commands."""
    t.register("hostname", stdout="test-device\n")
    t.register("uname -a", stdout="Linux test-device 5.15.0 #1 SMP aarch64 GNU/Linux\n")
    t.register_substring("os-release", stdout='NAME="Ubuntu"\nVERSION="22.04"\n')
    t.register_substring("sha256sum", stdout="abc123  /usr/bin/ls\ndef456  /usr/bin/cat\n")
    t.register_substring("find /lib", stdout="ghi789  /lib/libc.so.6\n")
    t.register("ps auxwwf", stdout="root  1  0.0 /sbin/init\n")
    t.register_substring("ps -eo", stdout="PID PPID UID GID COMM ARGS\n1 0 0 0 init /sbin/init\n")
    t.register_substring("/etc/passwd", stdout="root:x:0:0:root:/root:/bin/bash\n")
    t.register_substring("/etc/group", stdout="root:x:0:\n")
    t.register_substring("/etc/shadow", stdout="root:!:19000:0:99999:7:::\n")
    t.register("lsmod", stdout="Module Size Used\next4 1234 1\n")
    t.register_substring("/proc/modules", stdout="ext4 1234 1 - Live 0xffff\n")
    t.register_substring("lsof", stdout="COMMAND PID USER FD TYPE DEVICE\n")
    t.register_substring("ss -tulnap", stdout="Netid State Local\ntcp LISTEN 0.0.0.0:22\n")
    t.register_substring("netstat", stdout="tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN\n")
    t.register_substring("init.d", stdout="total 0\n")
    t.register_substring("rc*.d", stdout="no rc.d\n")
    t.register_substring("config.gz", stdout="# kernel config\nCONFIG_SMP=y\n")
    t.register_substring("lspci", stdout="00:00.0 Host bridge\n")
    t.register_substring("lsusb", stdout="Bus 001 Device 001: root hub\n")
    t.register_substring("lsblk", stdout="sda 8:0 disk 100G\n")
    t.register_substring("ls -la /etc/", stdout="-rw-r--r-- 1 root root 100 Jan 1 passwd\n")
    t.register_substring("ls -la /sbin/", stdout="-rwxr-xr-x 1 root root 100 Jan 1 init\n")
    t.register_substring("perm -4000", stdout="/usr/bin/sudo\n/usr/bin/passwd\n")
    t.register_substring("perm -2000", stdout="/usr/bin/wall\n")
    t.register_substring("lsattr", stdout="none found\n")


class TestCollectBaseline:
    def test_collects_all_artifacts(self, mock_transport: MockTransport):
        _setup_baseline_transport(mock_transport)
        snapshot = collect_baseline(mock_transport)
        assert snapshot.hostname == "test-device"
        assert len(snapshot.artifacts) > 0
        filenames = {a.filename for a in snapshot.artifacts}
        assert "uname.txt" in filenames
        assert "ps_full.txt" in filenames
        assert "passwd.txt" in filenames
        assert "lsmod.txt" in filenames
        assert "ss_listeners.txt" in filenames
        assert "system_hashes.txt" in filenames

    def test_records_commands(self, mock_transport: MockTransport):
        _setup_baseline_transport(mock_transport)
        snapshot = collect_baseline(mock_transport)
        commands = {a.command for a in snapshot.artifacts}
        assert "uname -a" in commands
        assert "lsmod" in commands
        assert "cat /etc/passwd" in commands

    def test_handles_command_failures(self, mock_transport: MockTransport):
        """Commands that fail still produce artifacts with error content."""
        mock_transport.register("hostname", stdout="test-device\n")
        # Everything else will return empty (default MockTransport behavior)
        snapshot = collect_baseline(mock_transport)
        assert snapshot.hostname == "test-device"
        assert len(snapshot.artifacts) > 0

    def test_hostname_fallback(self, mock_transport: MockTransport):
        mock_transport.register("hostname", stdout="")
        snapshot = collect_baseline(mock_transport)
        assert snapshot.hostname == "unknown"
