"""Phase 0 — Environment Assessment.

Captures volatile system state in order of volatility (most volatile first):
  1. Network connections
  2. Running processes
  3. Open files
  4. Loaded kernel modules
  5. Process environment variables (sampled)
  6. System memory info
  7. Kernel taint status
  8. Mount points

All output is stored as raw text artifacts for forensic analysis.
"""

from __future__ import annotations

import logging

from collector.common.transport import Transport
from collector.models import ForensicArtifact, Phase0Snapshot

logger = logging.getLogger(__name__)

# Phase 0 commands in order of volatility (most volatile first).
_PHASE0_COMMANDS: list[tuple[str, str]] = [
    # Step 0.1 — System identification
    ("uname.txt", "uname -a"),
    ("os_release.txt", "cat /etc/os-release 2>/dev/null"),
    ("uptime.txt", "uptime"),
    ("date_utc.txt", "date -u"),

    # Step 0.2 — Volatile data (most volatile first)

    # 1. Network connections
    ("ss_connections.txt", "ss -tulnap"),
    ("netstat_connections.txt", "netstat -tulnap 2>/dev/null || echo 'netstat not available'"),
    ("proc_net_tcp.txt", "cat /proc/net/tcp 2>/dev/null"),
    ("proc_net_tcp6.txt", "cat /proc/net/tcp6 2>/dev/null"),
    ("proc_net_udp.txt", "cat /proc/net/udp 2>/dev/null"),

    # 2. Running processes
    ("ps_full.txt", "ps auxwwf"),
    ("ps_detailed.txt", "ps -eo pid,ppid,uid,gid,comm,args"),
    ("proc_exe_links.txt", "ls -la /proc/*/exe 2>/dev/null | head -500"),

    # 3. Open files
    ("lsof_full.txt", "lsof -n 2>/dev/null | head -5000 || echo 'lsof not available'"),

    # 4. Loaded kernel modules
    ("lsmod.txt", "lsmod"),
    ("proc_modules.txt", "cat /proc/modules"),

    # 5. Process environment variables (sample first 50 PIDs)
    ("environ_sample.txt",
     "for pid in $(ls -d /proc/[0-9]* 2>/dev/null | head -50 | xargs -I{} basename {}); do "
     "echo \"=== PID $pid ===\"; "
     "cat /proc/$pid/environ 2>/dev/null | tr '\\0' '\\n'; "
     "echo; done"),

    # 6. System memory info
    ("meminfo.txt", "cat /proc/meminfo"),
    ("vmstat.txt", "cat /proc/vmstat"),
    ("slabinfo.txt", "cat /proc/slabinfo 2>/dev/null || echo 'permission denied'"),

    # 7. Kernel taint status
    ("kernel_tainted.txt", "cat /proc/sys/kernel/tainted"),

    # 8. Mount points
    ("mount.txt", "mount"),
    ("proc_mounts.txt", "cat /proc/mounts"),

    # Additional volatile data
    ("arp_cache.txt", "cat /proc/net/arp 2>/dev/null"),
    ("routing_table.txt", "ip route 2>/dev/null || route -n 2>/dev/null"),
    ("dns_resolv.txt", "cat /etc/resolv.conf 2>/dev/null"),
    ("iptables_rules.txt", "iptables -L -n -v 2>/dev/null || echo 'iptables not available'"),
    ("crontabs.txt",
     "for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do "
     "echo \"=== $u ===\"; crontab -l -u $u 2>/dev/null; done"),
    ("systemd_timers.txt", "systemctl list-timers --all --no-pager 2>/dev/null || echo 'not systemd'"),
    ("loginlog.txt", "last -20 2>/dev/null || echo 'last not available'"),
    ("dmesg_tail.txt", "dmesg 2>/dev/null | tail -200 || echo 'dmesg not available'"),
]


def collect_phase0(transport: Transport) -> Phase0Snapshot:
    """Capture Phase 0 volatile environment data from the target."""
    hostname_result = transport.run("hostname")
    hostname = hostname_result.stdout.strip() or "unknown"

    artifacts: list[ForensicArtifact] = []
    errors: list[str] = []

    for filename, command in _PHASE0_COMMANDS:
        result = transport.run(command, timeout=120)
        if result.ok or result.stdout.strip():
            artifacts.append(ForensicArtifact(
                filename=filename,
                content=result.stdout,
                command=command,
            ))
        else:
            errors.append(f"{filename}: {result.stderr or 'empty output'}")
            artifacts.append(ForensicArtifact(
                filename=filename,
                content=result.stdout or f"# ERROR: {result.stderr}",
                command=command,
            ))

    logger.info("Phase 0: captured %d artifacts for %s", len(artifacts), hostname)

    return Phase0Snapshot(
        hostname=hostname,
        artifacts=artifacts,
        errors=errors,
    )
