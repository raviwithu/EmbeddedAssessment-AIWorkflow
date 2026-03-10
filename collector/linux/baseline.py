"""Gold Image Baseline collector.

Captures the "known-good" state of a Linux system for later comparison
during forensic analysis (Phase 10 of the playbook).

Baseline items captured:
  - SHA256 hashes of system binaries and libraries
  - Running processes with full paths
  - User accounts, groups, shadow
  - Loaded kernel modules
  - Open files
  - Network listeners and connections
  - /etc/init.d contents and symlinks
  - Kernel configuration
  - Installed devices
  - File permissions on key directories
"""

from __future__ import annotations

import logging

from collector.common.transport import Transport
from collector.models import BaselineSnapshot, ForensicArtifact

logger = logging.getLogger(__name__)

# Commands mapped to artifact filenames.  Each tuple is (filename, command).
_BASELINE_COMMANDS: list[tuple[str, str]] = [
    # System identification
    ("uname.txt", "uname -a"),
    ("os_release.txt", "cat /etc/os-release 2>/dev/null"),
    ("hostname.txt", "hostname"),

    # System binary hashes
    ("system_hashes.txt",
     "find /usr/bin /usr/sbin /bin /sbin -type f -exec sha256sum {} \\; 2>/dev/null"),

    # Library hashes
    ("lib_hashes.txt",
     "find /lib /usr/lib -maxdepth 2 -name '*.so*' -type f -exec sha256sum {} \\; 2>/dev/null"),

    # Running processes
    ("ps_full.txt", "ps auxwwf"),
    ("ps_detailed.txt", "ps -eo pid,ppid,uid,gid,comm,args"),

    # User accounts and groups
    ("passwd.txt", "cat /etc/passwd"),
    ("group.txt", "cat /etc/group"),
    ("shadow.txt", "cat /etc/shadow 2>/dev/null || echo 'PERMISSION_DENIED'"),

    # Loaded kernel modules
    ("lsmod.txt", "lsmod"),
    ("proc_modules.txt", "cat /proc/modules"),

    # Open files
    ("lsof.txt", "lsof -n 2>/dev/null | head -5000 || echo 'lsof not available'"),

    # Network listeners and connections
    ("ss_listeners.txt", "ss -tulnap"),
    ("netstat_listeners.txt", "netstat -tulnap 2>/dev/null || echo 'netstat not available'"),

    # /etc/init.d contents
    ("initd_listing.txt", "ls -la /etc/init.d/ 2>/dev/null || echo 'no init.d'"),
    ("initd_links.txt",
     "find /etc/rc*.d -type l -ls 2>/dev/null || echo 'no rc.d'"),

    # Kernel configuration
    ("kernel_config.txt",
     "zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) 2>/dev/null || echo 'not available'"),

    # Installed devices
    ("lspci.txt", "lspci 2>/dev/null || echo 'lspci not available'"),
    ("lsusb.txt", "lsusb 2>/dev/null || echo 'lsusb not available'"),
    ("lsblk.txt", "lsblk 2>/dev/null || echo 'lsblk not available'"),

    # File permissions on key directories
    ("permissions_etc.txt", "ls -la /etc/ 2>/dev/null | head -100"),
    ("permissions_sbin.txt", "ls -la /sbin/ /usr/sbin/ 2>/dev/null | head -100"),

    # SUID/SGID files
    ("suid_files.txt",
     "find /usr /bin /sbin /opt -perm -4000 -type f 2>/dev/null"),
    ("sgid_files.txt",
     "find /usr /bin /sbin /opt -perm -2000 -type f 2>/dev/null"),

    # Immutable files
    ("immutable_files.txt",
     "lsattr -R /etc/ 2>/dev/null | grep '\\-i\\-' || echo 'none found'"),
]


def collect_baseline(transport: Transport) -> BaselineSnapshot:
    """Collect gold image baseline data from the target."""
    hostname_result = transport.run("hostname")
    hostname = hostname_result.stdout.strip() or "unknown"

    artifacts: list[ForensicArtifact] = []
    errors: list[str] = []

    for filename, command in _BASELINE_COMMANDS:
        result = transport.run(command, timeout=120)
        if result.ok or result.stdout.strip():
            artifacts.append(ForensicArtifact(
                filename=filename,
                content=result.stdout,
                command=command,
            ))
        else:
            errors.append(f"{filename}: {result.stderr or 'empty output'}")
            # Still save what we got (even empty) for the record
            artifacts.append(ForensicArtifact(
                filename=filename,
                content=result.stdout or f"# ERROR: {result.stderr}",
                command=command,
            ))

    logger.info("Baseline: collected %d artifacts for %s", len(artifacts), hostname)

    return BaselineSnapshot(
        hostname=hostname,
        artifacts=artifacts,
        errors=errors,
    )
