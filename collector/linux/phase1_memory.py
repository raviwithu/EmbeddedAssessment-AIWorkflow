"""Phase 1 — Memory Acquisition.

Handles remote memory acquisition via SSH:
  - Checks for LiME module availability
  - Falls back to /proc/kcore if LiME unavailable
  - Verifies acquisition integrity via SHA256
  - Records memory size and dump metadata

Note: LiME kernel module must be pre-compiled for the target's exact
kernel version and placed on the target before this phase runs.
This collector captures the commands and metadata — the actual memory
dump file stays on the target or a network destination.
"""

from __future__ import annotations

import logging

from collector.common.transport import Transport
from collector.models import ForensicArtifact, Phase1Snapshot

logger = logging.getLogger(__name__)


def collect_phase1(
    transport: Transport,
    dump_path: str = "/tmp/forensic",
) -> Phase1Snapshot:
    """Execute Phase 1 memory acquisition on the target.

    Args:
        transport: Connected transport to the target.
        dump_path: Remote directory on the target where the memory dump
                   will be stored.  Defaults to /tmp/forensic.
    """
    hostname_result = transport.run("hostname")
    hostname = hostname_result.stdout.strip() or "unknown"

    artifacts: list[ForensicArtifact] = []
    errors: list[str] = []

    # Create dump directory on target
    transport.run(f"mkdir -p {dump_path}")

    # Record system memory size for verification
    meminfo = transport.run("cat /proc/meminfo")
    artifacts.append(ForensicArtifact(
        filename="meminfo.txt",
        content=meminfo.stdout,
        command="cat /proc/meminfo",
    ))

    mem_total = _parse_mem_total(meminfo.stdout)

    # Step 1.1 — Attempt memory acquisition
    dump_file = f"{dump_path}/memory.lime"
    method_used = ""
    dump_sha256 = ""
    dump_size = 0

    # Try LiME first
    lime_check = transport.run(
        f"ls /mnt/trusted_usb/lime-$(uname -r).ko 2>/dev/null || "
        f"ls /tmp/lime-$(uname -r).ko 2>/dev/null || "
        f"find / -name 'lime-*.ko' -maxdepth 3 2>/dev/null | head -1"
    )
    lime_path = lime_check.stdout.strip().splitlines()[0] if lime_check.stdout.strip() else ""

    if lime_path:
        method_used = "lime"
        logger.info("Found LiME module at %s", lime_path)
        load_result = transport.run(
            f'sudo insmod {lime_path} "path={dump_file} format=lime"',
            timeout=300,
        )
        if load_result.exit_code != 0:
            errors.append(f"LiME insmod failed: {load_result.stderr}")
            method_used = ""
        else:
            artifacts.append(ForensicArtifact(
                filename="lime_load.txt",
                content=f"Loaded: {lime_path}\nOutput: {load_result.stdout}\n{load_result.stderr}",
                command=f"insmod {lime_path}",
            ))
    else:
        logger.warning("LiME module not found on target")
        artifacts.append(ForensicArtifact(
            filename="lime_search.txt",
            content="LiME module not found. Searched:\n"
                    "  /mnt/trusted_usb/lime-$(uname -r).ko\n"
                    "  /tmp/lime-$(uname -r).ko\n"
                    "  find / -name 'lime-*.ko' -maxdepth 3",
            command="lime search",
        ))

    # Fallback to /proc/kcore if LiME didn't work
    if not method_used:
        kcore_check = transport.run("test -r /proc/kcore && echo yes || echo no")
        if "yes" in kcore_check.stdout:
            method_used = "kcore"
            dump_file = f"{dump_path}/kcore.elf"
            logger.info("Falling back to /proc/kcore")
            # Note: only record that we CAN copy — actual copy may be very large
            artifacts.append(ForensicArtifact(
                filename="kcore_available.txt",
                content="WARNING: /proc/kcore is available but may be hooked by malware.\n"
                        f"To copy: cp /proc/kcore {dump_file}\n"
                        "This is less reliable than LiME.",
                command="test -r /proc/kcore",
            ))
            # Get kcore size
            kcore_stat = transport.run("ls -l /proc/kcore 2>/dev/null")
            artifacts.append(ForensicArtifact(
                filename="kcore_stat.txt",
                content=kcore_stat.stdout,
                command="ls -l /proc/kcore",
            ))
        else:
            errors.append("Neither LiME nor /proc/kcore available for memory acquisition")

    # Step 1.2 — Verify acquisition integrity (if dump exists)
    if method_used == "lime":
        sha_result = transport.run(f"sha256sum {dump_file} 2>/dev/null")
        if sha_result.ok and sha_result.stdout.strip():
            dump_sha256 = sha_result.stdout.strip().split()[0]
            artifacts.append(ForensicArtifact(
                filename="memory_sha256.txt",
                content=sha_result.stdout,
                command=f"sha256sum {dump_file}",
            ))

        size_result = transport.run(f"stat -c %s {dump_file} 2>/dev/null || ls -l {dump_file}")
        if size_result.ok:
            try:
                dump_size = int(size_result.stdout.strip().split()[0])
            except (ValueError, IndexError):
                pass
            artifacts.append(ForensicArtifact(
                filename="memory_size.txt",
                content=f"Dump size: {dump_size} bytes\nMemTotal: {mem_total} kB\n"
                        f"Method: {method_used}\nPath: {dump_file}",
                command=f"stat {dump_file}",
            ))

    # Record kernel version for profile matching (Phase 2)
    kernel_ver = transport.run("uname -r")
    artifacts.append(ForensicArtifact(
        filename="kernel_version.txt",
        content=kernel_ver.stdout,
        command="uname -r",
    ))

    system_map_check = transport.run(
        "ls /boot/System.map-$(uname -r) 2>/dev/null && echo 'found' || echo 'not found'"
    )
    artifacts.append(ForensicArtifact(
        filename="system_map_check.txt",
        content=system_map_check.stdout,
        command="ls /boot/System.map-$(uname -r)",
    ))

    logger.info(
        "Phase 1: method=%s, dump=%s, sha256=%s",
        method_used or "none", dump_file, dump_sha256[:16] + "..." if dump_sha256 else "n/a",
    )

    return Phase1Snapshot(
        hostname=hostname,
        artifacts=artifacts,
        memory_dump_path=dump_file if method_used else "",
        memory_dump_sha256=dump_sha256,
        memory_dump_size_bytes=dump_size,
        errors=errors,
    )


def _parse_mem_total(meminfo_output: str) -> str:
    """Extract MemTotal value from /proc/meminfo output."""
    for line in meminfo_output.splitlines():
        if line.startswith("MemTotal:"):
            return line.split(":")[1].strip()
    return "unknown"
