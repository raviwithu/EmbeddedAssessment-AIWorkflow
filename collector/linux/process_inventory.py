"""Collect running processes from a Linux target."""

from __future__ import annotations

import logging

from collector.common.transport import Transport
from collector.models import ProcessInfo

logger = logging.getLogger(__name__)


def collect_processes(transport: Transport) -> list[ProcessInfo]:
    """Return a list of running processes via ``ps``.

    Tries GNU ``ps aux`` first (11 columns), then falls back to BusyBox
    ``ps -o pid,user,stat,args`` (4 columns) which is common on embedded
    systems.
    """
    result = transport.run("ps aux --no-headers 2>/dev/null")
    if result.exit_code == 0 and result.stdout.strip():
        return _parse_gnu_ps(result.stdout)

    # Fallback for BusyBox / minimal ps
    result = transport.run("ps -o pid,user,stat,args 2>/dev/null || ps -ef 2>/dev/null")
    if result.exit_code != 0:
        logger.error("ps failed: %s", result.stderr)
        return []
    return _parse_fallback_ps(result.stdout)


def _parse_gnu_ps(output: str) -> list[ProcessInfo]:
    """Parse GNU coreutils ``ps aux --no-headers`` output."""
    processes: list[ProcessInfo] = []
    for line in output.strip().splitlines():
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            processes.append(
                ProcessInfo(
                    user=parts[0],
                    pid=int(parts[1]),
                    cpu_percent=float(parts[2]),
                    mem_percent=float(parts[3]),
                    state=parts[7],
                    command=parts[10],
                )
            )
        except (ValueError, IndexError):
            logger.debug("Skipping unparseable ps line: %s", line[:120])
    return processes


def _parse_fallback_ps(output: str) -> list[ProcessInfo]:
    """Parse BusyBox-style ``ps -o pid,user,stat,args`` output."""
    processes: list[ProcessInfo] = []
    for line in output.strip().splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        # Skip header rows
        if parts[0].upper() == "PID":
            continue
        try:
            processes.append(
                ProcessInfo(
                    pid=int(parts[0]),
                    user=parts[1],
                    state=parts[2],
                    command=parts[3],
                )
            )
        except (ValueError, IndexError):
            logger.debug("Skipping unparseable ps line: %s", line[:120])
    return processes
