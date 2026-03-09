"""Collect running processes from a Linux target."""

from __future__ import annotations

import logging

from collector.common.transport import Transport
from collector.models import ProcessInfo

logger = logging.getLogger(__name__)


def collect_processes(transport: Transport) -> list[ProcessInfo]:
    """Return a list of running processes via ``ps``."""
    result = transport.run("ps aux --no-headers")
    if result.exit_code != 0:
        logger.error("ps failed: %s", result.stderr)
        return []

    processes: list[ProcessInfo] = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
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
    return processes
