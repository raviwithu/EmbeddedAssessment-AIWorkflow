"""Collect basic system information from a Linux target."""

from __future__ import annotations

import logging

from collector.common.transport import Transport
from collector.models import SystemInfo

logger = logging.getLogger(__name__)


def collect_system_info(transport: Transport) -> SystemInfo:
    """Gather hostname, kernel, OS release, architecture, and uptime."""
    def _cmd(cmd: str) -> str:
        r = transport.run(cmd)
        return r.stdout.strip() if r.exit_code == 0 else ""

    return SystemInfo(
        hostname=_cmd("hostname"),
        kernel=_cmd("uname -r"),
        os_release=_cmd("cat /etc/os-release 2>/dev/null | head -5"),
        architecture=_cmd("uname -m"),
        uptime=_cmd("uptime -p 2>/dev/null || uptime"),
    )
