"""Collect services and open ports from a Linux target."""

from __future__ import annotations

import logging
import re

from collector.common.transport import Transport
from collector.models import OpenPort, ServiceInfo

logger = logging.getLogger(__name__)


def collect_services(transport: Transport) -> list[ServiceInfo]:
    """List systemd services and their states."""
    result = transport.run(
        "systemctl list-units --type=service --all --no-pager --no-legend"
    )
    if result.exit_code != 0:
        logger.warning("systemctl failed (may not be systemd): %s", result.stderr)
        return []

    services: list[ServiceInfo] = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        name = parts[0].removesuffix(".service")
        active = parts[2]  # active / inactive
        services.append(
            ServiceInfo(
                name=name,
                state=active,
                enabled=(active == "active"),
            )
        )
    return services


def collect_open_ports(transport: Transport) -> list[OpenPort]:
    """List open listening ports via ``ss``."""
    result = transport.run("ss -tulnp")
    if result.exit_code != 0:
        logger.warning("ss failed, trying netstat: %s", result.stderr)
        result = transport.run("netstat -tulnp")
        if result.exit_code != 0:
            logger.error("Could not enumerate ports: %s", result.stderr)
            return []

    ports: list[OpenPort] = []
    for line in result.stdout.strip().splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "udp"):
            continue
        local = parts[4]
        addr, _, port_str = local.rpartition(":")
        if not port_str.isdigit():
            continue
        process_match = re.search(r'users:\(\("([^"]+)"', line)
        ports.append(
            OpenPort(
                protocol=proto,
                port=int(port_str),
                address=addr or "0.0.0.0",
                process=process_match.group(1) if process_match else "",
            )
        )
    return ports
