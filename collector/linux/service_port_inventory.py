"""Collect services and open ports from a Linux target."""

from __future__ import annotations

import logging
import re

from collector.common.transport import Transport
from collector.models import OpenPort, ServiceInfo

logger = logging.getLogger(__name__)


def collect_services(transport: Transport) -> list[ServiceInfo]:
    """List systemd services and their states.

    Uses ``list-units`` for runtime state (active/inactive) and
    ``list-unit-files`` for boot-time enablement, then merges both.
    """
    # Runtime state
    result = transport.run(
        "systemctl list-units --type=service --all --no-pager --no-legend"
    )
    if result.exit_code != 0:
        logger.warning("systemctl failed (may not be systemd): %s", result.stderr)
        return []

    services: dict[str, ServiceInfo] = {}
    for line in result.stdout.strip().splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        name = parts[0].removesuffix(".service")
        active = parts[2]  # active / inactive
        services[name] = ServiceInfo(
            name=name,
            state=active,
            enabled=False,  # will be updated from unit-files below
        )

    # Boot-time enablement
    uf_result = transport.run(
        "systemctl list-unit-files --type=service --no-pager --no-legend"
    )
    if uf_result.exit_code == 0:
        for line in uf_result.stdout.strip().splitlines():
            uf_parts = line.split(None, 2)
            if len(uf_parts) < 2:
                continue
            uf_name = uf_parts[0].removesuffix(".service")
            uf_state = uf_parts[1]  # enabled / disabled / static / masked
            if uf_name in services:
                services[uf_name].enabled = uf_state == "enabled"
            else:
                # Unit file exists but unit not loaded — include as stopped
                services[uf_name] = ServiceInfo(
                    name=uf_name,
                    state="inactive",
                    enabled=uf_state == "enabled",
                )

    return list(services.values())


def _parse_local_address(local: str) -> tuple[str, str]:
    """Parse a local address field from ss/netstat into (addr, port).

    Handles IPv4 (``0.0.0.0:22``), IPv6 (``[::]:22``, ``:::22``),
    and wildcard (``*:22``) formats.
    """
    # Bracket notation: [::1]:8080
    bracket_match = re.match(r'\[([^\]]+)\]:(\d+)$', local)
    if bracket_match:
        return bracket_match.group(1), bracket_match.group(2)

    # Triple-colon IPv6 shorthand: :::22
    triple_match = re.match(r'(:::?)(\d+)$', local)
    if triple_match:
        return "::", triple_match.group(2)

    # Standard addr:port (IPv4 or *:port)
    addr, _, port_str = local.rpartition(":")
    return addr or "0.0.0.0", port_str


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
        addr, port_str = _parse_local_address(local)
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
