"""Map running systemd services to their main process and listening ports.

Uses ``systemctl show`` to obtain each service's MainPID, then correlates
with ``ps`` output for full process details and ``ss`` output for listening
ports.  All operations are read-only.
"""

from __future__ import annotations

import logging
import re

from collector.common.transport import Transport
from collector.linux.process_inventory import collect_processes
from collector.linux.service_port_inventory import collect_open_ports
from collector.models import OpenPort, ProcessInfo, ServiceProcessMap

logger = logging.getLogger(__name__)


def collect_service_process_map(transport: Transport) -> list[ServiceProcessMap]:
    """Map systemd services to their running processes and listening ports."""
    # 1. Gather services with runtime state
    services = _get_services(transport)
    if not services:
        return []

    # 2. Gather enabled/disabled status
    enabled_set = _get_enabled_services(transport)

    # 3. Batch-query MainPID for all services
    service_names = [name for name, _ in services]
    pid_map = _get_service_pids(transport, service_names)

    # 4. Collect full process list for cross-reference
    all_procs = collect_processes(transport)
    proc_by_pid: dict[int, ProcessInfo] = {p.pid: p for p in all_procs}

    # 5. Collect open ports for matching
    all_ports = collect_open_ports(transport)

    # 6. Build mappings
    mappings: list[ServiceProcessMap] = []
    for name, state in services:
        main_pid = pid_map.get(name, 0)
        proc = proc_by_pid.get(main_pid) if main_pid > 0 else None

        # Match ports: look for ports whose process name matches the service
        matched_ports = _match_ports(all_ports, main_pid, proc, name)

        mappings.append(ServiceProcessMap(
            service_name=name,
            service_state=state,
            enabled=name in enabled_set,
            main_pid=main_pid,
            process=proc,
            listening_ports=matched_ports,
        ))

    return mappings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_services(transport: Transport) -> list[tuple[str, str]]:
    """Return (name, active_state) tuples from systemctl list-units."""
    r = transport.run(
        "systemctl list-units --type=service --all --no-pager --no-legend"
    )
    if r.exit_code != 0:
        logger.warning("systemctl list-units failed: %s", r.stderr)
        return []

    services: list[tuple[str, str]] = []
    for line in r.stdout.strip().splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        name = parts[0].removesuffix(".service")
        active = parts[2]  # active / inactive
        services.append((name, active))
    return services


def _get_enabled_services(transport: Transport) -> set[str]:
    """Return set of service names that are enabled at boot."""
    r = transport.run(
        "systemctl list-unit-files --type=service --no-pager --no-legend"
    )
    if r.exit_code != 0:
        return set()

    enabled: set[str] = set()
    for line in r.stdout.strip().splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 2 and parts[1] == "enabled":
            enabled.add(parts[0].removesuffix(".service"))
    return enabled


def _get_service_pids(
    transport: Transport, service_names: list[str]
) -> dict[str, int]:
    """Batch-query MainPID for services via ``systemctl show``.

    Runs a single ``systemctl show`` command for all services to minimise
    round-trips, parsing ``Id`` and ``MainPID`` properties from the output.
    """
    if not service_names:
        return {}

    svc_args = " ".join(f"{n}.service" for n in service_names)
    r = transport.run(
        f"systemctl show {svc_args} --property=Id,MainPID --no-pager"
    )
    if r.exit_code != 0:
        logger.warning("systemctl show failed: %s", r.stderr)
        return {}

    pid_map: dict[str, int] = {}
    current_id: str | None = None

    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            current_id = None
            continue
        if line.startswith("Id="):
            current_id = line[3:].removesuffix(".service")
        elif line.startswith("MainPID=") and current_id is not None:
            try:
                pid_map[current_id] = int(line[8:])
            except ValueError:
                pass

    return pid_map


def _match_ports(
    all_ports: list[OpenPort],
    main_pid: int,
    proc: ProcessInfo | None,
    service_name: str,
) -> list[OpenPort]:
    """Find listening ports that belong to a service.

    Matches by:
    1. The ``process`` field in ``ss`` output containing the service name
    2. The process command basename matching the service name
    """
    if not all_ports:
        return []

    matched: list[OpenPort] = []
    # Extract the executable basename from the process command
    cmd_base = ""
    if proc:
        cmd_base = proc.command.split()[0].rsplit("/", 1)[-1] if proc.command else ""

    for port in all_ports:
        # ss process field often contains the process name
        if port.process and (
            port.process == service_name
            or port.process == cmd_base
            or service_name in port.process
        ):
            matched.append(port)

    return matched
