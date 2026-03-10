"""Map running systemd services to their main process and listening ports.

Uses ``systemctl show`` to obtain each service's MainPID, then correlates
with ``ps`` output for full process details and ``ss`` output for listening
ports.  All operations are read-only.
"""

from __future__ import annotations

import logging
import re
import shlex

from collector.common.transport import Transport
from collector.linux.process_inventory import collect_processes
from collector.linux.service_port_inventory import collect_open_ports, collect_services
from collector.models import OpenPort, ProcessInfo, ServiceInfo, ServiceProcessMap

logger = logging.getLogger(__name__)


def collect_service_process_map(transport: Transport) -> list[ServiceProcessMap]:
    """Map systemd services to their running processes and listening ports."""
    # 1. Reuse collect_services() for runtime state + enablement (no duplication)
    svc_list: list[ServiceInfo] = collect_services(transport)
    if not svc_list:
        return []

    # 2. Batch-query MainPID for all services
    service_names = [s.name for s in svc_list]
    pid_map = _get_service_pids(transport, service_names)

    # 3. Collect full process list for cross-reference
    all_procs = collect_processes(transport)
    proc_by_pid: dict[int, ProcessInfo] = {p.pid: p for p in all_procs}

    # 4. Collect open ports for matching
    all_ports = collect_open_ports(transport)

    # 5. Build mappings
    mappings: list[ServiceProcessMap] = []
    for svc in svc_list:
        main_pid = pid_map.get(svc.name, 0)
        proc = proc_by_pid.get(main_pid) if main_pid > 0 else None

        # Match ports: look for ports whose process name matches the service
        matched_ports = _match_ports(all_ports, main_pid, proc, svc.name)

        mappings.append(ServiceProcessMap(
            service_name=svc.name,
            service_state=svc.state,
            enabled=svc.enabled,
            main_pid=main_pid,
            process=proc,
            listening_ports=matched_ports,
        ))

    return mappings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_service_pids(
    transport: Transport, service_names: list[str]
) -> dict[str, int]:
    """Batch-query MainPID for services via ``systemctl show``.

    Runs a single ``systemctl show`` command for all services to minimise
    round-trips, parsing ``Id`` and ``MainPID`` properties from the output.
    """
    if not service_names:
        return {}

    svc_args = " ".join(shlex.quote(f"{n}.service") for n in service_names)
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
                logger.debug("Non-integer MainPID for %s: %r", current_id, line[8:])

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
