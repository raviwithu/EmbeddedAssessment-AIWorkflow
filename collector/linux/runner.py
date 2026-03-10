"""Orchestrate Linux collection modules — full or per-domain.

Each ``collect_*_domain`` function accepts a connected Transport and returns a
typed response.  ``run_linux_assessment`` still works for callers that want
everything in one shot.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone

from collector.common.transport import Transport, TransportError, create_transport
from collector.config import ModulesConfig, TargetConfig
from collector.linux.hardening_checks import run_hardening_checks
from collector.linux.hardware_comm import collect_hardware_interfaces
from collector.linux.process_inventory import collect_processes
from collector.linux.service_port_inventory import collect_open_ports, collect_services
from collector.linux.system_info import collect_system_info
from collector.models import (
    AssessmentResult,
    HardeningCheck,
    HardwareInterface,
    HwCommsCollectResponse,
    OpenPort,
    ProcessInfo,
    SecurityCollectResponse,
    ServiceInfo,
    SystemCollectResponse,
    SystemInfo,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-domain collectors (used by the API endpoints)
# ---------------------------------------------------------------------------

def collect_system_domain(
    transport: Transport,
    host: str,
    *,
    processes: bool = True,
    services: bool = True,
    ports: bool = True,
) -> SystemCollectResponse:
    """Collect system info, processes, services, and ports."""
    errors: list[str] = []
    sysinfo = SystemInfo()
    proc_list: list[ProcessInfo] = []
    svc_list: list[ServiceInfo] = []
    port_list: list[OpenPort] = []

    try:
        sysinfo = collect_system_info(transport)
    except TransportError as exc:
        errors.append(f"system_info: {exc}")

    if processes:
        try:
            proc_list = collect_processes(transport)
        except TransportError as exc:
            errors.append(f"processes: {exc}")

    if services:
        try:
            svc_list = collect_services(transport)
        except TransportError as exc:
            errors.append(f"services: {exc}")

    if ports:
        try:
            port_list = collect_open_ports(transport)
        except TransportError as exc:
            errors.append(f"open_ports: {exc}")

    return SystemCollectResponse(
        target_host=host,
        timestamp=datetime.now(timezone.utc),
        system_info=sysinfo,
        processes=proc_list,
        services=svc_list,
        open_ports=port_list,
        errors=errors,
    )


def collect_security_domain(
    transport: Transport,
    host: str,
    *,
    check_ids: list[str] | None = None,
) -> SecurityCollectResponse:
    """Run hardening checks and return results with a pass/fail summary."""
    errors: list[str] = []
    checks: list[HardeningCheck] = []

    try:
        checks = run_hardening_checks(transport)
    except TransportError as exc:
        errors.append(f"hardening: {exc}")

    if check_ids:
        allowed = set(check_ids)
        checks = [c for c in checks if c.check_id in allowed]

    summary = dict(Counter(c.status for c in checks))

    return SecurityCollectResponse(
        target_host=host,
        timestamp=datetime.now(timezone.utc),
        hardening=checks,
        summary=summary,
        errors=errors,
    )


def collect_hwcomms_domain(
    transport: Transport,
    host: str,
    *,
    interface_types: list[str] | None = None,
) -> HwCommsCollectResponse:
    """Enumerate hardware communication interfaces."""
    errors: list[str] = []
    interfaces: list[HardwareInterface] = []

    try:
        interfaces = collect_hardware_interfaces(transport)
    except TransportError as exc:
        errors.append(f"hardware: {exc}")

    if interface_types:
        allowed = set(interface_types)
        interfaces = [i for i in interfaces if i.type in allowed]

    return HwCommsCollectResponse(
        target_host=host,
        timestamp=datetime.now(timezone.utc),
        hardware_interfaces=interfaces,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Full assessment (config-driven, used by legacy /assess endpoint)
# ---------------------------------------------------------------------------

def run_linux_assessment(
    target: TargetConfig, modules: ModulesConfig
) -> AssessmentResult:
    """Connect to a Linux target and run all enabled collection modules."""
    result = AssessmentResult(target_name=target.name, platform=target.platform)
    transport: Transport = create_transport(target.connection)

    try:
        transport.connect()

        result.system_info = collect_system_info(transport)

        if modules.process_inventory.enabled:
            result.processes = collect_processes(transport)
            logger.info("Collected %d processes", len(result.processes))

        if modules.service_port_inventory.enabled:
            result.services = collect_services(transport)
            result.open_ports = collect_open_ports(transport)
            logger.info(
                "Collected %d services, %d open ports",
                len(result.services),
                len(result.open_ports),
            )

        if modules.hardening_checks.enabled:
            result.hardening = run_hardening_checks(transport)
            logger.info("Ran %d hardening checks", len(result.hardening))

        if modules.hardware_comm.enabled:
            result.hardware_interfaces = collect_hardware_interfaces(transport)
            logger.info("Found %d hardware interfaces", len(result.hardware_interfaces))

    except Exception as exc:
        logger.exception("Assessment failed for %s", target.name)
        result.errors.append(str(exc))
    finally:
        transport.close()

    return result
