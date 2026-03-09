"""FastAPI collector service for embedded target assessment.

Endpoints
---------
POST /collect/linux/system   — system info, processes, services, ports
POST /collect/linux/security — hardening / security-posture checks
POST /collect/linux/hwcomms  — hardware communication interface enumeration
POST /report/render          — render an AssessmentResult to HTML / Markdown
GET  /health                 — liveness probe
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Generator

import uvicorn
from fastapi import FastAPI, HTTPException

from collector.common.transport import (
    ConnectionFailed,
    Transport,
    TransportError,
    create_transport,
)
from collector.config import ConnectionConfig, load_config
from collector.linux.runner import (
    collect_hwcomms_domain,
    collect_security_domain,
    collect_system_domain,
)
from collector.models import (
    HwCommsCollectRequest,
    HwCommsCollectResponse,
    RenderedReport,
    ReportRenderRequest,
    ReportRenderResponse,
    SecurityCollectRequest,
    SecurityCollectResponse,
    SystemCollectRequest,
    SystemCollectResponse,
    TargetConnectionRequest,
)
from report.generator import render_html, render_markdown

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Embedded Assessment Collector",
    version="0.2.0",
    description="REST API for embedded Linux target assessment — "
    "system inventory, security hardening, and hardware enumeration.",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_connection_config(req: TargetConnectionRequest) -> ConnectionConfig:
    """Convert an API request's connection block to the internal config model."""
    return ConnectionConfig(
        method="ssh",
        host=req.host,
        port=req.port,
        username=req.username,
        auth=req.auth,
        key_path=req.key_path,
        password=req.password,
        timeout_seconds=req.timeout_seconds,
    )


@contextmanager
def _open_transport(req: TargetConnectionRequest) -> Generator[Transport, None, None]:
    """Open an SSH transport from request params; handles errors as HTTP 502."""
    cfg = _to_connection_config(req)
    transport = create_transport(cfg)
    try:
        transport.connect()
    except ConnectionFailed as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Cannot connect to {req.host}:{req.port}: {exc}",
        ) from exc
    try:
        yield transport
    finally:
        transport.close()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# POST /collect/linux/system
# ---------------------------------------------------------------------------

@app.post(
    "/collect/linux/system",
    response_model=SystemCollectResponse,
    summary="Collect system info, processes, services, and ports",
    tags=["collect"],
)
def collect_linux_system(req: SystemCollectRequest) -> SystemCollectResponse:
    """Connect to a Linux target over SSH and collect system-level inventory.

    Gathers hostname, kernel, OS info, running processes, systemd services,
    and listening ports.  Each sub-collector runs independently — a failure
    in one does not block the others.
    """
    with _open_transport(req.target) as transport:
        return collect_system_domain(
            transport,
            req.target.host,
            processes=req.collect_processes,
            services=req.collect_services,
            ports=req.collect_ports,
        )


# ---------------------------------------------------------------------------
# POST /collect/linux/security
# ---------------------------------------------------------------------------

@app.post(
    "/collect/linux/security",
    response_model=SecurityCollectResponse,
    summary="Run hardening and security-posture checks",
    tags=["collect"],
)
def collect_linux_security(req: SecurityCollectRequest) -> SecurityCollectResponse:
    """Run non-intrusive hardening checks on a Linux target.

    Checks SSH config, firewall rules, SELinux mode, ASLR, core dump
    settings, and SUID binary counts.  Optionally filter to specific
    check IDs.  Returns per-check results plus a pass/fail/warn/info
    summary.
    """
    with _open_transport(req.target) as transport:
        return collect_security_domain(
            transport,
            req.target.host,
            check_ids=req.checks,
        )


# ---------------------------------------------------------------------------
# POST /collect/linux/hwcomms
# ---------------------------------------------------------------------------

@app.post(
    "/collect/linux/hwcomms",
    response_model=HwCommsCollectResponse,
    summary="Enumerate hardware communication interfaces",
    tags=["collect"],
)
def collect_linux_hwcomms(req: HwCommsCollectRequest) -> HwCommsCollectResponse:
    """Enumerate UART, SPI, I2C, GPIO, and USB interfaces on a Linux target.

    Optionally filter to specific interface types.  All checks are read-only
    device enumeration — no bus interaction or intrusive probing.
    """
    with _open_transport(req.target) as transport:
        return collect_hwcomms_domain(
            transport,
            req.target.host,
            interface_types=req.interface_types,
        )


# ---------------------------------------------------------------------------
# POST /report/render
# ---------------------------------------------------------------------------

@app.post(
    "/report/render",
    response_model=ReportRenderResponse,
    summary="Render an assessment result to HTML and/or Markdown",
    tags=["report"],
)
def report_render(req: ReportRenderRequest) -> ReportRenderResponse:
    """Accept a full AssessmentResult and render it into the requested
    report formats.  Returns the rendered content inline (no file I/O).
    """
    reports: list[RenderedReport] = []

    for fmt in req.formats:
        if fmt.value == "html":
            reports.append(RenderedReport(format="html", content=render_html(req.result)))
        elif fmt.value == "markdown":
            reports.append(RenderedReport(format="markdown", content=render_markdown(req.result)))

    return ReportRenderResponse(
        target_name=req.result.target_name,
        reports=reports,
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log_level = os.environ.get("LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
    uvicorn.run(app, host="0.0.0.0", port=8000)
