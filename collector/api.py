"""FastAPI collector service for embedded target assessment.

Endpoints
---------
POST /assess                 — full config-driven assessment (all or by target name)
GET  /targets                — list configured targets from config file
POST /collect/linux/system   — system info, processes, services, ports
POST /collect/linux/security — hardening / security-posture checks
POST /collect/linux/hwcomms  — hardware communication interface enumeration
POST /report/render          — render an AssessmentResult to HTML / Markdown
GET  /health                 — liveness probe
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import contextmanager
from typing import Generator

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from collector.common.transport import (
    ConnectionFailed,
    Transport,
    TransportError,
    create_transport,
)
from collector.config import AppConfig, ConnectionConfig, load_config
from collector.linux.runner import (
    collect_hwcomms_domain,
    collect_security_domain,
    collect_service_map_domain,
    collect_system_domain,
    run_linux_assessment,
)
from collector.models import (
    AssessmentResult,
    HwCommsCollectRequest,
    HwCommsCollectResponse,
    RenderedReport,
    ReportRenderRequest,
    ReportRenderResponse,
    SecurityCollectRequest,
    SecurityCollectResponse,
    ServiceMapCollectRequest,
    ServiceMapCollectResponse,
    SystemCollectRequest,
    SystemCollectResponse,
    TargetConnectionRequest,
)
from report.generator import render_html, render_markdown

logger = logging.getLogger(__name__)

# Default request timeout in seconds (overridable via REQUEST_TIMEOUT env var).
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "120"))

# Load config from file (COLLECTOR_CONFIG env var or default path).
_config_path = os.environ.get("COLLECTOR_CONFIG", "config/config.yaml")
try:
    _app_config: AppConfig = load_config(_config_path)
    logger.info("Loaded config from %s (%d targets)", _config_path, len(_app_config.targets))
except FileNotFoundError:
    logger.warning("Config file %s not found — /assess and /targets will be unavailable", _config_path)
    _app_config = AppConfig()

app = FastAPI(
    title="Embedded Assessment Collector",
    version="0.3.0",
    description="REST API for embedded Linux target assessment — "
    "system inventory, security hardening, and hardware enumeration.",
)


# ---------------------------------------------------------------------------
# Middleware — request timeout
# ---------------------------------------------------------------------------

@app.middleware("http")
async def timeout_middleware(request: Request, call_next):
    """Cancel requests that exceed REQUEST_TIMEOUT seconds."""
    try:
        return await asyncio.wait_for(
            call_next(request),
            timeout=REQUEST_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.warning("Request timed out: %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=504,
            content={"detail": f"Request timed out after {REQUEST_TIMEOUT}s"},
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
    except TransportError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Transport error on {req.host}: {exc}",
        ) from exc
    finally:
        transport.close()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# GET /targets
# ---------------------------------------------------------------------------

class TargetSummary(BaseModel):
    name: str
    platform: str
    host: str
    port: int


@app.get(
    "/targets",
    response_model=list[TargetSummary],
    summary="List configured assessment targets",
    tags=["config"],
)
async def list_targets() -> list[TargetSummary]:
    """Return the list of targets defined in the config file."""
    return [
        TargetSummary(
            name=t.name,
            platform=t.platform,
            host=t.connection.host,
            port=t.connection.port,
        )
        for t in _app_config.targets
    ]


# ---------------------------------------------------------------------------
# POST /assess
# ---------------------------------------------------------------------------

class AssessRequest(BaseModel):
    """Request body for POST /assess."""
    target_name: str | None = None  # None = assess all configured targets


class AssessResponse(BaseModel):
    """Response from POST /assess."""
    results: list[AssessmentResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def _do_assess(target_name: str | None) -> AssessResponse:
    targets = _app_config.targets
    modules = _app_config.modules

    if not targets:
        raise HTTPException(
            status_code=404,
            detail="No targets configured — add targets to config/config.yaml",
        )

    if target_name:
        targets = [t for t in targets if t.name == target_name]
        if not targets:
            raise HTTPException(
                status_code=404,
                detail=f"Target '{target_name}' not found in config",
            )

    results: list[AssessmentResult] = []
    errors: list[str] = []

    for target in targets:
        try:
            result = run_linux_assessment(target, modules)
            results.append(result)
        except Exception as exc:
            errors.append(f"{target.name}: {exc}")

    return AssessResponse(results=results, errors=errors)


@app.post(
    "/assess",
    response_model=AssessResponse,
    summary="Run a full config-driven assessment",
    tags=["assess"],
)
async def assess(req: AssessRequest = AssessRequest()) -> AssessResponse:
    """Run all enabled collection modules against configured targets.

    Optionally provide ``target_name`` to assess a single target.
    Targets and module toggles are read from ``config/config.yaml``.
    """
    return await asyncio.to_thread(_do_assess, req.target_name)


# ---------------------------------------------------------------------------
# POST /collect/linux/system
# ---------------------------------------------------------------------------

def _do_collect_system(req: SystemCollectRequest) -> SystemCollectResponse:
    with _open_transport(req.target) as transport:
        return collect_system_domain(
            transport,
            req.target.host,
            processes=req.collect_processes,
            services=req.collect_services,
            ports=req.collect_ports,
        )


@app.post(
    "/collect/linux/system",
    response_model=SystemCollectResponse,
    summary="Collect system info, processes, services, and ports",
    tags=["collect"],
)
async def collect_linux_system(req: SystemCollectRequest) -> SystemCollectResponse:
    """Connect to a Linux target over SSH and collect system-level inventory.

    Gathers hostname, kernel, OS info, running processes, systemd services,
    and listening ports.  Each sub-collector runs independently — a failure
    in one does not block the others.
    """
    return await asyncio.to_thread(_do_collect_system, req)


# ---------------------------------------------------------------------------
# POST /collect/linux/security
# ---------------------------------------------------------------------------

def _do_collect_security(req: SecurityCollectRequest) -> SecurityCollectResponse:
    with _open_transport(req.target) as transport:
        return collect_security_domain(
            transport,
            req.target.host,
            check_ids=req.checks,
        )


@app.post(
    "/collect/linux/security",
    response_model=SecurityCollectResponse,
    summary="Run hardening and security-posture checks",
    tags=["collect"],
)
async def collect_linux_security(req: SecurityCollectRequest) -> SecurityCollectResponse:
    """Run non-intrusive hardening checks on a Linux target.

    Checks SSH config, firewall rules, SELinux mode, ASLR, core dump
    settings, and SUID binary counts.  Optionally filter to specific
    check IDs.  Returns per-check results plus a pass/fail/warn/info
    summary.
    """
    return await asyncio.to_thread(_do_collect_security, req)


# ---------------------------------------------------------------------------
# POST /collect/linux/hwcomms
# ---------------------------------------------------------------------------

def _do_collect_hwcomms(req: HwCommsCollectRequest) -> HwCommsCollectResponse:
    with _open_transport(req.target) as transport:
        return collect_hwcomms_domain(
            transport,
            req.target.host,
            interface_types=req.interface_types,
        )


@app.post(
    "/collect/linux/hwcomms",
    response_model=HwCommsCollectResponse,
    summary="Enumerate hardware communication interfaces",
    tags=["collect"],
)
async def collect_linux_hwcomms(req: HwCommsCollectRequest) -> HwCommsCollectResponse:
    """Enumerate UART, SPI, I2C, GPIO, and USB interfaces on a Linux target.

    Optionally filter to specific interface types.  All checks are read-only
    device enumeration — no bus interaction or intrusive probing.
    """
    return await asyncio.to_thread(_do_collect_hwcomms, req)


# ---------------------------------------------------------------------------
# POST /collect/linux/service-map
# ---------------------------------------------------------------------------

def _do_collect_service_map(req: ServiceMapCollectRequest) -> ServiceMapCollectResponse:
    with _open_transport(req.target) as transport:
        return collect_service_map_domain(transport, req.target.host)


@app.post(
    "/collect/linux/service-map",
    response_model=ServiceMapCollectResponse,
    summary="Map running services to their processes and ports",
    tags=["collect"],
)
async def collect_linux_service_map(
    req: ServiceMapCollectRequest,
) -> ServiceMapCollectResponse:
    """Map each systemd service to its main process (via MainPID) and any
    listening ports.  Provides a unified view of which process belongs to
    which service.
    """
    return await asyncio.to_thread(_do_collect_service_map, req)


# ---------------------------------------------------------------------------
# POST /report/render
# ---------------------------------------------------------------------------

@app.post(
    "/report/render",
    response_model=ReportRenderResponse,
    summary="Render an assessment result to HTML and/or Markdown",
    tags=["report"],
)
async def report_render(req: ReportRenderRequest) -> ReportRenderResponse:
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
