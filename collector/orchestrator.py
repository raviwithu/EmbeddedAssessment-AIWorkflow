"""Full Linux assessment orchestrator.

Connects to a target, detects if it is Linux, then runs every available
collector and stores results in a per-host output folder.

Usage
-----
# Ad-hoc via CLI args
python -m collector.orchestrator --host 192.168.1.100 --username root --auth key

# From config file (all targets)
python -m collector.orchestrator --config config/config.yaml

# Single target from config
python -m collector.orchestrator --config config/config.yaml --target my-device

# Custom output directory
python -m collector.orchestrator --host 10.0.0.5 --output ./my-output
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from collector.common.sanitize import sanitize_hostname as _sanitize_hostname
from collector.common.transport import ConnectionFailed, Transport, TransportError, create_transport
from collector.config import ConnectionConfig, load_config
from collector.linux.baseline import collect_baseline
from collector.linux.forensic_storage import save_snapshot
from collector.linux.hardening_checks import run_hardening_checks
from collector.linux.hardware_comm import collect_hardware_interfaces
from collector.linux.phase0_environment import collect_phase0
from collector.linux.phase1_memory import collect_phase1
from collector.linux.process_inventory import collect_processes
from collector.linux.service_port_inventory import collect_open_ports, collect_services
from collector.linux.service_process_map import collect_service_process_map
from collector.linux.system_info import collect_system_info
from collector.models import AssessmentResult
from report.generator import render_html, render_markdown

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Linux detection
# ---------------------------------------------------------------------------

def is_linux(transport: Transport) -> bool:
    """Return True if the remote host is running Linux."""
    result = transport.run("uname -s")
    os_name = result.stdout.strip().lower()
    return os_name == "linux"


# ---------------------------------------------------------------------------
# Core orchestrator
# ---------------------------------------------------------------------------

def run_full_assessment(
    transport: Transport,
    output_dir: str = "./output",
) -> dict:
    """Detect Linux, run all collectors, save to per-host folder.

    Args:
        transport: An already-connected Transport instance.
        output_dir: Root output directory.  Per-host folders are created under it.

    Returns:
        A summary dict with hostname, collectors run, artifact counts, and errors.
    """
    summary: dict = {
        "hostname": "",
        "platform": "",
        "collectors_run": [],
        "collectors_failed": [],
        "artifact_counts": {},
        "output_path": "",
        "errors": [],
    }

    # Step 1 — Detect platform
    if not is_linux(transport):
        os_result = transport.run("uname -s")
        detected = os_result.stdout.strip() or "unknown"
        summary["platform"] = detected
        summary["errors"].append(
            f"Target is not Linux (detected: {detected}). Skipping all Linux collectors."
        )
        logger.warning("Target is not Linux (detected: %s). Skipping.", detected)
        return summary

    summary["platform"] = "linux"

    # Step 2 — Get hostname for folder naming
    hostname_result = transport.run("hostname")
    hostname = hostname_result.stdout.strip() or "unknown"
    summary["hostname"] = hostname

    host_dir = Path(output_dir) / _sanitize_hostname(hostname)
    host_dir.mkdir(parents=True, exist_ok=True)
    summary["output_path"] = str(host_dir)

    # Step 3 — Build AssessmentResult with all inventory collectors
    result = AssessmentResult(target_name=hostname, platform="linux")

    # System info
    _run_collector(
        summary, "system_info",
        lambda: setattr(result, "system_info", collect_system_info(transport)),
    )

    # Processes
    _run_collector(
        summary, "process_inventory",
        lambda: setattr(result, "processes", collect_processes(transport)),
    )

    # Services
    _run_collector(
        summary, "service_port_inventory",
        lambda: (
            setattr(result, "services", collect_services(transport)),
            setattr(result, "open_ports", collect_open_ports(transport)),
        ),
    )

    # Service-process map
    _run_collector(
        summary, "service_process_map",
        lambda: setattr(result, "service_process_map", collect_service_process_map(transport)),
    )

    # Hardening checks
    _run_collector(
        summary, "hardening_checks",
        lambda: setattr(result, "hardening", run_hardening_checks(transport)),
    )

    # Hardware interfaces
    _run_collector(
        summary, "hardware_comm",
        lambda: setattr(result, "hardware_interfaces", collect_hardware_interfaces(transport)),
    )

    # Save assessment result as JSON
    assessment_path = host_dir / "assessment_result.json"
    assessment_path.write_text(result.model_dump_json(indent=2))
    logger.info("Saved assessment result to %s", assessment_path)

    # Generate reports
    try:
        html_path = host_dir / "report.html"
        html_path.write_text(render_html(result))
        md_path = host_dir / "report.md"
        md_path.write_text(render_markdown(result))
        logger.info("Saved reports to %s", host_dir)
    except Exception as exc:
        summary["errors"].append(f"report_generation: {exc}")
        logger.error("Report generation failed: %s", exc)

    # Step 4 — Forensic playbook collectors (saved via forensic_storage)
    forensic_output = str(host_dir)

    # Baseline
    def _do_baseline():
        snap = collect_baseline(transport)
        save_snapshot(snap, forensic_output, "baseline")
        summary["artifact_counts"]["baseline"] = len(snap.artifacts)

    _run_collector(summary, "baseline", _do_baseline)

    # Phase 0
    def _do_phase0():
        snap = collect_phase0(transport)
        save_snapshot(snap, forensic_output, "phase0")
        summary["artifact_counts"]["phase0"] = len(snap.artifacts)

    _run_collector(summary, "phase0", _do_phase0)

    # Phase 1
    def _do_phase1():
        snap = collect_phase1(transport)
        save_snapshot(snap, forensic_output, "phase1")
        summary["artifact_counts"]["phase1"] = len(snap.artifacts)

    _run_collector(summary, "phase1", _do_phase1)

    return summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_collector(summary: dict, name: str, fn) -> None:
    """Run a collector function, catching errors so others can continue."""
    try:
        fn()
        summary["collectors_run"].append(name)
        logger.info("Collector '%s' completed", name)
    except Exception as exc:
        summary["collectors_failed"].append(name)
        summary["errors"].append(f"{name}: {exc}")
        logger.error("Collector '%s' failed: %s", name, exc)




# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="collector.orchestrator",
        description="Run a full Linux assessment against one or more targets.",
    )

    # Config file mode
    parser.add_argument(
        "--config", "-c",
        help="Path to config YAML file (overrides --host/--username/etc.)",
    )
    parser.add_argument(
        "--target", "-t",
        help="Target name from config file (default: run all targets)",
    )

    # Ad-hoc mode
    parser.add_argument("--host", help="Target hostname or IP")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--username", "-u", default="root", help="SSH username (default: root)")
    parser.add_argument(
        "--auth", choices=["key", "password"], default="key",
        help="Auth method (default: key)",
    )
    parser.add_argument("--key-path", default="~/.ssh/id_ed25519", help="SSH key path")
    parser.add_argument("--password", default="", help="SSH password (prefer env SSH_PASSWORD)")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds")

    # Output
    parser.add_argument(
        "--output", "-o", default="./output",
        help="Output directory (default: ./output)",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    # Determine targets
    targets: list[ConnectionConfig] = []

    if args.config:
        app_config = load_config(args.config)
        for t in app_config.targets:
            if args.target and t.name != args.target:
                continue
            targets.append(t.connection)
        if not targets:
            if args.target:
                logger.error("Target '%s' not found in config", args.target)
                sys.exit(1)
            logger.error("No targets in config file")
            sys.exit(1)
    elif args.host:
        targets.append(ConnectionConfig(
            host=args.host,
            port=args.port,
            username=args.username,
            auth=args.auth,
            key_path=args.key_path,
            password=args.password,
            timeout_seconds=args.timeout,
        ))
    else:
        parser.print_help()
        sys.exit(1)

    # Run assessment for each target
    all_summaries = []
    for conn in targets:
        print(f"\n{'='*60}")
        print(f"  Assessing {conn.host}:{conn.port}")
        print(f"{'='*60}")

        transport = create_transport(conn)
        try:
            transport.connect()
        except ConnectionFailed as exc:
            msg = f"Cannot connect to {conn.host}:{conn.port}: {exc}"
            logger.error(msg)
            all_summaries.append({"hostname": conn.host, "errors": [msg]})
            continue

        try:
            summary = run_full_assessment(transport, output_dir=args.output)
            all_summaries.append(summary)
            _print_summary(summary)
        except Exception as exc:
            msg = f"Assessment failed for {conn.host}: {exc}"
            logger.error(msg)
            all_summaries.append({
                "hostname": conn.host,
                "platform": "unknown",
                "collectors_run": [],
                "collectors_failed": [],
                "artifact_counts": {},
                "output_path": "",
                "errors": [msg],
            })
        finally:
            transport.close()

    # Final status
    total_ok = sum(1 for s in all_summaries if not s.get("errors"))
    total_err = sum(1 for s in all_summaries if s.get("errors"))
    print(f"\nDone — {total_ok} succeeded, {total_err} had errors out of {len(all_summaries)} target(s).")


def _print_summary(summary: dict) -> None:
    """Print a human-readable summary to stdout."""
    print(f"\n  Host:     {summary.get('hostname', 'unknown')}")
    print(f"  Platform: {summary.get('platform', 'unknown')}")
    print(f"  Output:   {summary.get('output_path', 'n/a')}")

    run = summary.get("collectors_run", [])
    failed = summary.get("collectors_failed", [])
    if run:
        print(f"  Collectors OK:     {', '.join(run)}")
    if failed:
        print(f"  Collectors FAILED: {', '.join(failed)}")

    counts = summary.get("artifact_counts", {})
    if counts:
        parts = [f"{k}={v}" for k, v in counts.items()]
        print(f"  Artifacts: {', '.join(parts)}")

    errors = summary.get("errors", [])
    if errors:
        print(f"  Errors ({len(errors)}):")
        for e in errors:
            print(f"    - {e}")


if __name__ == "__main__":
    main()
