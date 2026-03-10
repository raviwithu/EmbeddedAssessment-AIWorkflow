"""Per-host forensic artifact storage.

Stores collected artifacts in:
    <output_dir>/<hostname>/baseline/
    <output_dir>/<hostname>/phase0/
    <output_dir>/<hostname>/phase1/

If data already exists for a host, files are updated in place.
A manifest.json tracks all collection runs.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from collector.models import BaselineSnapshot, ForensicArtifact, Phase0Snapshot, Phase1Snapshot

logger = logging.getLogger(__name__)


def save_snapshot(
    snapshot: BaselineSnapshot | Phase0Snapshot | Phase1Snapshot,
    output_dir: str | Path,
    phase: str,
) -> Path:
    """Save a forensic snapshot to the per-host directory.

    Returns the directory path where artifacts were stored.
    """
    host_dir = Path(output_dir) / _sanitize(snapshot.hostname) / phase
    host_dir.mkdir(parents=True, exist_ok=True)

    # Write each artifact as a separate file
    for artifact in snapshot.artifacts:
        artifact_path = host_dir / artifact.filename
        artifact_path.write_text(artifact.content)

    # Update manifest
    _update_manifest(host_dir, snapshot)

    logger.info(
        "Saved %d artifacts to %s", len(snapshot.artifacts), host_dir,
    )
    return host_dir


def load_manifest(host_dir: str | Path) -> dict:
    """Load the manifest.json from a host directory."""
    manifest_path = Path(host_dir) / "manifest.json"
    if manifest_path.exists():
        return json.loads(manifest_path.read_text())
    return {}


def _update_manifest(
    host_dir: Path,
    snapshot: BaselineSnapshot | Phase0Snapshot | Phase1Snapshot,
) -> None:
    """Update manifest.json with collection metadata."""
    manifest_path = host_dir / "manifest.json"

    manifest = {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())

    runs = manifest.get("runs", [])
    runs.append({
        "timestamp": snapshot.timestamp.isoformat(),
        "hostname": snapshot.hostname,
        "artifact_count": len(snapshot.artifacts),
        "artifacts": [a.filename for a in snapshot.artifacts],
        "errors": snapshot.errors,
    })

    manifest["hostname"] = snapshot.hostname
    manifest["last_updated"] = snapshot.timestamp.isoformat()
    manifest["runs"] = runs

    manifest_path.write_text(json.dumps(manifest, indent=2))


def _sanitize(hostname: str) -> str:
    """Sanitize hostname for use as a directory name."""
    name = hostname.replace("\x00", "").replace("/", "_").replace("\\", "_").replace("..", "_").strip()
    return name[:255] or "unknown"
