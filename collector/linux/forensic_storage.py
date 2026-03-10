"""Per-host forensic artifact storage.

Stores collected artifacts in:
    <output_dir>/<hostname>/baseline/
    <output_dir>/<hostname>/phase0/
    <output_dir>/<hostname>/phase1/

If data already exists for a host, files are updated in place.
A manifest.json tracks all collection runs.
"""

from __future__ import annotations

import fcntl
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from collector.common.sanitize import sanitize_hostname as _sanitize
from collector.models import BaselineSnapshot, ForensicArtifact, Phase0Snapshot, Phase1Snapshot

logger = logging.getLogger(__name__)

# Only allow safe characters in artifact filenames.
_SAFE_FILENAME = re.compile(r"[^a-zA-Z0-9._-]")


def _sanitize_filename(filename: str) -> str:
    """Strip path separators and dangerous sequences from artifact filenames."""
    # Remove any directory components
    name = filename.replace("/", "_").replace("\\", "_").replace("\x00", "")
    name = name.replace("..", "_")
    name = _SAFE_FILENAME.sub("_", name)
    name = name.strip("._")
    return name[:255] or "artifact"


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

    # Write each artifact as a separate file (with sanitized filenames)
    for artifact in snapshot.artifacts:
        safe_name = _sanitize_filename(artifact.filename)
        artifact_path = host_dir / safe_name
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
        try:
            return json.loads(manifest_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Corrupted manifest at %s: %s", manifest_path, exc)
    return {}


def _update_manifest(
    host_dir: Path,
    snapshot: BaselineSnapshot | Phase0Snapshot | Phase1Snapshot,
) -> None:
    """Update manifest.json with collection metadata.

    Uses file locking to prevent race conditions from concurrent writes.
    """
    manifest_path = host_dir / "manifest.json"

    # Open for read+write (create if missing)
    fd = manifest_path.open("a+")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)

        fd.seek(0)
        content = fd.read()
        try:
            manifest = json.loads(content) if content.strip() else {}
        except json.JSONDecodeError:
            logger.warning("Corrupted manifest at %s — resetting", manifest_path)
            manifest = {}

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

        fd.seek(0)
        fd.truncate()
        fd.write(json.dumps(manifest, indent=2))
        fd.flush()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()
