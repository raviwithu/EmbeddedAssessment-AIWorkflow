"""Normalize and enrich assessment results before report generation."""

from __future__ import annotations

import json
from pathlib import Path

from collector.models import AssessmentResult


def to_json(result: AssessmentResult) -> str:
    """Serialize an AssessmentResult to pretty-printed JSON."""
    return result.model_dump_json(indent=2)


def save_json(result: AssessmentResult, output_dir: str | Path) -> Path:
    """Write assessment result as a JSON file and return the path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    filename = f"{result.target_name}_{result.timestamp:%Y%m%d_%H%M%S}.json"
    path = out / filename
    path.write_text(to_json(result))
    return path


def load_json(path: str | Path) -> AssessmentResult:
    """Load an AssessmentResult from a JSON file."""
    raw = Path(path).read_text()
    return AssessmentResult.model_validate_json(raw)
