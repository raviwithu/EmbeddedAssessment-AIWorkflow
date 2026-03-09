"""Placeholder for Android target assessment runner.

Android collection will mirror the Linux runner structure but use ADB transport
and Android-specific commands (pm list packages, getprop, dumpsys, etc.).
"""

from __future__ import annotations

from collector.config import ModulesConfig, TargetConfig
from collector.models import AssessmentResult


def run_android_assessment(
    target: TargetConfig, modules: ModulesConfig
) -> AssessmentResult:
    """Run assessment against an Android target via ADB."""
    raise NotImplementedError(
        "Android assessment is not yet implemented. "
        "See AGENTS.md for the planned module structure."
    )
