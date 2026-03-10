"""Basic hardening / security-posture checks for Linux targets.

These checks are non-intrusive — read-only commands and file reads only.
"""

from __future__ import annotations

import logging
import re

from collector.common.transport import Transport, TransportError
from collector.models import HardeningCheck

_SAFE_SETTING = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

# SUID binaries above this count trigger a warning.
SUID_WARN_THRESHOLD = 15

logger = logging.getLogger(__name__)


def _check(
    check_id: str, category: str, description: str, status: str, detail: str = ""
) -> HardeningCheck:
    return HardeningCheck(
        check_id=check_id,
        category=category,
        description=description,
        status=status,
        detail=detail,
    )


def run_hardening_checks(transport: Transport) -> list[HardeningCheck]:
    """Execute all hardening checks and return results.

    Each check runs independently — a failure in one does not prevent the
    others from executing.  Transport errors are caught and recorded as
    ``warn`` results rather than propagating.
    """
    _ALL_CHECKS = [
        _check_root_login,
        _check_password_auth,
        _check_firewall,
        _check_selinux,
        _check_aslr,
        _check_core_dumps,
        _check_suid_files,
    ]

    checks: list[HardeningCheck] = []
    for fn in _ALL_CHECKS:
        try:
            checks.append(fn(transport))
        except (TransportError, ValueError, OSError) as exc:
            # Derive a check_id from the function name (e.g. _check_firewall -> firewall)
            name = fn.__name__.removeprefix("_check_")
            logger.warning("Hardening check '%s' failed: %s", name, exc)
            checks.append(_check(
                f"ERR-{name}", "error", f"Check '{name}' could not run",
                "warn", str(exc),
            ))
    return checks


def _grep_sshd_setting(t: Transport, setting: str) -> str:
    """Search sshd_config and drop-in configs for a setting.

    Checks both /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf.
    Returns the last match (which is the effective value), or "NOTFOUND".
    """
    if not _SAFE_SETTING.match(setting):
        raise ValueError(f"Invalid sshd setting name: {setting!r}")
    cmd = (
        f"grep -hi '^{setting}' "
        "/etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf "
        "2>/dev/null | tail -1"
    )
    r = t.run(cmd)
    value = r.stdout.strip()
    return value if value else "NOTFOUND"


def _check_root_login(t: Transport) -> HardeningCheck:
    value = _grep_sshd_setting(t, "PermitRootLogin")
    if value == "NOTFOUND":
        return _check("H-001", "SSH", "PermitRootLogin setting", "warn", "sshd_config not found")
    if "no" in value.lower():
        return _check("H-001", "SSH", "PermitRootLogin setting", "pass", value)
    return _check("H-001", "SSH", "PermitRootLogin setting", "fail", value)


def _check_password_auth(t: Transport) -> HardeningCheck:
    value = _grep_sshd_setting(t, "PasswordAuthentication")
    if value == "NOTFOUND":
        return _check("H-002", "SSH", "PasswordAuthentication setting", "warn", "Not found")
    if "no" in value.lower():
        return _check("H-002", "SSH", "PasswordAuthentication setting", "pass", value)
    return _check("H-002", "SSH", "PasswordAuthentication setting", "fail", value)


def _check_firewall(t: Transport) -> HardeningCheck:
    r = t.run("iptables -L -n 2>/dev/null | head -20 || echo NOTFOUND")
    if "NOTFOUND" in r.stdout or r.exit_code != 0:
        return _check("H-003", "Firewall", "iptables rules present", "warn", "Cannot read iptables")
    lines = [l for l in r.stdout.strip().splitlines() if l and not l.startswith("Chain") and not l.startswith("target")]
    if len(lines) == 0:
        return _check("H-003", "Firewall", "iptables rules present", "fail", "No rules configured")
    return _check("H-003", "Firewall", "iptables rules present", "pass", f"{len(lines)} rules found")


def _check_selinux(t: Transport) -> HardeningCheck:
    r = t.run("getenforce 2>/dev/null || echo NOTFOUND")
    value = r.stdout.strip()
    if "Enforcing" in value:
        return _check("H-004", "MAC", "SELinux mode", "pass", value)
    if "Permissive" in value:
        return _check("H-004", "MAC", "SELinux mode", "warn", value)
    return _check("H-004", "MAC", "SELinux mode", "info", value)


def _check_aslr(t: Transport) -> HardeningCheck:
    r = t.run("cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo NOTFOUND")
    value = r.stdout.strip()
    if value == "2":
        return _check("H-005", "Kernel", "ASLR enabled", "pass", f"Value: {value}")
    if value == "1":
        return _check("H-005", "Kernel", "ASLR enabled", "warn", f"Partial ASLR: {value}")
    return _check("H-005", "Kernel", "ASLR enabled", "fail", f"Value: {value}")


def _check_core_dumps(t: Transport) -> HardeningCheck:
    r = t.run("cat /proc/sys/fs/suid_dumpable 2>/dev/null || echo NOTFOUND")
    value = r.stdout.strip()
    if value == "0":
        return _check("H-006", "Kernel", "SUID core dumps disabled", "pass", f"Value: {value}")
    return _check("H-006", "Kernel", "SUID core dumps disabled", "fail", f"Value: {value}")


def _check_suid_files(t: Transport) -> HardeningCheck:
    # Search all common binary paths; use wc -l for an accurate count
    # instead of head which caps and misreports.
    r = t.run(
        "find /usr /bin /sbin /opt -perm -4000 -type f 2>/dev/null"
    )
    files = [f for f in r.stdout.strip().splitlines() if f]
    count = len(files)
    if count > SUID_WARN_THRESHOLD:
        return _check(
            "H-007", "Filesystem", "SUID binary count", "warn",
            f"{count} SUID binaries found",
        )
    return _check(
        "H-007", "Filesystem", "SUID binary count", "pass",
        f"{count} SUID binaries found",
    )
