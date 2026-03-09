"""Basic hardening / security-posture checks for Linux targets.

These checks are non-intrusive — read-only commands and file reads only.
"""

from __future__ import annotations

import logging

from collector.common.transport import Transport
from collector.models import HardeningCheck

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
    """Execute all hardening checks and return results."""
    checks: list[HardeningCheck] = []
    checks.append(_check_root_login(transport))
    checks.append(_check_password_auth(transport))
    checks.append(_check_firewall(transport))
    checks.append(_check_selinux(transport))
    checks.append(_check_aslr(transport))
    checks.append(_check_core_dumps(transport))
    checks.append(_check_suid_files(transport))
    return checks


def _check_root_login(t: Transport) -> HardeningCheck:
    r = t.run("grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo NOTFOUND")
    value = r.stdout.strip()
    if "NOTFOUND" in value:
        return _check("H-001", "SSH", "PermitRootLogin setting", "warn", "sshd_config not found")
    if "no" in value.lower():
        return _check("H-001", "SSH", "PermitRootLogin setting", "pass", value)
    return _check("H-001", "SSH", "PermitRootLogin setting", "fail", value)


def _check_password_auth(t: Transport) -> HardeningCheck:
    r = t.run("grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo NOTFOUND")
    value = r.stdout.strip()
    if "NOTFOUND" in value:
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
    r = t.run("find /usr -perm -4000 -type f 2>/dev/null | head -30")
    files = [f for f in r.stdout.strip().splitlines() if f]
    if len(files) > 15:
        return _check("H-007", "Filesystem", "SUID binary count", "warn", f"{len(files)}+ SUID binaries found")
    return _check("H-007", "Filesystem", "SUID binary count", "pass", f"{len(files)} SUID binaries found")
