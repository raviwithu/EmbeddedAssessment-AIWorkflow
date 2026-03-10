"""Tests for hardening checks (collector/linux/hardening_checks.py)."""

from __future__ import annotations

from collector.linux.hardening_checks import run_hardening_checks
from tests.conftest import MockTransport
from tests.linux.conftest import (
    IPTABLES_EMPTY,
    IPTABLES_WITH_RULES,
    SSHD_PASSWORD_AUTH_NO,
    SSHD_PASSWORD_AUTH_YES,
    SSHD_ROOT_LOGIN_NO,
    SSHD_ROOT_LOGIN_YES,
    SUID_FILES_FEW,
    SUID_FILES_MANY,
)


def _setup_secure_transport(t: MockTransport) -> None:
    """Register command outputs for a fully hardened system."""
    t.register_substring("PermitRootLogin", stdout=SSHD_ROOT_LOGIN_NO)
    t.register_substring("PasswordAuthentication", stdout=SSHD_PASSWORD_AUTH_NO)
    t.register_substring("iptables", stdout=IPTABLES_WITH_RULES)
    t.register_substring("getenforce", stdout="Enforcing\n")
    t.register_substring("randomize_va_space", stdout="2\n")
    t.register_substring("suid_dumpable", stdout="0\n")
    t.register_substring("find /usr /bin /sbin /opt", stdout=SUID_FILES_FEW)


def _setup_insecure_transport(t: MockTransport) -> None:
    """Register command outputs for a poorly hardened system."""
    t.register_substring("PermitRootLogin", stdout=SSHD_ROOT_LOGIN_YES)
    t.register_substring("PasswordAuthentication", stdout=SSHD_PASSWORD_AUTH_YES)
    t.register_substring("iptables", stdout="NOTFOUND\n")
    t.register_substring("getenforce", stdout="Disabled\n")
    t.register_substring("randomize_va_space", stdout="0\n")
    t.register_substring("suid_dumpable", stdout="2\n")
    t.register_substring("find /usr /bin /sbin /opt", stdout=SUID_FILES_MANY)


# ---------------------------------------------------------------------------
# All checks run
# ---------------------------------------------------------------------------

class TestAllChecksRun:
    def test_returns_seven_checks(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        assert len(checks) == 7

    def test_check_ids(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        ids = [c.check_id for c in checks]
        assert ids == ["H-001", "H-002", "H-003", "H-004", "H-005", "H-006", "H-007"]


# ---------------------------------------------------------------------------
# Secure system — all pass
# ---------------------------------------------------------------------------

class TestSecureSystem:
    def test_root_login_pass(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-001"].status == "pass"

    def test_password_auth_pass(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-002"].status == "pass"

    def test_firewall_pass(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-003"].status == "pass"

    def test_selinux_pass(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-004"].status == "pass"

    def test_aslr_pass(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-005"].status == "pass"

    def test_core_dumps_pass(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-006"].status == "pass"

    def test_suid_pass(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-007"].status == "pass"


# ---------------------------------------------------------------------------
# Insecure system — fail/warn
# ---------------------------------------------------------------------------

class TestInsecureSystem:
    def test_root_login_fail(self, mock_transport: MockTransport):
        _setup_insecure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-001"].status == "fail"

    def test_password_auth_fail(self, mock_transport: MockTransport):
        _setup_insecure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-002"].status == "fail"

    def test_firewall_warn(self, mock_transport: MockTransport):
        _setup_insecure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-003"].status == "warn"

    def test_aslr_fail(self, mock_transport: MockTransport):
        _setup_insecure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-005"].status == "fail"

    def test_core_dumps_fail(self, mock_transport: MockTransport):
        _setup_insecure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-006"].status == "fail"

    def test_suid_warn(self, mock_transport: MockTransport):
        _setup_insecure_transport(mock_transport)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-007"].status == "warn"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_sshd_not_found_warns(self, mock_transport: MockTransport):
        """When sshd_config grep returns nothing, checks return warn."""
        _setup_secure_transport(mock_transport)
        # Override SSH settings to return empty (NOTFOUND)
        mock_transport._responses.clear()
        mock_transport.commands_run.clear()
        # Re-register with missing sshd config
        mock_transport.register_substring("PermitRootLogin", stdout="")
        mock_transport.register_substring("PasswordAuthentication", stdout="")
        mock_transport.register_substring("iptables", stdout=IPTABLES_WITH_RULES)
        mock_transport.register_substring("getenforce", stdout="Enforcing\n")
        mock_transport.register_substring("randomize_va_space", stdout="2\n")
        mock_transport.register_substring("suid_dumpable", stdout="0\n")
        mock_transport.register_substring("find /usr /bin /sbin /opt", stdout=SUID_FILES_FEW)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-001"].status == "warn"
        assert by_id["H-002"].status == "warn"

    def test_selinux_permissive_warns(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        mock_transport._responses.clear()
        _setup_secure_transport(mock_transport)
        # Override getenforce
        for k in list(mock_transport._responses):
            if "getenforce" in k:
                del mock_transport._responses[k]
        mock_transport.register_substring("getenforce", stdout="Permissive\n")
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-004"].status == "warn"

    def test_partial_aslr_warns(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        mock_transport._responses.clear()
        _setup_secure_transport(mock_transport)
        for k in list(mock_transport._responses):
            if "randomize_va_space" in k:
                del mock_transport._responses[k]
        mock_transport.register_substring("randomize_va_space", stdout="1\n")
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-005"].status == "warn"

    def test_firewall_no_rules_fails(self, mock_transport: MockTransport):
        _setup_secure_transport(mock_transport)
        mock_transport._responses.clear()
        _setup_secure_transport(mock_transport)
        for k in list(mock_transport._responses):
            if "iptables" in k:
                del mock_transport._responses[k]
        mock_transport.register_substring("iptables", stdout=IPTABLES_EMPTY)
        checks = run_hardening_checks(mock_transport)
        by_id = {c.check_id: c for c in checks}
        assert by_id["H-003"].status == "fail"
