# Hardening Checks — Agent Execution Playbook

> **Purpose**: Step-by-step instructions for an automated agent to audit the security posture of a Linux target — SSH configuration, firewall rules, kernel security features, mandatory access controls, and SUID binary inventory.
>
> **Collector**: `collector/linux/hardening_checks.py`
> **API Endpoint**: `POST /collect/linux/security`

---

## PREREQUISITES

### Required Access
- SSH connectivity to the target system
- Root/sudo required for:
  - Reading SSH daemon configuration
  - Listing iptables rules
  - Finding SUID binaries across the filesystem
- SELinux/AppArmor status may require root

### Required Tools
```
TOOLS_REQUIRED:
  - grep: SSH configuration parsing
  - iptables: Firewall rule enumeration
  - getenforce: SELinux status (if SELinux present)
  - cat: Reading /proc kernel parameters
  - find: SUID binary discovery
```

---

## COLLECTION STEPS

### Step 5.1 — Check SSH Root Login
```bash
grep -hi '^PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1
```
```
PURPOSE: Determine if direct root login via SSH is permitted.
NOTE: Uses tail -1 to get the final effective directive (last match wins in sshd_config).
Also checks sshd_config.d/ drop-in directory for overrides.
EXPECTED: "PermitRootLogin no" or "PermitRootLogin prohibit-password"
```

### Step 5.2 — Check SSH Password Authentication
```bash
grep -hi '^PasswordAuthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1
```
```
PURPOSE: Determine if password-based SSH authentication is allowed.
EXPECTED: "PasswordAuthentication no" (key-based auth only)
NOTE: Password authentication is vulnerable to brute-force attacks.
```

### Step 5.3 — Check Firewall Rules
```bash
iptables -L -n 2>/dev/null | head -20
```
```
PURPOSE: Enumerate active iptables firewall rules.
OUTPUT: First 20 lines of the iptables rule listing.
NOTE: If iptables is not found, returns "NOTFOUND" — system may use nftables or have no firewall.
```

### Step 5.4 — Check SELinux Status
```bash
getenforce 2>/dev/null || echo NOTFOUND
```
```
PURPOSE: Check if SELinux mandatory access control is enabled.
EXPECTED VALUES:
  - Enforcing: Full MAC enforcement (best)
  - Permissive: Logging only, no enforcement (audit mode)
  - Disabled: SELinux not active
  - NOTFOUND: SELinux not installed
```

### Step 5.5 — Check ASLR Status
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo NOTFOUND
```
```
PURPOSE: Verify Address Space Layout Randomization is enabled.
VALUES:
  - 0: ASLR disabled (CRITICAL — exploitation trivially easier)
  - 1: Partial randomization (stack only)
  - 2: Full randomization (stack + heap + mmap — recommended)
```

### Step 5.6 — Check Core Dump Configuration
```bash
cat /proc/sys/fs/suid_dumpable 2>/dev/null || echo NOTFOUND
```
```
PURPOSE: Check if SUID processes can produce core dumps (credential leakage risk).
VALUES:
  - 0: No SUID core dumps (secure)
  - 1: SUID core dumps enabled (RISK — may leak credentials/keys)
  - 2: Restricted core dumps (piped to handler)
```

### Step 5.7 — Enumerate SUID Binaries
```bash
find /usr /bin /sbin /opt -perm -4000 -type f 2>/dev/null
```
```
PURPOSE: Find all binaries with the SUID bit set (run with owner's privileges).
THRESHOLD: Collector warns if count exceeds 15 (SUID_WARN_THRESHOLD).
NOTE: Each SUID binary is a potential privilege escalation vector.
```

---

## ANALYSIS & DECISION LOGIC

### What to Look For

| Check | Pass Condition | Fail Condition |
|-------|---------------|----------------|
| SSH Root Login | `no` or `prohibit-password` | `yes` |
| SSH Password Auth | `no` | `yes` |
| Firewall | Rules present with default DROP/REJECT | No rules or default ACCEPT |
| SELinux | `Enforcing` | `Disabled` or `Permissive` |
| ASLR | Value = `2` | Value = `0` or `1` |
| Core Dumps | Value = `0` | Value = `1` |
| SUID Binaries | Count ≤ 15, all from known packages | Count > 15, or unknown SUID binaries |

### Red Flags / IOCs

- **SSH PermitRootLogin yes**: CRITICAL — direct root access over network
- **SSH PasswordAuthentication yes**: HIGH — brute-force attack surface
- **No firewall rules (default ACCEPT)**: HIGH — no network-level access control
- **ASLR disabled (value=0)**: CRITICAL — memory exploitation trivial
- **SELinux disabled on a system that should have it**: MEDIUM — reduced containment
- **SUID binary count > 15**: MEDIUM — expanded privilege escalation surface
- **Unknown SUID binary not from a system package**: CRITICAL — potential backdoor
- **SUID binary in /tmp, /home, or /opt with unknown origin**: CRITICAL — likely planted
- **Core dumps enabled for SUID (value=1)**: MEDIUM — credential leakage via core files

### Decision Tree

```
START
  │
  ├── SSH Configuration:
  │     ├── Root login enabled?
  │     │     YES → ALERT: CRITICAL — Disable immediately
  │     │     NO  → PASS
  │     └── Password auth enabled?
  │           YES → ALERT: HIGH — Switch to key-based authentication
  │           NO  → PASS
  │
  ├── Firewall:
  │     ├── iptables rules present?
  │     │     YES → Analyze rules:
  │     │           → Default policy ACCEPT? → ALERT: HIGH — Permissive firewall
  │     │           → Default policy DROP/REJECT? → PASS (verify expected ports allowed)
  │     │     NO  → Check for nftables: nft list ruleset
  │     │           → IF nftables present: Analyze those rules
  │     │           → IF no firewall at all: ALERT: HIGH — No network access control
  │     │
  ├── Kernel Security:
  │     ├── ASLR = 0?
  │     │     YES → ALERT: CRITICAL — Enable immediately:
  │     │           echo 2 > /proc/sys/kernel/randomize_va_space
  │     │     NO  → PASS (value should be 2)
  │     └── Core dumps for SUID = 1?
  │           YES → ALERT: MEDIUM — Disable:
  │                 echo 0 > /proc/sys/fs/suid_dumpable
  │           NO  → PASS
  │
  ├── Mandatory Access Control:
  │     ├── SELinux installed?
  │     │     YES → Mode = Enforcing? → PASS
  │     │           Mode = Permissive? → ALERT: MEDIUM — Switch to Enforcing
  │     │           Mode = Disabled? → ALERT: HIGH — Enable SELinux
  │     │     NO  → Check for AppArmor: aa-status 2>/dev/null
  │     │           → IF neither present: ALERT: MEDIUM — No MAC framework
  │     │
  └── SUID Analysis:
        ├── Count > 15?
        │     YES → ALERT: MEDIUM — Review and remove unnecessary SUID bits
        │     NO  → PASS
        └── Any SUID binary not from system packages?
              YES → ALERT: CRITICAL — Verify origin of SUID binary
              → ACTION: Check with package manager:
                dpkg -S <binary> 2>/dev/null || rpm -qf <binary> 2>/dev/null
              NO  → PASS
```

---

## REMEDIATION GUIDANCE

| Finding | Remediation |
|---------|-------------|
| SSH root login enabled | Set `PermitRootLogin no` in sshd_config, restart sshd |
| SSH password auth enabled | Set `PasswordAuthentication no`, ensure key-based auth is configured first |
| No firewall rules | Configure iptables/nftables with default-deny policy |
| ASLR disabled | `echo 2 > /proc/sys/kernel/randomize_va_space`; persist in `/etc/sysctl.d/` |
| SELinux disabled | Enable in `/etc/selinux/config`, set to `Enforcing`, reboot |
| Excessive SUID binaries | Remove SUID bit from non-essential binaries: `chmod u-s <binary>` |
| Unknown SUID binary | Remove SUID bit, quarantine binary, investigate origin |
| Core dumps for SUID | `echo 0 > /proc/sys/fs/suid_dumpable`; persist in sysctl |

---

## REFERENCES

- CIS Benchmarks for Linux: https://www.cisecurity.org/benchmark/distribution_independent_linux
- OpenSSH hardening: https://www.ssh.com/academy/ssh/sshd_config
- GTFOBins (SUID exploitation): https://gtfobins.github.io/
- MITRE ATT&CK — Abuse Elevation Control: https://attack.mitre.org/techniques/T1548/
- Linux kernel sysctl hardening: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/

---

*End of Playbook — Version 1.0*
