# Baseline Collection — Agent Execution Playbook

> **Purpose**: Step-by-step instructions for an automated agent to capture a comprehensive gold image baseline of a Linux system — binary hashes, user accounts, kernel modules, network state, filesystem permissions, and installed device inventory — for use in future integrity comparisons.
>
> **Collector**: `collector/linux/baseline.py`
> **API Endpoint**: `POST /forensic/baseline`

---

## PREREQUISITES

### Required Access
- SSH connectivity to the target system
- Root/sudo required for:
  - Reading `/etc/shadow`
  - Full `lsof` output
  - Complete filesystem traversal for hashing
  - SUID/SGID file discovery
- System should be in a known-good state (pre-deployment or post-verification)

### Required Tools
```
TOOLS_REQUIRED:
  - uname, hostname: System identification
  - find: Filesystem traversal
  - sha256sum: Cryptographic hashing
  - ps: Process inventory
  - cat: File reading
  - lsmod: Kernel module listing
  - lsof: Open file listing
  - ss / netstat: Network listener enumeration
  - ls: Directory listing
  - lspci, lsusb, lsblk: Device enumeration
  - lsattr: Extended file attributes
  - zcat: Compressed kernel config reading
```

---

## COLLECTION STEPS

### Step 7.1 — System Identification
```bash
uname -a
cat /etc/os-release 2>/dev/null
hostname
```
```
PURPOSE: Record the system identity to tag the baseline with kernel version, OS, and hostname.
```

### Step 7.2 — Binary Hashes (System Binaries)
```bash
find /usr/bin /usr/sbin /bin /sbin -type f -exec sha256sum {} \; 2>/dev/null | head -10000
```
```
PURPOSE: Generate SHA-256 hashes of all system binaries for future integrity verification.
LIMIT: First 10,000 entries to prevent timeout on large systems.
TIMEOUT: 120 seconds per command.
CRITICAL: Any future hash mismatch indicates binary tampering or unauthorized update.
```

### Step 7.3 — Library Hashes (Shared Libraries)
```bash
find /lib /usr/lib -maxdepth 2 -name '*.so*' -type f -exec sha256sum {} \; 2>/dev/null | head -10000
```
```
PURPOSE: Hash shared libraries to detect trojanized or replaced libraries.
NOTE: LD_PRELOAD and library injection attacks replace legitimate .so files.
```

### Step 7.4 — Process Inventory
```bash
ps auxwwf
ps -eo pid,ppid,uid,gid,comm,args
```
```
PURPOSE: Capture the full process tree and process details as known-good state.
```

### Step 7.5 — User and Group Accounts
```bash
cat /etc/passwd
cat /etc/group
cat /etc/shadow 2>/dev/null || echo 'PERMISSION_DENIED'
```
```
PURPOSE: Record all local user accounts, groups, and password hashes.
NOTE: /etc/shadow requires root. If unavailable, records PERMISSION_DENIED.
CRITICAL: New accounts or changed hashes indicate unauthorized access.
```

### Step 7.6 — Kernel Modules
```bash
lsmod
cat /proc/modules
```
```
PURPOSE: Record all loaded kernel modules as known-good baseline.
COMPARISON: Future analysis compares against this to detect new/hidden modules.
```

### Step 7.7 — Open Files
```bash
lsof -n 2>/dev/null | head -5000 || echo 'lsof not available'
```
```
PURPOSE: Record all open file handles — identifies running services and their resources.
LIMIT: First 5,000 entries to prevent timeout.
```

### Step 7.8 — Network Listeners
```bash
ss -tulnap
netstat -tulnap 2>/dev/null || echo 'netstat not available'
```
```
PURPOSE: Record all listening ports and established connections as known-good state.
```

### Step 7.9 — Init System Configuration
```bash
ls -la /etc/init.d/ 2>/dev/null || echo 'no init.d'
find /etc/rc*.d -type l -ls 2>/dev/null || echo 'no rc.d'
```
```
PURPOSE: Record init scripts and runlevel symlinks for persistence detection.
```

### Step 7.10 — Kernel Configuration
```bash
zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) 2>/dev/null || echo 'not available'
```
```
PURPOSE: Capture the kernel build configuration for security feature verification.
NOTE: Checks both /proc/config.gz and /boot/config-* as fallback.
```

### Step 7.11 — Device Inventory
```bash
lspci 2>/dev/null || echo 'lspci not available'
lsusb 2>/dev/null || echo 'lsusb not available'
lsblk 2>/dev/null || echo 'lsblk not available'
```
```
PURPOSE: Record all PCI, USB, and block devices for hardware change detection.
```

### Step 7.12 — File Permissions
```bash
ls -la /etc/ 2>/dev/null | head -100
ls -la /sbin/ /usr/sbin/ 2>/dev/null | head -100
```
```
PURPOSE: Record file permissions on critical directories for permission tampering detection.
```

### Step 7.13 — SUID/SGID Binaries
```bash
find /usr /bin /sbin /opt -perm -4000 -type f 2>/dev/null
find /usr /bin /sbin /opt -perm -2000 -type f 2>/dev/null
```
```
PURPOSE: Record all SUID and SGID binaries. New SUID binaries are privilege escalation backdoors.
```

### Step 7.14 — Immutable Files
```bash
lsattr -R /etc/ 2>/dev/null | grep '\-i\-' || echo 'none found'
```
```
PURPOSE: Record files with the immutable attribute set.
NOTE: Attackers may set immutable on backdoor configs to prevent removal.
Alternatively, defenders set immutable on critical configs to prevent tampering.
```

---

## ANALYSIS & DECISION LOGIC

### What to Look For

This playbook is primarily about **capture**, not analysis. The baseline becomes the reference for all future comparisons. However, during capture, flag obvious issues:

| Baseline Item | Immediate Red Flag |
|---------------|-------------------|
| Binary hashes | Known-malicious hashes (check against threat intel) |
| User accounts | Unexpected UID 0 accounts (root-equivalent) |
| Kernel modules | Out-of-tree or unsigned modules |
| Network listeners | Unexpected ports open on a "clean" system |
| SUID binaries | SUID binaries in unusual locations |
| Immutable files | Unexpected immutable files in /tmp or /home |

### Red Flags During Baseline Capture

- **System is NOT in a known-good state**: CRITICAL — baseline is meaningless if system is already compromised
- **UID 0 accounts other than root**: HIGH — hidden admin accounts
- **SUID binary not traceable to a package**: HIGH — planted escalation tool
- **Network listener on unusual port**: MEDIUM — verify before accepting as baseline
- **Immutable file in /tmp or user directories**: HIGH — persistence mechanism
- **shadow file has empty password hashes**: CRITICAL — passwordless accounts

### Decision Tree

```
START
  │
  ├── Is the system verified as clean/known-good?
  │     YES → Proceed with baseline capture
  │     NO  → STOP — Run full security assessment first
  │           → A baseline from a compromised system is worse than no baseline
  │
  ├── All 30 commands completed successfully?
  │     YES → Store baseline with timestamp and system identifier
  │     NO  → Record which commands failed
  │           → IF critical commands failed (hashes, users, modules):
  │               → ALERT: MEDIUM — Incomplete baseline
  │               → ACTION: Investigate why commands failed (permissions? missing tools?)
  │
  ├── Any immediate red flags found during capture?
  │     YES → Investigate before accepting this as "gold image"
  │     NO  → Accept baseline
  │
  └── Store baseline securely:
        → Hash the baseline data itself (integrity of the baseline)
        → Store off-system (forensic storage, SIEM, version control)
        → Protect against tampering (read-only, signed)
```

---

## REMEDIATION GUIDANCE

| Finding | Remediation |
|---------|-------------|
| Compromised system used for baseline | Rebuild from trusted media, then re-capture baseline |
| Missing commands/tools | Install required packages before baseline capture |
| Permission denied on critical items | Run collector with root/sudo privileges |
| Excessive SUID binaries in baseline | Remove unnecessary SUID bits before accepting baseline |
| Unknown user accounts | Remove unauthorized accounts before baseline |

### Baseline Maintenance

- **Recapture baseline** after any authorized system change (package update, config change)
- **Compare periodically** — schedule automated baseline comparisons (weekly minimum)
- **Store multiple versions** — maintain baseline history for trend analysis
- **Protect baseline integrity** — store on separate, access-controlled system

---

## REFERENCES

- NIST SP 800-123 — Guide to General Server Security: https://csrc.nist.gov/publications/detail/sp/800-123/final
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks/
- AIDE (Advanced Intrusion Detection Environment): https://aide.github.io/
- Tripwire: https://github.com/Tripwire/tripwire-open-source
- MITRE ATT&CK — Indicator Removal: https://attack.mitre.org/techniques/T1070/

---

*End of Playbook — Version 1.0*
