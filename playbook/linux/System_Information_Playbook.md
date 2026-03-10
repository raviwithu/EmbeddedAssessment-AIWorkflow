# System Information Collection — Agent Execution Playbook

> **Purpose**: Step-by-step instructions for an automated agent to collect and analyze system identification data — OS fingerprinting, kernel version analysis, architecture enumeration, and uptime forensics on a Linux target.
>
> **Collector**: `collector/linux/system_info.py`
> **API Endpoint**: `POST /collect/linux/system`

---

## PREREQUISITES

### Required Access
- SSH connectivity to the target system (key-based or credential-based)
- Standard user privileges sufficient (no root required for basic collection)
- Network reachability from the collector host to the target

### Required Tools
```
TOOLS_REQUIRED:
  - hostname: System hostname resolution
  - uname: Kernel and architecture identification
  - uptime: System uptime reporting
  - cat: File reading (/etc/os-release)
```

---

## COLLECTION STEPS

### Step 1.1 — Collect Hostname
```bash
hostname
```
```
PURPOSE: Identify the target system by its configured hostname.
NOTE: On embedded systems, hostname may be a default like "localhost" or a factory string.
```

### Step 1.2 — Collect Kernel Version
```bash
uname -r
```
```
PURPOSE: Retrieve the running kernel version string.
CRITICAL: This value is essential for building Volatility profiles, matching LiME modules,
and identifying known kernel vulnerabilities (CVE matching).
```

### Step 1.3 — Collect OS Release Information
```bash
cat /etc/os-release 2>/dev/null | head -5
```
```
PURPOSE: Identify the Linux distribution, version, and variant.
NOTE: On minimal/embedded systems, /etc/os-release may not exist.
The collector captures the first 5 lines (typically ID, VERSION_ID, NAME, PRETTY_NAME).
```

### Step 1.4 — Collect System Architecture
```bash
uname -m
```
```
PURPOSE: Determine the CPU architecture (x86_64, aarch64, armv7l, mips, etc.).
CRITICAL for embedded assessment: architecture determines available exploit tooling,
binary compatibility, and hardware interface expectations.
```

### Step 1.5 — Collect System Uptime
```bash
uptime -p 2>/dev/null || uptime
```
```
PURPOSE: Determine how long the system has been running since last boot.
FALLBACK: If "uptime -p" (pretty format) is unavailable, falls back to standard uptime output.
```

---

## ANALYSIS & DECISION LOGIC

### What to Look For

| Data Point | Analysis Focus |
|------------|---------------|
| Hostname | Does it match expected naming conventions? Factory defaults suggest unconfigured device |
| Kernel version | Is it outdated? Check against CVE databases for known vulnerabilities |
| OS release | Is it a supported distribution? End-of-life distros receive no patches |
| Architecture | Does it match expected hardware? Unexpected arch may indicate emulation |
| Uptime | Extremely long uptime suggests no patching/rebooting discipline |

### Red Flags / IOCs

- **Kernel version older than 2 years**: HIGH — likely missing critical security patches
- **End-of-life distribution** (e.g., Ubuntu 16.04, CentOS 6): HIGH — no security updates available
- **Hostname set to "localhost" or default**: MEDIUM — device may not have been properly provisioned
- **Uptime exceeding 365 days**: MEDIUM — system has not been rebooted for kernel updates
- **Architecture mismatch**: HIGH — if the device is ARM but reports x86_64, may indicate a compromised/emulated environment
- **Missing /etc/os-release**: LOW — common on minimal embedded systems, but limits OS identification
- **Custom or unknown kernel version string**: MEDIUM — may indicate a patched, backdoored, or non-standard kernel

### Decision Tree

```
START
  │
  ├── Kernel version obtained?
  │     YES → Check against NVD/CVE database for known vulnerabilities
  │           → IF CVEs found: Record severity and count
  │           → Cross-reference with Phase 1 memory acquisition kernel match
  │     NO  → ALERT: MEDIUM — Cannot determine kernel version
  │
  ├── OS release identified?
  │     YES → Check end-of-life status
  │           → IF EOL: ALERT: HIGH — No security patches available
  │     NO  → LOG: Minimal/embedded system — attempt alternative identification
  │           → Check: cat /etc/issue, cat /etc/debian_version, cat /etc/redhat-release
  │
  ├── Uptime > 365 days?
  │     YES → ALERT: MEDIUM — System likely unpatched
  │           → Recommend reboot schedule and patch management review
  │     NO  → LOG: Uptime within acceptable range
  │
  └── All data collected successfully?
        YES → Proceed to process inventory collection
        NO  → Record failures, proceed with available data
```

---

## REMEDIATION GUIDANCE

| Finding | Remediation |
|---------|-------------|
| Outdated kernel | Schedule kernel update and reboot during maintenance window |
| EOL distribution | Plan migration to supported OS version |
| Default hostname | Configure proper hostname per organizational naming policy |
| Excessive uptime | Implement regular reboot schedule aligned with patch cycles |
| Unknown/custom kernel | Verify kernel provenance; compare with vendor-supplied kernel |

---

## REFERENCES

- NVD (National Vulnerability Database): https://nvd.nist.gov/
- Linux Kernel CVEs: https://www.linuxkernelcves.com/
- Ubuntu Release Cycle: https://ubuntu.com/about/release-cycle
- Debian LTS: https://wiki.debian.org/LTS
- `/etc/os-release` specification: https://www.freedesktop.org/software/systemd/man/os-release.html

---

*End of Playbook — Version 1.0*
