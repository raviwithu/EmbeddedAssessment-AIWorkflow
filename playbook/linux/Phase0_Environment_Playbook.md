# Phase 0: Environment Assessment — Agent Execution Playbook

> **Purpose**: Step-by-step instructions for an automated agent to capture volatile system data from a live Linux target following the order of volatility — network connections, running processes, open files, kernel modules, memory info, mount points, ARP cache, routing, DNS, firewall rules, cron jobs, login history, and kernel messages.
>
> **Collector**: `collector/linux/phase0_environment.py`
> **API Endpoint**: `POST /forensic/phase0`
>
> **Sources**: RFC 3227 — Guidelines for Evidence Collection and Archiving, The Art of Memory Forensics (Ligh, Case, Levy, Walters)

---

## PREREQUISITES

### Required Access
- SSH connectivity to the target system
- Root/sudo required for:
  - Full process environment variables (`/proc/*/environ`)
  - Detailed network socket information (`ss -tulnap`)
  - Kernel slab allocator info (`/proc/slabinfo`)
  - Firewall rules (`iptables`)
  - Other users' crontabs
- **WARNING**: Every action on the target system modifies volatile data — minimize footprint

### Required Tools
```
TOOLS_REQUIRED:
  - uname, uptime, date: System identification
  - ss / netstat: Network connections
  - ps: Process listing
  - lsof: Open file handles
  - lsmod: Kernel modules
  - cat: /proc filesystem reading
  - mount: Mount point listing
  - ip / route: Routing table
  - iptables: Firewall rules
  - crontab: Scheduled jobs
  - systemctl: Systemd timer listing
  - last: Login history
  - dmesg: Kernel ring buffer
```

---

## COLLECTION STEPS

> **CRITICAL**: Collect in order of volatility — most volatile data first. Network state and running processes change rapidly and must be captured before anything else.

### Step 0.1 — System Identification
```bash
uname -a
cat /etc/os-release 2>/dev/null
uptime
date -u
```
```
PURPOSE: Timestamp and identify the target system.
NOTE: Use UTC time (date -u) for consistent forensic timeline.
```

### Step 0.2 — Network Connections (MOST VOLATILE)
```bash
# Active connections and listeners
ss -tulnap
netstat -tulnap 2>/dev/null || echo 'netstat not available'

# Raw kernel network tables
cat /proc/net/tcp 2>/dev/null
cat /proc/net/tcp6 2>/dev/null
cat /proc/net/udp 2>/dev/null
```
```
PURPOSE: Capture all network connections — established, listening, and pending.
CRITICAL: Network connections are the MOST VOLATILE evidence.
An attacker's C2 session or data exfiltration channel may disconnect at any moment.
/proc/net/tcp provides raw kernel view that is harder to tamper with than ss/netstat output.
```

### Step 0.3 — Running Processes
```bash
ps auxwwf
ps -eo pid,ppid,uid,gid,comm,args
ls -la /proc/*/exe 2>/dev/null | head -500
```
```
PURPOSE: Full process tree with parent-child relationships, user context, and binary paths.
NOTE: /proc/*/exe symlinks reveal the actual binary on disk (detects process masquerading).
```

### Step 0.4 — Open Files
```bash
lsof -n 2>/dev/null | head -5000 || echo 'lsof not available'
```
```
PURPOSE: Record all open file descriptors — identifies active file access, network sockets,
and resource usage by each process.
LIMIT: First 5,000 entries to prevent timeout.
```

### Step 0.5 — Loaded Kernel Modules
```bash
lsmod
cat /proc/modules
```
```
PURPOSE: Record loaded kernel modules.
COMPARISON: Compare with baseline to detect newly loaded (potentially malicious) modules.
```

### Step 0.6 — Process Environment Variables (Sample)
```bash
for pid in $(ls -d /proc/[0-9]* 2>/dev/null | head -50 | xargs -I{} basename {}); do
    echo "=== PID $pid ==="
    cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n'
    echo
done
```
```
PURPOSE: Capture environment variables of the first 50 processes.
SIGNIFICANCE: LD_PRELOAD, PATH manipulation, and malware config often stored in env vars.
LIMIT: First 50 PIDs to prevent excessive data collection.
```

### Step 0.7 — System Memory Information
```bash
cat /proc/meminfo
cat /proc/vmstat
cat /proc/slabinfo 2>/dev/null || echo 'permission denied'
```
```
PURPOSE: Record memory usage, VM statistics, and kernel slab allocator state.
NOTE: slabinfo requires root and shows kernel object allocation patterns.
```

### Step 0.8 — Kernel Taint Status
```bash
cat /proc/sys/kernel/tainted
```
```
PURPOSE: Check if the kernel has been modified (out-of-tree modules, unsigned modules, etc.).
VALUE 0 = untainted. Any non-zero value requires investigation.
```

### Step 0.9 — Mount Points
```bash
mount
cat /proc/mounts
```
```
PURPOSE: Record all mounted filesystems and their mount options.
SIGNIFICANCE: noexec, nosuid flags may have been removed; tmpfs mounts may be suspicious.
```

### Step 0.10 — ARP Cache
```bash
cat /proc/net/arp 2>/dev/null
```
```
PURPOSE: Record ARP table — shows recently communicated hosts on the local network.
SIGNIFICANCE: Unexpected ARP entries may indicate lateral movement or ARP spoofing.
```

### Step 0.11 — Routing Table
```bash
ip route 2>/dev/null || route -n 2>/dev/null
```
```
PURPOSE: Record routing configuration.
SIGNIFICANCE: Modified routes may redirect traffic through attacker-controlled systems.
```

### Step 0.12 — DNS Configuration
```bash
cat /etc/resolv.conf 2>/dev/null
```
```
PURPOSE: Record DNS resolver configuration.
SIGNIFICANCE: Modified DNS can redirect all name resolution through attacker infrastructure.
```

### Step 0.13 — Firewall Rules
```bash
iptables -L -n -v 2>/dev/null || echo 'iptables not available'
```
```
PURPOSE: Record current firewall state.
SIGNIFICANCE: Attacker may have added rules to allow C2 traffic or block security tools.
```

### Step 0.14 — Scheduled Jobs (Cron)
```bash
for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
    echo "=== $u ==="
    crontab -l -u "$u" 2>/dev/null
done
```
```
PURPOSE: Record all user crontabs for persistence mechanism detection.
```

### Step 0.15 — Systemd Timers
```bash
systemctl list-timers --all --no-pager 2>/dev/null || echo 'not systemd'
```
```
PURPOSE: Record systemd timer units — modern equivalent of cron for persistence.
```

### Step 0.16 — Login History
```bash
last -20 2>/dev/null || echo 'last not available'
```
```
PURPOSE: Record recent login activity (last 20 entries).
```

### Step 0.17 — Kernel Messages
```bash
dmesg 2>/dev/null | tail -200 || echo 'dmesg not available'
```
```
PURPOSE: Capture recent kernel ring buffer messages (last 200 lines).
SIGNIFICANCE: Module loading events, hardware errors, OOM kills, security violations.
```

---

## ANALYSIS & DECISION LOGIC

### What to Look For

| Data Category | Key Indicators |
|--------------|----------------|
| Network connections | Unexpected ESTABLISHED connections, listeners on high ports, connections to known-bad IPs |
| Processes | Processes from /tmp, reverse shells, deleted binaries, masquerading processes |
| Open files | Files open in /dev/shm, hidden files, raw socket access |
| Kernel modules | Modules not in baseline, out-of-tree modules, unsigned modules |
| Environment vars | LD_PRELOAD set, PATH manipulation, encoded payloads in env |
| Memory | Unexpected memory usage patterns, slab anomalies |
| Mounts | Removed noexec/nosuid, suspicious tmpfs mounts |
| ARP | Unknown MAC addresses, duplicate IPs (ARP spoofing) |
| Routing | Unexpected routes, traffic redirection |
| DNS | Modified resolv.conf pointing to unknown nameservers |
| Firewall | Added ACCEPT rules, removed security rules |
| Cron | New cron entries, base64-encoded commands, download-and-execute patterns |
| Login history | Logins from unexpected IPs, logins at unusual times |
| Kernel messages | Module load events, segfaults, OOM events |

### Red Flags / IOCs

- **ESTABLISHED connection to unknown external IP**: CRITICAL — possible C2 channel
- **LD_PRELOAD set in any process environment**: HIGH — userland rootkit
- **Kernel taint value non-zero (especially bits 12, 13)**: HIGH — out-of-tree/unsigned module
- **DNS resolv.conf pointing to non-corporate nameserver**: HIGH — DNS hijacking
- **New cron entry with wget/curl/base64**: CRITICAL — persistence with payload download
- **Firewall rules added since baseline**: HIGH — attacker enabling access
- **ARP table showing duplicate IPs with different MACs**: HIGH — ARP spoofing/MITM
- **Login from unexpected geographic IP**: HIGH — unauthorized access
- **Module loaded that's not in baseline**: HIGH — possible rootkit
- **dmesg showing repeated segfaults**: MEDIUM — possible exploitation attempts

### Decision Tree

```
START
  │
  ├── IMMEDIATE TRIAGE (first 60 seconds of analysis):
  │     ├── Any active C2 connections? (unknown external ESTABLISHED connections)
  │     │     YES → ALERT: CRITICAL — Document and proceed with full collection
  │     │           → Do NOT disconnect yet — capture more evidence first
  │     │     NO  → Continue
  │     │
  │     ├── Any active reverse shells? (bash -i, nc -e, python pty)
  │     │     YES → ALERT: CRITICAL — Active compromise confirmed
  │     │     NO  → Continue
  │     │
  │     └── Kernel tainted?
  │           YES → ALERT: HIGH — Investigate loaded modules
  │           NO  → Continue
  │
  ├── PERSISTENCE CHECK:
  │     ├── New cron entries? → Compare with baseline
  │     ├── New systemd timers? → Compare with baseline
  │     ├── Modified init scripts? → Compare with baseline
  │     └── IF any new persistence: ALERT: HIGH — Record and continue
  │
  ├── NETWORK ANOMALY CHECK:
  │     ├── DNS modified? → ALERT: HIGH
  │     ├── Routes modified? → ALERT: HIGH
  │     ├── Firewall rules changed? → ALERT: HIGH
  │     └── ARP anomalies? → ALERT: MEDIUM
  │
  └── PROCEED TO PHASE 1:
        → All volatile data captured
        → Phase 1 (Memory Acquisition) can now proceed
        → Phase 0 data provides context for memory analysis
```

---

## REMEDIATION GUIDANCE

| Finding | Remediation |
|---------|-------------|
| Active C2 connection | Capture traffic (tcpdump), then isolate system from network |
| LD_PRELOAD rootkit | Identify the preloaded library, check /etc/ld.so.preload |
| DNS hijacking | Restore resolv.conf, check DHCP client configuration |
| Malicious cron entry | Remove entry, investigate payload, check for re-creation mechanism |
| Firewall tampering | Restore baseline rules, investigate how rules were changed |
| ARP spoofing | Enable static ARP for critical hosts, deploy ARP monitoring |
| Unauthorized login | Disable compromised account, rotate credentials, check for lateral movement |

> **NOTE**: Phase 0 is about **evidence capture**, not remediation. Do not remediate during this phase — remediation destroys evidence. Complete all forensic phases before taking remediation actions.

---

## REFERENCES

- RFC 3227 — Guidelines for Evidence Collection and Archiving: https://www.rfc-editor.org/rfc/rfc3227
- Order of Volatility: Registers → Cache → RAM → Disk → Remote logging → Physical media
- The Art of Memory Forensics (Ligh, Case, Levy, Walters)
- NIST SP 800-86 — Guide to Integrating Forensic Techniques: https://csrc.nist.gov/publications/detail/sp/800-86/final
- MITRE ATT&CK — Persistence: https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK — Command and Control: https://attack.mitre.org/tactics/TA0011/

---

*End of Playbook — Version 1.0*
