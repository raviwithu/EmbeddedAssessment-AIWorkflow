# Process Inventory — Agent Execution Playbook

> **Purpose**: Step-by-step instructions for an automated agent to enumerate all running processes on a Linux target, detect suspicious or anomalous processes, and identify potential malware, backdoors, or unauthorized software.
>
> **Collector**: `collector/linux/process_inventory.py`
> **API Endpoint**: `POST /collect/linux/system`

---

## PREREQUISITES

### Required Access
- SSH connectivity to the target system
- Standard user privileges (basic process listing)
- Root/sudo recommended for full visibility (some process details hidden from non-root)

### Required Tools
```
TOOLS_REQUIRED:
  - ps (GNU coreutils or BusyBox): Process listing
  - /proc filesystem: Process metadata source
```

---

## COLLECTION STEPS

### Step 2.1 — Enumerate Processes (GNU coreutils)
```bash
# Primary method — full GNU ps output
ps aux --no-headers 2>/dev/null
```
```
PURPOSE: Collect all running processes with user, PID, CPU%, MEM%, state, and full command line.
OUTPUT FORMAT: 11 columns — USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
```

### Step 2.2 — Fallback: BusyBox/Minimal Systems
```bash
# Fallback for embedded/minimal systems without GNU coreutils
ps -o pid,user,stat,args 2>/dev/null || ps -ef 2>/dev/null
```
```
PURPOSE: On BusyBox or stripped-down systems, GNU ps may not be available.
The collector tries simplified ps formats and parses 4 columns (pid, user, state, command).
```

### Step 2.3 — Parse Collected Data
```
AGENT: For each process line, extract:
  - user: Account running the process
  - pid: Process ID
  - cpu_percent: CPU utilization (0.0 if unavailable on BusyBox)
  - mem_percent: Memory utilization (0.0 if unavailable on BusyBox)
  - state: Process state (R=running, S=sleeping, Z=zombie, T=stopped, D=uninterruptible)
  - command: Full command line with arguments
```

---

## ANALYSIS & DECISION LOGIC

### What to Look For

| Indicator | Significance |
|-----------|-------------|
| Processes running as root | Should be limited to system services; unexpected root processes are suspicious |
| Processes with high CPU/MEM | May indicate cryptominers or resource-exhausting malware |
| Zombie processes (state=Z) | May indicate process injection or unstable malware |
| Processes with deleted binary (`(deleted)`) | Binary was removed after execution — strong IOC |
| Processes with no visible command | Process hiding its command line via argv manipulation |
| Processes spawned from `/tmp`, `/dev/shm`, `/var/tmp` | Classic malware staging directories |
| Unexpected interpreters (python, perl, bash -i) | May indicate reverse shells or post-exploitation tools |
| Kernel threads with unusual names | May indicate rootkit kernel threads |

### Red Flags / IOCs

- **Process binary path contains `/tmp/`, `/dev/shm/`, or `/var/tmp/`**: HIGH — malware staging location
- **Process name mimics system process** (e.g., `sshd `, `[kworker]`, `cron`): HIGH — process masquerading
- **Reverse shell patterns** (`bash -i >& /dev/tcp/`, `nc -e`, `python -c 'import socket'`): CRITICAL — active backdoor
- **Cryptominer signatures** (`xmrig`, `minerd`, `stratum+tcp://`): HIGH — unauthorized mining
- **Deleted binary** (`/path/to/binary (deleted)`): HIGH — anti-forensic technique
- **Process with empty or overwritten command line**: MEDIUM — argv manipulation
- **Unexpected `sshd` or `telnetd` instances**: HIGH — potential unauthorized remote access
- **Processes running as `nobody` or `www-data` with shell access**: MEDIUM — possible web shell pivot

### Decision Tree

```
START
  │
  ├── FOR EACH process:
  │     │
  │     ├── Binary path in /tmp, /dev/shm, /var/tmp?
  │     │     YES → ALERT: HIGH — Suspicious execution location
  │     │           → ACTION: Capture binary hash, check against threat intel
  │     │
  │     ├── Command line matches reverse shell pattern?
  │     │     YES → ALERT: CRITICAL — Active backdoor detected
  │     │           → ACTION: Record PID, remote IP, kill if authorized
  │     │
  │     ├── Process running as root but not a known system service?
  │     │     YES → ALERT: MEDIUM — Unexpected root process
  │     │           → ACTION: Investigate parent process (PPID), check binary integrity
  │     │
  │     ├── CPU > 80% sustained?
  │     │     YES → ALERT: MEDIUM — Resource abuse (possible cryptominer)
  │     │           → ACTION: Check command line for mining pool URLs
  │     │
  │     ├── Process state = Z (zombie)?
  │     │     YES → ALERT: LOW — Zombie process detected
  │     │           → ACTION: Check parent process for proper wait() handling
  │     │
  │     └── Process name matches system process but PID/path is wrong?
  │           YES → ALERT: HIGH — Process masquerading
  │           → ACTION: Compare binary hash with known-good version
  │
  └── Compare process list against baseline (if available)
        → New processes not in baseline: Investigate
        → Missing expected processes: Check for process killing/denial of service
```

---

## REMEDIATION GUIDANCE

| Finding | Remediation |
|---------|-------------|
| Reverse shell detected | Kill process, block remote IP at firewall, investigate initial access vector |
| Cryptominer running | Kill process, remove binary, audit for persistence mechanisms |
| Deleted binary process | Dump process memory (`/proc/<PID>/exe`), investigate origin |
| Process masquerading | Compare with package manager (`dpkg -V`, `rpm -Va`), reinstall if tampered |
| Suspicious root process | Trace parent chain, check cron/systemd for persistence, revoke unnecessary privileges |
| Processes from /tmp | Remove binary, check for re-creation (persistence), mount /tmp noexec |

---

## REFERENCES

- Linux `ps` man page: `man ps`
- `/proc` filesystem documentation: https://www.kernel.org/doc/html/latest/filesystems/proc.html
- MITRE ATT&CK — Process Injection: https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK — Masquerading: https://attack.mitre.org/techniques/T1036/

---

*End of Playbook — Version 1.0*
