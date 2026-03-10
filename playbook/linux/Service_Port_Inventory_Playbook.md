# Service & Port Inventory — Agent Execution Playbook

> **Purpose**: Step-by-step instructions for an automated agent to enumerate all systemd services and listening network ports on a Linux target, identify rogue services, detect unauthorized listeners, and correlate services with their network exposure.
>
> **Collector**: `collector/linux/service_port_inventory.py`
> **API Endpoint**: `POST /collect/linux/system`

---

## PREREQUISITES

### Required Access
- SSH connectivity to the target system
- Root/sudo required for full port-to-process attribution (`ss -tulnp` / `netstat -tulnp`)
- systemd must be present for service enumeration (non-systemd systems will return empty service list)

### Required Tools
```
TOOLS_REQUIRED:
  - systemctl: Service enumeration (systemd)
  - ss: Socket statistics (primary port enumeration)
  - netstat: Fallback port enumeration (if ss unavailable)
```

---

## COLLECTION STEPS

### Step 3.1 — Enumerate Systemd Services (Active Units)
```bash
systemctl list-units --type=service --all --no-pager --no-legend
```
```
PURPOSE: List all loaded service units with their current runtime state.
OUTPUT: Unit name, load state, active state, sub state, description.
CAPTURES: Service name and active/inactive/failed state.
```

### Step 3.2 — Enumerate Systemd Services (Unit Files)
```bash
systemctl list-unit-files --type=service --no-pager --no-legend
```
```
PURPOSE: List all installed service unit files with their enabled/disabled status.
CAPTURES: Service name and whether it is enabled at boot.
```

### Step 3.3 — Enumerate Listening Ports (Primary: ss)
```bash
ss -tulnp
```
```
PURPOSE: List all TCP and UDP listening sockets with process attribution.
FLAGS:
  -t: TCP sockets
  -u: UDP sockets
  -l: Listening sockets only
  -n: Numeric (no DNS resolution)
  -p: Show process using socket (requires root)
```

### Step 3.4 — Enumerate Listening Ports (Fallback: netstat)
```bash
# Only executed if ss fails
netstat -tulnp
```
```
PURPOSE: Fallback for systems where ss is unavailable (older or minimal systems).
Same flags as ss — TCP/UDP, listening, numeric, with process info.
```

### Step 3.5 — Parse Port Data
```
AGENT: For each listening port, extract:
  - protocol: tcp or udp
  - port: Port number
  - address: Bind address (0.0.0.0, ::, 127.0.0.1, specific IP)
  - process: Process name owning the socket

The collector handles multiple address formats:
  - IPv4: 0.0.0.0:22, 127.0.0.1:3306
  - IPv6: [::]:80, :::22, [::1]:631
  - Wildcard: *:68
```

---

## ANALYSIS & DECISION LOGIC

### What to Look For

| Indicator | Significance |
|-----------|-------------|
| Services in "failed" state | Crashed or misconfigured — may indicate tampering |
| Enabled services not in active state | Should be running but aren't — possible DoS or disablement |
| Unknown/unexpected services | May be attacker-installed persistence mechanisms |
| Ports listening on 0.0.0.0 or :: | Exposed to all network interfaces — wider attack surface |
| High ports (>1024) with no known service | May indicate backdoor listeners |
| Well-known ports with wrong process | Process hijacking or trojanized service |
| Database ports exposed externally | 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB) should be localhost-only |

### Red Flags / IOCs

- **Unknown service enabled at boot**: HIGH — potential persistence mechanism
- **Listening port with no identifiable process**: HIGH — possible rootkit hiding process
- **Port 4444, 5555, 1337, 31337 listening**: HIGH — common backdoor/C2 ports
- **Multiple SSH daemons (sshd on different ports)**: HIGH — potential backdoor SSH instance
- **Telnet (port 23) enabled**: HIGH — plaintext protocol, should never be enabled
- **Service name doesn't match expected binary**: MEDIUM — possible trojanized service
- **Database port bound to 0.0.0.0**: HIGH — database exposed to network
- **Web server on non-standard port**: MEDIUM — may be legitimate or attacker web shell
- **Service "masked" in unit files**: LOW — intentionally disabled, verify it should be

### Decision Tree

```
START
  │
  ├── SERVICES ANALYSIS:
  │     │
  │     ├── Any services in "failed" state?
  │     │     YES → Investigate failure reason: systemctl status <service>
  │     │           → IF crash loop: Check for binary tampering
  │     │
  │     ├── Any unknown/unexpected services enabled?
  │     │     YES → ALERT: HIGH — Check service unit file for binary path
  │     │           → ACTION: Verify binary hash against known-good
  │     │           → ACTION: Check service creation date
  │     │
  │     └── Expected services missing?
  │           YES → ALERT: MEDIUM — Service may have been disabled by attacker
  │           → ACTION: Check if service file still exists, check audit logs
  │
  ├── PORT ANALYSIS:
  │     │
  │     ├── Any listening port without process attribution?
  │     │     YES → ALERT: HIGH — Possible rootkit hiding process
  │     │           → ACTION: Cross-reference with process inventory
  │     │           → ACTION: Check /proc/net/tcp directly
  │     │
  │     ├── Any common backdoor ports listening (4444, 5555, 1337, 31337)?
  │     │     YES → ALERT: CRITICAL — Likely backdoor
  │     │           → ACTION: Identify process, capture binary, block port
  │     │
  │     ├── Any service bound to 0.0.0.0/:: that should be localhost-only?
  │     │     YES → ALERT: HIGH — Unnecessary network exposure
  │     │           → ACTION: Reconfigure to bind to 127.0.0.1 or ::1
  │     │
  │     └── Any port with process name mismatch?
  │           YES → ALERT: HIGH — Possible trojanized service
  │           → ACTION: Verify binary integrity
  │
  └── CROSS-REFERENCE:
        → Compare services list with ports list
        → Services with no listening port: expected? Or failing to bind?
        → Ports with no matching service: rogue listener
```

---

## REMEDIATION GUIDANCE

| Finding | Remediation |
|---------|-------------|
| Unknown service enabled | Disable: `systemctl disable --now <service>`, investigate origin |
| Backdoor port listening | Kill process, remove binary, block port in firewall, check persistence |
| Database exposed to network | Reconfigure bind address to 127.0.0.1, add firewall rule |
| Telnet enabled | Disable immediately: `systemctl disable --now telnet.socket` |
| Failed service | Investigate cause, repair or remove, check for tampering |
| Service with wrong binary | Reinstall package, verify with `dpkg -V` or `rpm -Va` |

---

## REFERENCES

- `ss` man page: `man ss`
- systemd service management: https://www.freedesktop.org/software/systemd/man/systemctl.html
- IANA port assignments: https://www.iana.org/assignments/service-names-port-numbers/
- MITRE ATT&CK — Non-Standard Port: https://attack.mitre.org/techniques/T1571/
- MITRE ATT&CK — System Services: https://attack.mitre.org/techniques/T1569/

---

*End of Playbook — Version 1.0*
