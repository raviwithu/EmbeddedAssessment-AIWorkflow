# Service-to-Process Map — Agent Execution Playbook

> **Purpose**: Step-by-step instructions for an automated agent to correlate systemd services with their running processes and listening ports, detect orphaned processes, identify services with missing processes, and attribute network ports to specific services.
>
> **Collector**: `collector/linux/service_process_map.py`
> **API Endpoint**: `POST /collect/linux/service-map`

---

## PREREQUISITES

### Required Access
- SSH connectivity to the target system
- Root/sudo required for full process-to-port attribution
- systemd must be present for service-to-PID mapping

### Required Tools
```
TOOLS_REQUIRED:
  - systemctl: Service enumeration and MainPID lookup
  - ps: Process inventory (GNU coreutils or BusyBox)
  - ss / netstat: Port enumeration for port-to-process matching
```

---

## COLLECTION STEPS

### Step 4.1 — Collect Service List
```bash
# Reuses collect_services() from service_port_inventory.py
systemctl list-units --type=service --all --no-pager --no-legend
systemctl list-unit-files --type=service --no-pager --no-legend
```
```
PURPOSE: Build the complete list of known services with their active/enabled state.
```

### Step 4.2 — Batch Query Service PIDs
```bash
# Single batch query for all service MainPIDs
systemctl show sshd.service nginx.service cron.service ... --property=Id,MainPID --no-pager
```
```
PURPOSE: Retrieve the main process ID for each active service in a single command.
OPTIMIZATION: Batch query avoids N individual systemctl calls.
OUTPUT: Id=sshd.service\nMainPID=1234\n\nId=nginx.service\nMainPID=5678\n...
NOTE: MainPID=0 means the service is not currently running.
```

### Step 4.3 — Collect Process Inventory
```bash
# Reuses collect_processes() from process_inventory.py
ps aux --no-headers 2>/dev/null
```
```
PURPOSE: Get full process list to match against service PIDs.
```

### Step 4.4 — Collect Open Ports
```bash
# Reuses collect_open_ports() from service_port_inventory.py
ss -tulnp
```
```
PURPOSE: Get listening ports with process names for port-to-service attribution.
```

### Step 4.5 — Build Service-Process-Port Map
```
AGENT: For each service, the collector:
  1. Looks up the MainPID from Step 4.2
  2. Finds the matching process from Step 4.3 (by PID)
  3. Matches listening ports from Step 4.4 (by process name or command basename)
  4. Produces a ServiceProcessMap entry with:
     - service_name, state, enabled
     - main_pid
     - process (user, pid, cpu%, mem%, state, command)
     - ports (protocol, port, address, process)
```

---

## ANALYSIS & DECISION LOGIC

### What to Look For

| Indicator | Significance |
|-----------|-------------|
| Service active but MainPID=0 | Service claims running but has no process — possible crash or type=oneshot |
| Service active but process not found in ps | Process may have exited or been killed |
| Process running but no matching service | Orphaned process — not managed by systemd |
| Service with unexpected port binding | May indicate configuration tampering |
| Multiple services sharing the same PID | Unusual — may indicate process hijacking |
| Port attributed to wrong service | Possible port squatting or service impersonation |

### Red Flags / IOCs

- **Active service with no running process**: HIGH — service crashed or process was killed
- **Process running with no corresponding service**: MEDIUM — orphaned or manually started process; if listening on a port, escalate to HIGH
- **Service MainPID points to wrong binary**: CRITICAL — process replacement attack
- **Port bound by a process that doesn't match the expected service**: HIGH — port hijacking
- **Service PID changed since last collection**: MEDIUM — service restarted (normal) or replaced (suspicious)
- **Multiple services with identical MainPID**: HIGH — process confusion or systemd misconfiguration

### Decision Tree

```
START
  │
  ├── FOR EACH service:
  │     │
  │     ├── Service active AND MainPID > 0?
  │     │     YES → Verify PID exists in process list
  │     │           → IF process found:
  │     │               → Verify command matches expected binary
  │     │               → Match ports to service
  │     │           → IF process NOT found:
  │     │               → ALERT: HIGH — Service reports running but process is gone
  │     │               → ACTION: Restart service, investigate why it died
  │     │     NO  → Check if service should be running
  │     │           → IF enabled but inactive: ALERT: MEDIUM — Expected service not running
  │     │
  │     ├── Service has listening ports?
  │     │     YES → Verify ports match expected service configuration
  │     │           → IF unexpected port: ALERT: HIGH — Service configuration tampering
  │     │     NO  → Is this a network service? If yes, why no ports?
  │     │
  │     └── Service binary matches package-installed binary?
  │           YES → PASS
  │           NO  → ALERT: CRITICAL — Binary replacement detected
  │
  ├── FOR EACH orphaned process (process with no service):
  │     │
  │     ├── Process listening on a port?
  │     │     YES → ALERT: HIGH — Unmanaged network listener
  │     │           → ACTION: Identify binary, check for persistence
  │     │     NO  → ALERT: LOW — Orphaned process (may be legitimate one-off)
  │     │
  │     └── Process running as root?
  │           YES → Escalate severity by one level
  │
  └── CROSS-REFERENCE with baseline (if available):
        → New services not in baseline: Investigate
        → New port-service mappings: Verify intentional
        → Missing services: Check for intentional removal vs attacker disablement
```

---

## REMEDIATION GUIDANCE

| Finding | Remediation |
|---------|-------------|
| Service with dead process | Restart service, check logs: `journalctl -u <service>` |
| Orphaned network listener | Identify and stop process, create systemd unit if legitimate |
| Binary replacement | Reinstall package, investigate how binary was modified |
| Unexpected port binding | Review service configuration, check for config file tampering |
| Missing expected service | Re-enable service, check for attacker disablement |

---

## REFERENCES

- systemd service management: https://www.freedesktop.org/software/systemd/man/systemctl.html
- `systemctl show` properties: https://www.freedesktop.org/software/systemd/man/systemd.exec.html
- MITRE ATT&CK — Service Stop: https://attack.mitre.org/techniques/T1489/
- MITRE ATT&CK — Hijack Execution Flow: https://attack.mitre.org/techniques/T1574/

---

*End of Playbook — Version 1.0*
