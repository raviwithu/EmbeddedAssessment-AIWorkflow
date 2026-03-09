# Module Reference

## Collector Modules

### process_inventory
- **File:** `collector/linux/process_inventory.py`
- **Command:** `ps aux --no-headers`
- **Output:** List of `ProcessInfo` (PID, user, CPU%, MEM%, state, command)

### service_port_inventory
- **File:** `collector/linux/service_port_inventory.py`
- **Commands:** `systemctl list-units`, `ss -tulnp` (fallback: `netstat -tulnp`)
- **Output:** Lists of `ServiceInfo` and `OpenPort`

### hardening_checks
- **File:** `collector/linux/hardening_checks.py`
- **Checks:**
  - H-001: SSH PermitRootLogin
  - H-002: SSH PasswordAuthentication
  - H-003: iptables firewall rules
  - H-004: SELinux mode
  - H-005: ASLR (randomize_va_space)
  - H-006: SUID core dumps
  - H-007: SUID binary count
- **Output:** List of `HardeningCheck` with pass/fail/warn/info status

### hardware_comm
- **File:** `collector/linux/hardware_comm.py`
- **Interfaces:** UART (/dev/ttyS*, ttyUSB*, ttyAMA*), SPI, I2C, GPIO, USB
- **Output:** List of `HardwareInterface`

### system_info
- **File:** `collector/linux/system_info.py`
- **Output:** `SystemInfo` (hostname, kernel, OS, arch, uptime)

## Transport Layer

- **SSH:** `collector/common/transport.py` — paramiko-based
- **ADB:** Placeholder for future Android support

## Report Formats

- **JSON:** Raw Pydantic model serialization
- **HTML:** Styled table-based report via Jinja2
- **Markdown:** Table-based report via Jinja2
