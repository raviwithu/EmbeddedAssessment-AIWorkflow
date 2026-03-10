# Hardware Interface Enumeration — Agent Execution Playbook

> **Purpose**: Step-by-step instructions for an automated agent to enumerate hardware communication interfaces on an embedded Linux target — UART/serial, SPI, I2C, GPIO, and USB — and assess the risk of exposed debug interfaces.
>
> **Collector**: `collector/linux/hardware_comm.py`
> **API Endpoint**: `POST /collect/linux/hwcomms`

---

## PREREQUISITES

### Required Access
- SSH connectivity to the target system
- Root/sudo recommended for full device access (many `/dev/` nodes require root)
- Physical access context: these interfaces are often exploited via physical attack vectors

### Required Tools
```
TOOLS_REQUIRED:
  - ls: Device node enumeration (/dev/, /sys/class/)
  - test: Readability checks on device nodes
  - lsusb: USB device enumeration (optional — may not be present on minimal systems)
```

---

## COLLECTION STEPS

### Step 6.1 — Enumerate Serial/UART Interfaces
```bash
ls /dev/ttyS* /dev/ttyUSB* /dev/ttyAMA* /dev/ttyACM* 2>/dev/null
```
```
PURPOSE: Find all serial/UART device nodes.
DEVICE TYPES:
  - /dev/ttyS*:   Standard serial ports (16550 UART)
  - /dev/ttyUSB*: USB-to-serial adapters (FTDI, CH340, CP2102)
  - /dev/ttyAMA*: ARM AMBA PL011 UART (Raspberry Pi, embedded ARM)
  - /dev/ttyACM*: USB Abstract Control Model (Arduino, modems)
SIGNIFICANCE: UART is the #1 debug interface on embedded devices — often provides root shell.
```

### Step 6.2 — Enumerate SPI Interfaces
```bash
ls /dev/spidev* 2>/dev/null
```
```
PURPOSE: Find SPI (Serial Peripheral Interface) device nodes.
SIGNIFICANCE: SPI is commonly used for flash memory chips containing firmware.
ATTACK VECTOR: SPI flash can be read/written to extract or modify firmware.
```

### Step 6.3 — Enumerate I2C Interfaces
```bash
ls /dev/i2c-* 2>/dev/null
```
```
PURPOSE: Find I2C (Inter-Integrated Circuit) bus device nodes.
SIGNIFICANCE: I2C connects to EEPROMs, sensors, TPMs, and other peripherals.
ATTACK VECTOR: I2C EEPROM may contain credentials, keys, or configuration data.
```

### Step 6.4 — Enumerate GPIO Interfaces
```bash
ls /sys/class/gpio/gpiochip* /dev/gpiochip* 2>/dev/null
```
```
PURPOSE: Find GPIO (General Purpose Input/Output) chip interfaces.
SIGNIFICANCE: GPIO controls hardware pins — can be used to toggle debug modes,
reset security chips, or interface with JTAG.
```

### Step 6.5 — Enumerate USB Devices
```bash
lsusb 2>/dev/null
```
```
PURPOSE: List all USB devices connected to the system.
SIGNIFICANCE: Unexpected USB devices may indicate:
  - USB Rubber Ducky / BadUSB attack devices
  - Unauthorized storage devices (data exfiltration)
  - USB-to-serial debug adapters
  - Rogue USB network adapters
```

### Step 6.6 — Check Device Readability
```bash
# For each device found in Steps 6.1-6.4:
test -r <device_path> && echo <device_path>
```
```
PURPOSE: Determine which hardware interfaces the current user can read/access.
CRITICAL: If debug interfaces are readable by non-root users, the attack surface
is significantly increased — any user-level compromise grants hardware access.
```

---

## ANALYSIS & DECISION LOGIC

### What to Look For

| Interface | Risk Assessment |
|-----------|----------------|
| UART (ttyS/ttyUSB/ttyAMA/ttyACM) | ROOT SHELL risk — UART often has login prompt or direct shell |
| SPI (spidev) | FIRMWARE EXTRACTION — can read/write flash chips |
| I2C (i2c-*) | DATA EXTRACTION — EEPROMs may contain keys/credentials |
| GPIO (gpiochip) | HARDWARE CONTROL — can toggle debug modes, bypass security |
| USB (lsusb) | ATTACK DEVICE — unexpected devices may be malicious |

### Red Flags / IOCs

- **UART interfaces readable by non-root user**: CRITICAL — any user can potentially get root shell
- **SPI interfaces present and accessible**: HIGH — firmware can be extracted and reverse-engineered
- **I2C interfaces present and accessible**: HIGH — sensitive data in EEPROMs may be readable
- **GPIO accessible by non-root**: MEDIUM — hardware state can be manipulated
- **Unexpected USB devices**: HIGH — possible attack hardware (BadUSB, implants)
- **USB mass storage device present on headless/embedded system**: HIGH — potential data exfiltration
- **USB network adapter not in expected configuration**: MEDIUM — rogue network interface
- **Multiple UART interfaces on non-development system**: MEDIUM — debug interfaces should be disabled in production

### Decision Tree

```
START
  │
  ├── UART Interfaces Found?
  │     YES → How many?
  │           → IF on production device (not development):
  │               ALERT: HIGH — Debug UART should be disabled in production
  │               → ACTION: Check if UART provides login prompt:
  │                   screen /dev/ttyS0 115200
  │               → IF login prompt found: ALERT: CRITICAL — Root shell accessible via UART
  │           → Check readability:
  │               → IF readable by non-root: ALERT: CRITICAL — Widen attack surface
  │     NO  → PASS (good — no serial debug interfaces exposed)
  │
  ├── SPI Interfaces Found?
  │     YES → ALERT: HIGH — Firmware extraction possible
  │           → ACTION: Identify connected flash chip:
  │               flashrom -p linux_spi:dev=/dev/spidev0.0
  │           → ACTION: Assess if firmware encryption is in use
  │     NO  → PASS
  │
  ├── I2C Interfaces Found?
  │     YES → ALERT: MEDIUM — I2C bus accessible
  │           → ACTION: Scan bus for devices:
  │               i2cdetect -y <bus_number>
  │           → ACTION: Check for EEPROM at common addresses (0x50-0x57)
  │     NO  → PASS
  │
  ├── GPIO Interfaces Found?
  │     YES → ALERT: LOW-MEDIUM — GPIO access available
  │           → ACTION: Document exposed GPIO chips and pin count
  │           → ACTION: Check if GPIO can toggle debug/JTAG modes
  │     NO  → PASS
  │
  └── USB Devices:
        ├── Expected devices only?
        │     YES → PASS
        │     NO  → FOR EACH unexpected device:
        │           → Check vendor/product ID against known malicious devices
        │           → ALERT: HIGH — Unknown USB device connected
        │           → ACTION: Record VID:PID, investigate device purpose
        └── USB mass storage present on embedded system?
              YES → ALERT: HIGH — Potential data exfiltration channel
              NO  → PASS
```

---

## REMEDIATION GUIDANCE

| Finding | Remediation |
|---------|-------------|
| UART accessible in production | Disable UART in device tree / kernel config, or remove physical connector |
| UART readable by non-root | `chmod 600 /dev/ttyS*`, configure udev rules for proper permissions |
| SPI accessible | Restrict `/dev/spidev*` permissions, encrypt firmware at rest |
| I2C accessible | Restrict `/dev/i2c-*` permissions, encrypt sensitive EEPROM data |
| GPIO accessible by non-root | Configure proper permissions via udev rules |
| Unknown USB device | Physically inspect, remove if unauthorized, implement USB device whitelisting |
| Debug interfaces in production | Disable in kernel config, remove physical connectors, fuse-blow if possible |

---

## REFERENCES

- UART exploitation guide: https://www.exploit-db.com/docs/english/18274-hardware-hacking---uart-debugging.pdf
- SPI flash dumping with flashrom: https://flashrom.org/
- I2C tools: https://i2c.wiki.kernel.org/index.php/I2C_Tools
- USB security: https://www.kernel.org/doc/html/latest/usb/authorization.html
- MITRE ATT&CK — Hardware Additions: https://attack.mitre.org/techniques/T1200/
- OWASP IoT — Insecure Hardware Interfaces: https://owasp.org/www-project-internet-of-things/

---

*End of Playbook — Version 1.0*
