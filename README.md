# Embedded Assessment Platform

Automated security assessment for embedded Linux (and future Android) targets.
Collects system inventory, checks hardening posture, enumerates hardware interfaces,
and generates structured reports — orchestrated via n8n.

> **Scope:** Inventory and hardening assessment only. No exploitation or intrusive testing.

## Architecture

```
n8n (orchestration)  -->  Collector API (FastAPI)  -->  Target (SSH / ADB)
                                  |
                           Parsers + Report
                                  |
                         JSON / HTML / Markdown
```

## Quick Start

```bash
# 1. Copy and edit configuration
cp config/config.yaml config/config.local.yaml
cp .env.example .env
# Edit .env with your SSH target credentials

# 2. Deploy all services
./deploy.sh

# 3. Or run the collector locally (without Docker)
pip install -r requirements.txt
COLLECTOR_CONFIG=config/config.local.yaml python -m collector.api
```

The collector API runs on `http://localhost:8000`.
n8n UI is available at `http://localhost:5678`.

## Deploy & Teardown Scripts

### `deploy.sh` — Start the platform

Brings up the entire platform in one command:

- Checks that Docker is installed and the daemon is running
- Copies `.env.example` to `.env` if no `.env` file exists
- Creates the `output/` directory
- Builds the collector image and starts all containers (`n8n` + `collector`)
- Runs health checks and prints service URLs

```bash
./deploy.sh
```

### `teardown.sh` — Stop the platform

Stops all running containers. Supports optional flags for cleanup:

| Flag | Description |
|------|-------------|
| _(no flags)_ | Stop containers only |
| `-v`, `--volumes` | Also remove named volumes (n8n data, SSH keys) |
| `-i`, `--images` | Also remove built collector image |
| `-a`, `--all` | Remove volumes and images |
| `-h`, `--help` | Show usage help |

```bash
./teardown.sh          # stop containers
./teardown.sh -v       # stop + remove volumes
./teardown.sh -a       # stop + remove volumes + images
```

## API Endpoints

| Method | Path                     | Description                                   |
|--------|--------------------------|-----------------------------------------------|
| GET    | /health                  | Liveness probe                                |
| GET    | /targets                 | List configured targets from config file      |
| POST   | /assess                  | Full config-driven assessment (all or by name) |
| POST   | /collect/linux/system    | System info, processes, services, ports       |
| POST   | /collect/linux/security  | Hardening / security-posture checks           |
| POST   | /collect/linux/hwcomms   | Hardware communication interface enumeration  |
| POST   | /collect/linux/service-map | Map services to processes and listening ports |
| POST   | /forensic/baseline       | Gold image baseline capture                   |
| POST   | /forensic/phase0         | Phase 0 volatile environment snapshot         |
| POST   | /forensic/phase1         | Phase 1 memory acquisition (LiME / kcore)     |
| POST   | /report/render           | Render AssessmentResult to HTML / Markdown     |

### Config-driven assessment

```bash
# Assess all targets defined in config/config.yaml
curl -X POST http://localhost:8000/assess -H 'Content-Type: application/json' -d '{}'

# Assess a specific target by name
curl -X POST http://localhost:8000/assess -H 'Content-Type: application/json' \
  -d '{"target_name": "linux-device-01"}'
```

### Per-domain collection (with SSH credentials)

```bash
# System inventory
curl -X POST http://localhost:8000/collect/linux/system \
  -H 'Content-Type: application/json' \
  -d '{"target": {"host": "192.168.1.100"}}'

# Security checks only
curl -X POST http://localhost:8000/collect/linux/security \
  -H 'Content-Type: application/json' \
  -d '{"target": {"host": "192.168.1.100"}, "checks": ["H-001", "H-005"]}'

# Hardware interface enumeration
curl -X POST http://localhost:8000/collect/linux/hwcomms \
  -H 'Content-Type: application/json' \
  -d '{"target": {"host": "192.168.1.100"}, "interface_types": ["uart", "i2c"]}'
```

### Service-to-process mapping

```bash
curl -X POST http://localhost:8000/collect/linux/service-map \
  -H 'Content-Type: application/json' \
  -d '{"target": {"host": "192.168.1.100"}}'
```

### Forensic collection

```bash
# Gold image baseline (hashes, processes, users, kernel modules, SUID files, etc.)
curl -X POST http://localhost:8000/forensic/baseline \
  -H 'Content-Type: application/json' \
  -d '{"target": {"host": "192.168.1.100"}}'

# Phase 0 — volatile environment snapshot (order-of-volatility capture)
curl -X POST http://localhost:8000/forensic/phase0 \
  -H 'Content-Type: application/json' \
  -d '{"target": {"host": "192.168.1.100"}}'

# Phase 1 — memory acquisition via LiME or /proc/kcore
curl -X POST http://localhost:8000/forensic/phase1 \
  -H 'Content-Type: application/json' \
  -d '{"target": {"host": "192.168.1.100"}}'
```

Forensic artifacts are saved to `output/baselines/<hostname>/<phase>/` with a `manifest.json` tracking all collection runs.

> SSH credentials fall back to `SSH_*` environment variables when not provided in the request body.

## Collection Modules

| Module             | Description                                  |
|--------------------|----------------------------------------------|
| process_inventory  | Running processes via `ps`                   |
| service_port_inventory | systemd services + listening ports (ss/netstat) |
| service_process_map | Map systemd services to PIDs and ports       |
| hardening_checks   | SSH config, firewall, SELinux, ASLR, SUID    |
| hardware_comm      | UART, SPI, I2C, GPIO, USB enumeration        |
| system_info        | Hostname, kernel, OS, architecture, uptime   |
| baseline           | Gold image capture (binary hashes, users, kernel modules, SUID) |
| phase0_environment | Phase 0 volatile data in order of volatility |
| phase1_memory      | Memory acquisition via LiME module or /proc/kcore |
| forensic_storage   | Per-host artifact storage with manifest tracking |

## Project Structure

```
deploy.sh                   Start all services (Docker)
teardown.sh                 Stop all services (with cleanup options)
collector/
  common/transport.py       SSH / ADB transport abstraction
  linux/
    baseline.py             Gold image baseline collector
    forensic_storage.py     Per-host artifact storage + manifest
    hardening_checks.py     Security posture checks
    hardware_comm.py        Hardware interface enumeration
    phase0_environment.py   Phase 0 volatile environment capture
    phase1_memory.py        Phase 1 memory acquisition (LiME/kcore)
    process_inventory.py    Process listing and parsing
    runner.py               Orchestrates all collection modules
    service_port_inventory.py  Services and listening ports
    service_process_map.py  Service-to-process-to-port mapping
    system_info.py          System identification
  android/                  Android stubs (future)
  api.py                    FastAPI service
  config.py                 Configuration loader
  models.py                 Pydantic data models
parsers/
  normalize.py              JSON serialization / deserialization
report/
  generator.py              HTML + Markdown report generation
  templates/                Jinja2 report templates
n8n/
  docker-compose.yml        n8n + collector services
  workflows/                Importable n8n workflow definitions
config/
  config.yaml               Sample configuration
tests/
  linux/                    Unit tests for collection modules
  parsers/                  Tests for JSON normalization
  report/                   Tests for report generation
```

## Configuration

See [config/config.yaml](config/config.yaml) for all options.
Copy to `config/config.local.yaml` for your environment — it is gitignored.

## Adding New Checks

1. Add a function to the appropriate module in `collector/linux/`
2. Register it in `collector/linux/runner.py`
3. Add a model if needed in `collector/models.py`
4. Update report templates in `report/templates/`

## License

Internal use.
