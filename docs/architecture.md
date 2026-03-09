# Architecture

## Overview

```
┌──────────────┐     webhook      ┌──────────────────┐      SSH/ADB      ┌────────────┐
│     n8n      │ ───────────────> │  Collector API   │ ──────────────── > │   Target   │
│ (orchestrate)│ <─────────────── │  (FastAPI)       │ <──────────────── │  (embedded) │
└──────────────┘     results      └──────────────────┘    cmd output     └────────────┘
                                         │
                                    ┌────┴────┐
                                    │ Parsers │
                                    └────┬────┘
                                    ┌────┴────┐
                                    │ Reports │
                                    └─────────┘
                               JSON / HTML / Markdown
```

## Data Flow

1. n8n triggers `/assess` via HTTP POST
2. Collector API loads config, creates SSH transport
3. Each enabled module runs commands on the target
4. Raw output is parsed into typed Pydantic models
5. Results are serialized to JSON
6. Report generator renders HTML and Markdown via Jinja2
7. Response returned to n8n with summary + output paths

## Key Design Decisions

- **n8n is orchestration only** — no direct target interaction from n8n
- **Transport abstraction** — SSH today, ADB later, same module interface
- **Pydantic models** — typed, validated, serializable assessment data
- **Non-intrusive** — all checks are read-only; no exploitation
