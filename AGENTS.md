# Project: Embedded Target Assessment Automation

## Goal
Build an n8n-based embedded security assessment workflow that:
1. Connects to a target system through SSH or ADB
2. Collects:
   - running processes
   - services and open ports
   - OS/kernel/package information
   - hardening/security state
   - hardware communication visibility
3. Normalizes all results into JSON
4. Generates a detailed HTML and Markdown report

## Constraints
- n8n is orchestration only
- direct target interaction must be done by collector scripts/services
- support Linux first, then Android
- do not implement exploitation
- focus on inventory, hardening assessment, and reporting

## Output standards
- Python 3.11
- typed code where practical
- structured JSON outputs
- clean error handling
- markdown docs for each module

## First milestone
Implement Linux target collection through SSH and local bench-side hardware interface collection.