# Phase 1: Memory Acquisition — Agent Execution Playbook

> **Purpose**: Step-by-step instructions for an automated agent to acquire a full physical memory dump from a live Linux target using LiME (preferred) or /proc/kcore (fallback), verify dump integrity, and prepare for Volatility-based analysis.
>
> **Collector**: `collector/linux/phase1_memory.py`
> **API Endpoint**: `POST /forensic/phase1`
>
> **Sources**: The Art of Memory Forensics (Ligh, Case, Levy, Walters), LiME documentation

---

## PREREQUISITES

### Required Access
- SSH connectivity to the target system
- **Root/sudo required** — memory acquisition needs kernel-level access
- Sufficient storage at dump path (default: `/tmp/forensic`) — dump size ≈ physical RAM size
- Pre-compiled LiME module matching the exact target kernel version

### Required Tools
```
TOOLS_REQUIRED:
  - LiME (Linux Memory Extractor): Pre-compiled .ko for target kernel
    - Source: https://github.com/504ensicslabs/LiME
    - CRITICAL: Must be compiled for EXACT kernel version (uname -r)
    - NEVER compile on a potentially compromised system
  - insmod / rmmod: Kernel module loading/unloading (requires root)
  - sha256sum: Integrity hash computation
  - stat / ls: File size verification
  - cat: Reading /proc/meminfo
```

---

## COLLECTION STEPS

### Step 1.1 — Prepare Dump Directory
```bash
mkdir -p /tmp/forensic
```
```
PURPOSE: Create the output directory for memory dump files.
NOTE: Default path is /tmp/forensic. Can be overridden via dump_path parameter.
CONSIDERATION: Ensure target filesystem has enough free space (≈ RAM size).
```

### Step 1.2 — Record Total Physical Memory
```bash
cat /proc/meminfo
```
```
PURPOSE: Record total physical memory to validate dump size later.
KEY LINE: "MemTotal: XXXX kB" — dump should be approximately this size.
```

### Step 1.3 — Locate LiME Kernel Module
```bash
ls /mnt/trusted_usb/lime-$(uname -r).ko 2>/dev/null || \
ls /tmp/lime-$(uname -r).ko 2>/dev/null || \
find / -name 'lime-*.ko' -maxdepth 3 2>/dev/null | head -1
```
```
PURPOSE: Find the pre-compiled LiME module matching the running kernel.
SEARCH ORDER:
  1. /mnt/trusted_usb/ — preferred location (trusted external media)
  2. /tmp/ — alternate staging location
  3. System-wide search — last resort (maxdepth 3 to limit scope)
NOTE: If LiME module is not found, collector falls back to /proc/kcore.
```

### Step 1.4a — Acquire Memory with LiME (Primary Method)
```bash
# Load LiME module to dump memory to file
sudo insmod /path/to/lime-$(uname -r).ko "path=/tmp/forensic/memory.lime format=lime"
```
```
PURPOSE: Perform full physical memory acquisition in LiME format.
TIMEOUT: 300 seconds (5 minutes) — large memory systems may take time.
FORMAT: "lime" format preserves memory layout with address range metadata.
BEHAVIOR: LiME writes the dump and then the module remains loaded until removed.
WARNING: Loading a kernel module modifies system state — this is an accepted trade-off.
```

### Step 1.4b — Fallback: /proc/kcore Acquisition
```bash
# Check if /proc/kcore is readable
test -r /proc/kcore && echo yes || echo no

# If readable, record its virtual size
ls -l /proc/kcore 2>/dev/null
```
```
PURPOSE: If LiME is unavailable, check if /proc/kcore can be used as fallback.
WARNING: /proc/kcore is LESS RELIABLE than LiME:
  - Malware can hook the /proc/kcore read function to hide memory regions
  - /proc/kcore is a virtual file — its size doesn't reflect actual memory
  - Some kernel configurations disable /proc/kcore access
NOTE: The collector records kcore availability but does not automatically copy it.
```

### Step 1.5 — Unload LiME Module
```bash
sudo rmmod lime 2>/dev/null
```
```
PURPOSE: Clean up — remove LiME module from kernel after acquisition.
TIMEOUT: 30 seconds.
NOTE: If rmmod fails, the module remains loaded but is harmless.
```

### Step 1.6 — Verify Dump Integrity
```bash
# Compute SHA-256 hash
sha256sum /tmp/forensic/memory.lime 2>/dev/null

# Get dump file size
stat -c %s /tmp/forensic/memory.lime 2>/dev/null || ls -l /tmp/forensic/memory.lime
```
```
PURPOSE: Generate integrity hash and verify file size.
VERIFICATION:
  - SHA-256 hash: Record for chain of custody — must match if dump is transferred
  - File size: Should be approximately equal to MemTotal from Step 1.2
  - If size is significantly smaller: dump may be incomplete
  - If size is zero: dump failed entirely
```

### Step 1.7 — Record Kernel Profile Information
```bash
uname -r
ls /boot/System.map-$(uname -r) 2>/dev/null && echo 'found' || echo 'not found'
```
```
PURPOSE: Record kernel version and System.map availability for Volatility profile creation.
System.map is needed to build the Volatility profile for memory analysis (Phase 2+).
```

---

## ANALYSIS & DECISION LOGIC

### What to Look For

| Verification | Expected | Problem |
|-------------|----------|---------|
| Dump file exists | Yes | Acquisition failed |
| Dump file size ≈ MemTotal | Within 10% | Incomplete dump |
| SHA-256 hash computed | Non-empty | Hash computation failed |
| LiME method used | Preferred | kcore fallback is less reliable |
| System.map available | Found | Volatility profile creation will be harder |

### Red Flags / IOCs

- **LiME module fails to load (insmod error)**: MEDIUM — kernel may block module loading (module signing enforced, Secure Boot)
- **Dump file size is 0**: CRITICAL — acquisition completely failed
- **Dump file significantly smaller than MemTotal**: HIGH — incomplete acquisition, some memory regions missed
- **LiME module not found for kernel version**: MEDIUM — must compile LiME offline for this kernel version
- **/proc/kcore not readable**: LOW — expected on hardened systems
- **Kernel taint flag set after LiME load**: EXPECTED — LiME is an out-of-tree module, it will set taint bit 12

### Decision Tree

```
START
  │
  ├── LiME module found?
  │     YES → Load LiME module
  │           → insmod succeeded?
  │               YES → Verify dump file:
  │                     → File exists and size > 0?
  │                         YES → Compute SHA-256 hash
  │                               → Unload LiME module
  │                               → PROCEED to Phase 2 (Volatility Analysis)
  │                         NO  → ALERT: CRITICAL — Dump failed
  │                               → Try kcore fallback
  │               NO  → ALERT: MEDIUM — insmod failed
  │                     → Check dmesg for error reason
  │                     → IF "Required key not available": Module signing enforced
  │                     → IF "Operation not permitted": Secure Boot or lockdown mode
  │                     → Try kcore fallback
  │     NO  → ALERT: MEDIUM — LiME not available for this kernel
  │           → Try kcore fallback
  │
  ├── kcore fallback:
  │     ├── /proc/kcore readable?
  │     │     YES → Record availability
  │     │           → WARNING: kcore is hookable by rootkits
  │     │           → Agent should attempt manual copy if authorized:
  │     │               cp /proc/kcore /tmp/forensic/kcore.elf
  │     │     NO  → ALERT: HIGH — No memory acquisition method available
  │     │           → ACTION: Compile LiME offline for kernel version from Step 1.7
  │     │           → ACTION: Transfer compiled module and re-attempt
  │
  └── Post-Acquisition:
        → Verify SHA-256 hash
        → Verify dump size vs MemTotal
        → Record acquisition method (lime or kcore)
        → Transfer dump to forensic workstation if needed
        → Proceed to Phase 2 (Volatility Profile Setup)
```

---

## REMEDIATION GUIDANCE

| Finding | Remediation |
|---------|-------------|
| LiME not found | Compile LiME on a clean system with matching kernel headers |
| insmod blocked by module signing | Sign the LiME module with the kernel's signing key, or temporarily disable enforcement |
| insmod blocked by Secure Boot | LiME must be signed with a trusted key enrolled in Secure Boot DB |
| Incomplete dump | Retry acquisition; check available disk space; try network dump mode |
| /proc/kcore not readable | Expected on hardened systems; use LiME instead |
| System.map not found | Extract from kernel package or compile from kernel source |

### Handling the Memory Dump

- **Chain of custody**: Record SHA-256 hash immediately after acquisition
- **Transfer**: Use secure channel (SCP, SFTP) to move dump to forensic workstation
- **Storage**: Store dump on encrypted, access-controlled forensic storage
- **Do NOT analyze on the target system** — transfer to a clean forensic workstation
- **Proceed to**: `Linux_Memory_Vulnerability_Analysis_Agent_Playbook.md` (Phases 2-12)

---

## REFERENCES

- LiME (Linux Memory Extractor): https://github.com/504ensicslabs/LiME
- Volatility Framework: https://github.com/volatilityfoundation/volatility3
- The Art of Memory Forensics (Ligh, Case, Levy, Walters) — Chapter on Linux Memory Acquisition
- /proc/kcore documentation: https://www.kernel.org/doc/html/latest/filesystems/proc.html
- Linux kernel module signing: https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html
- RFC 3227 — Guidelines for Evidence Collection: https://www.rfc-editor.org/rfc/rfc3227

---

*End of Playbook — Version 1.0*
