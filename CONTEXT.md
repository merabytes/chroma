# chroma — Context for ARM64 adaptation

## What is chroma?

Runtime CDP (Chrome DevTools Protocol) activator for macOS Chrome processes launched **without** `--remote-debugging-port`. Injects the DevTools HTTP handler into a live, fully-stripped Chrome process.

Repo: `https://github.com/merabytes/chroma`  
Local: `~/chroma/chroma.py`

---

## Architecture overview

```
chroma.py
├── Offset discovery (per Chrome version+arch, cached in ~/.chroma/offsets.json)
│   1. Cache hit (key = "149.0.7827.104-arm64")
│   2. Static scan: ADRP xref scanner + signature scan (arch-filtered)
│   3. Frida live scan: _frida_scan_offsets() — scans running process memory
│   4. Manual: --offset key=0xVALUE
│
├── Injection backends (tried in order: mach → lldb → frida)
│   mach:  Python ctypes + Mach task APIs. Compiles dylib on-the-fly, injects via
│          thread_create_running(). No external deps beyond cc (Xcode CLT).
│   lldb:  lldb --batch + expr commands. Ships with Xcode CLT.
│   frida: pip install frida fallback.
│
└── Verification: GET http://localhost:9222/json/version
```

---

## Target offsets needed (relative to framework vm_base, ASLR-independent)

| Key | Description | Status x86_64 | Status arm64 |
|-----|-------------|---------------|--------------|
| `devtools_start` | `DevToolsHttpHandler::Start(factory*, socket*, addr*, flags)` | ✅ found via sig | ❌ not found yet |
| `handler_vtable` | vtable ptr for `TCPServerSocketFactory` | ✅ found via RTTI | ❌ not found yet |
| `create_server_socket` | optional — creates TCP socket | ✅ | ⚠️ false positive (0x7690 is wrong) |
| `op_new` | `operator new` — always from libc++ `_Znwm`, never a Chrome offset | ✅ | ✅ |

**`op_new` is always resolved at runtime via `dlsym(RTLD_DEFAULT, "_Znwm")` — no offset needed.**

---

## ARM64 specific problems & current state

### 1. vm_base = 0x0
The arm64 slice of the framework has `__TEXT vmaddr = 0x0` (PIE/position-independent).  
All offsets are relative to 0x0, so `rel = fn_va - 0 = fn_va`. This is correct behavior — the slide is the full runtime base address.

### 2. Static ADRP scanner not finding devtools_start
Chrome arm64 uses `ADRP + LDR` (load from GOT) rather than `ADRP + ADD` for string references. The static scanner's `_arm64_adrp_refs()` function walks backwards from string file-offsets and looks for ADRP instructions, but:
- The 4K page alignment math had 32-bit overflow bugs (now fixed with file-offset arithmetic)
- `DevToolsActivePort` and `Listening on ` may be in `__TEXT,__cstring` but referenced from a far section

### 3. Frida live scanner
`_frida_scan_offsets()` is the most reliable path for arm64. It:
- Finds the string in live memory via `Memory.scanSync()`
- Scans 4MB of code before the string for ADRP instructions (BigInt arithmetic to avoid 32-bit overflow)
- Walks backwards to find function prologue: `STP x29,x30,[sp,#-N]!` (FD 7B ?? A9) or PACIBSP/PACIASP
- Returns offsets as hex strings relative to module base

**Current bug being debugged**: Frida scanner runs but `devtools_start` still not found. The diagnostic output (`[chroma/frida-scan] diagnostics:`) was added in commit `58c0943` — output not yet seen from user.

### 4. Signature database (arm64)
Stored in `SIGNATURES` dict with `(milestone_range, hex_pattern, arch)` tuples.  
Current arm64 entries are **placeholders** — need real bytes from the binary:
```python
# These need to be verified/replaced with actual bytes from Chrome 149 arm64:
((120, 149), "fd 7b ?? a9 f4 ?? ?? a9 f6 ?? ?? a9 fd ?? ?? 91 f4 03 00 aa", "arm64"),  # create_server_socket
((120, 149), "fd 7b ?? a9 f4 ?? ?? a9 f6 ?? ?? a9 f8 ?? ?? a9 fd ?? ?? 91 f4 03 00 aa f5 03 01 aa", "arm64"),  # devtools_start
```

---

## How to derive the correct arm64 offsets manually

### Option A — otool + strings (offline)
```bash
FW="/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/149.0.7827.104/Google Chrome Framework"

# Find DevToolsActivePort string offset
otool -arch arm64 -s __TEXT __cstring "$FW" | grep -b "DevToolsActivePort"

# Disassemble around a candidate function
otool -arch arm64 -tV "$FW" | grep -A 40 "DevToolsActivePort"
```

### Option B — lldb offline (no inject, just inspect)
```bash
lldb "$FW"
(lldb) image dump symtab  # if symbols exist (they don't in stripped builds)
(lldb) memory find -s "DevToolsActivePort" -- 0x100000000 0x200000000
```

### Option C — Frida on running Chrome (best)
```bash
sudo frida -p $(pgrep -x "Google Chrome") -e "
var mod = Process.getModuleByName('Google Chrome Framework');
var m = Memory.scanSync(mod.base, mod.size, '44 65 76 54 6f 6f 6c 73 41 63 74 69 76 65 50 6f 72 74');
m.forEach(function(x) { console.log('string at:', x.address, 'offset:', x.address.sub(mod.base)); });
"
# Then find ADRP xrefs to that address manually
```

### Option D — Supply manually
```bash
sudo python3 chroma.py \
  --offset devtools_start=0xXXXXXXX \
  --offset handler_vtable=0xYYYYYYY
```

---

## Key constants / invariants

- **Chrome 149.0.7827.104 arm64** — PID typically 643 (changes on restart)
- **Framework path**: `/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/149.0.7827.104/Google Chrome Framework`
- **Cache file**: `~/.chroma/offsets.json` — delete to force rescan
- **Frida installed**: `/opt/homebrew/lib/python3.11/site-packages/frida` (Homebrew)
- **`sudo python3`** uses system Python; `_import_frida()` adds Homebrew site-packages to `sys.path` automatically
- **CDP target port**: 9222 (default)
- **Verify**: `curl http://localhost:9222/json/version`

---

## Activation flow (what happens when offsets are found)

```c
// Compiled into a .dylib, injected via dlopen() from a Mach thread:
void* opnew  = _Znwm;                          // from libc++
void* dstart = base + offsets["devtools_start"]; // ASLR-adjusted

void* sb = opnew(0x20); memset(sb, 0, 0x20);   // socket name buffer
void* ab = opnew(0x50); memset(ab, 0, 0x50);   // addr buffer
void* fc = opnew(0x20); memset(fc, 0, 0x20);   // factory object
*(void**)fc        = base + offsets["handler_vtable"];
((uint16_t*)fc)[4] = 9222;    // port
((uint16_t*)fc)[5] = 0x2475;  // flags

// create_server_socket is optional — skip if offset unknown
dstart(fc, sb, ab, 0);         // DevToolsHttpHandler::Start
```

---

## Recent commits (newest first)

| Hash | Description |
|------|-------------|
| `58c0943` | fix(frida-scan): BigInt ADRP decode, proper error logging, NativePointer arithmetic |
| `798a269` | fix: JS toString(16) for hex offsets; auto-invalidate incomplete cache |
| `c7ac754` | fix(arm64): arch-filtered sigs, sudo frida path resolution, Frida live xref scanner |
| `23c4906` | fix: fat binary magic detection — fat header is BE, Mach-O slice is LE |
| `dfeb1aa` | refactor: version-agnostic offset discovery (string-xref + sig scan + cache) |
| `ad0882f` | feat: multi-backend activation (mach/lldb/frida) — Frida now optional |

---

## Immediate next step

Run `sudo python3 chroma.py --scan` and capture the full output.  
The Frida scanner now prints diagnostics — the key line to look for:

```
[chroma/frida-scan] diagnostics:
  devtools_start[DevToolsActivePort]: string not found in memory   ← means string IS in memory but ADRP xref not found
  devtools_start[DevToolsActivePort]: ADRP xref not found in 4MB window before string  ← window too small or wrong section
  devtools_start[DevToolsActivePort]: found at 0xXXXXXX (xref from 0xYYYYYY)  ← SUCCESS
```

If the string is found but no ADRP xref: the reference may be a **LDR from literal pool** (arm64 alternative to ADRP+ADD for nearby constants). The fix would be to also scan for `LDR Xn, [PC, #imm]` (encoding: `xx xx xx 58`).
