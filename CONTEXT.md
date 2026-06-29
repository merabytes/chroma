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
│   1. Cache hit (key = "149.0.7827.116-arm64")
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

## Target offsets (Chrome 149.0.7827.116 arm64)

| Key | IDA address | Description | Status |
|-----|------------|-------------|--------|
| `devtools_start` | `sub_2ED62AC` | outer wrapper: GetBrowserContext + factory + Start | ✅ fixed in fec210d |
| `handler_vtable` | `unk_CF99820` | vtable for TCPServerSocketFactory (0x10 byte factory) | ✅ fixed in fec210d |
| `create_server_socket` | — | optional, not needed | skip |
| `op_new` | — | always from libc++ `_Znwm` via dlsym | ✅ |

---

## ARM64 root cause (solved in fec210d)

### The crash
`EXC_ARM_DA_ALIGN` / PAC auth failure at `0x84aed33800000001` in Thread 41 (injected dylib).

### Root cause
The scanner found `sub_2F93AAC` (= `DevToolsHttpHandler::Start`, the **inner** function) via
`DevToolsActivePort`/`Listening on` xrefs. The dylib passed the factory object as `X0=this` to
this function. Chrome immediately dereferenced it as a DevToolsHttpHandler vtable → PAC failure.

### Correct call chain (arm64)
```
sub_2ED5E58   ("remote-debugging-port" setup function)
  │  opnew(0x10) → fc
  │  ADRL X8, unk_CF99820  ; factory vtable
  │  STR  X8, [fc]
  │  STRH port, [fc,#8]
  │  MOV  W8, #0x2475
  │  STRH W8, [fc,#0xA]
  │  BL   sub_2ED62AC      ← THIS is devtools_start (outer wrapper)
  │
  └─▶ sub_2ED62AC(factory*, socket_name*, frontend*, flags=0)
        BL sub_1CA2970     ; GetBrowserContext()
        opnew(0x88)        ; alloc DevToolsHttpHandler
        BL sub_2ED641C(handler, browser_ctx, factory, sock, frontend, flags)
          └─▶ sub_2F93AAC  ; inner Start (the one we were calling wrong)
```

### Fix
- Static scanner (arm64, step 2b): scan `remote-debugging-port` → setup fn → find `MOV Wn,#0x2475`
  → next `BL` = outer wrapper. ADRP+ADD before `0x2475` = factory vtable.
- Frida JS scanner: same logic in the JS block.
- Dylib template: factory size `0x10` for arm64 (not `0x20`).

### Factory layout (arm64, 0x10 bytes)
```
[+0x00]  vtable ptr   (unk_CF99820, relative to slide)
[+0x08]  port uint16
[+0x0A]  flags 0x2475
[+0x0C]  padding
```

### dylib call (unchanged semantics)
```c
dstart(fc, sb, ab, 0);
// fc = factory (0x10 bytes, vtable+port+0x2475)
// sb = socket_name (0x20 bytes, zeroed = use default)
// ab = frontend   (0x50 bytes, zeroed = use default)
// 0  = flags
```

---

## Key constants / invariants

- **Chrome 149.0.7827.116 arm64** — current crashing version (was .104 in old cache)
- **Framework path**: `/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/149.0.7827.116/Google Chrome Framework`
- **Cache file**: `~/.chroma/offsets.json` — owned by root (sudo chroma), key `149.0.7827.116-arm64` not cached yet → will trigger rescan on first run
- **Frida installed**: `/opt/homebrew/lib/python3.11/site-packages/frida` (Homebrew)
- **`sudo python3`** uses system Python; `_import_frida()` adds Homebrew site-packages to `sys.path` automatically
- **CDP target port**: 9222 (default)
- **Verify**: `curl http://localhost:9222/json/version`

---

## How to run

```bash
sudo python3 ~/chroma/chroma.py
# Or with explicit scan to see diagnostics:
sudo python3 ~/chroma/chroma.py --scan
# Or manual override if scanner fails:
sudo python3 ~/chroma/chroma.py --offset devtools_start=0x2ED62AC --offset handler_vtable=0xCF99820
```

---

## Recent commits (newest first)

| Hash | Description |
|------|-------------|
| `fec210d` | **fix(arm64): correct devtools_start to outer wrapper via remote-debugging-port+0x2475 scan** |
| `19b7ae8` | fix(frida-scan): BigInt ADRP decode, proper error logging, NativePointer arithmetic |
| `798a269` | fix: JS toString(16) for hex offsets; auto-invalidate incomplete cache |
| `c7ac754` | fix(arm64): arch-filtered sigs, sudo frida path resolution, Frida live xref scanner |
| `23c4906` | fix: fat binary magic detection — fat header is BE, Mach-O slice is LE |
| `dfeb1aa` | refactor: version-agnostic offset discovery (string-xref + sig scan + cache) |
| `ad0882f` | feat: multi-backend activation (mach/lldb/frida) — Frida now optional |

---

## Second crash (solved in 9ec39d8)

### The crash
`EXC_BAD_ACCESS (SIGBUS) / EXC_ARM_DA_ALIGN` at `0x84aed33800000001` in Thread 43 (injected dylib).

### Root cause
On Apple Silicon (arm64/arm64e), `__DATA_CONST,__const` vtable entries are PAC-signed by dyld
at load time via `PACIA`. Writing the raw on-disk address into `fc[0]` bypasses PAC — when
`sub_2ED62AC` does `BLRAA x8, x0` the auth fails → PC = corrupted pointer with bit0=1.

On-disk value (chained fixup format, NOT a pointer): e.g. `0x004000000af9b970`  
Runtime value after dyld: PAC-signed absolute pointer (different bits, signed)

### Fix
Read the vtable pointer from live process memory (already resolved + PAC-signed by dyld):
- **Frida**: `fc.writePointer(ptr(rt.handler_vtable).readPointer())`  
- **Mach dylib**: `*(void**)fc = **(void***)<addr>`

### Cache
`~/.chroma/offsets.json` was manually cleared. On next run it will rescan for `.116-arm64`.

### Backend order (arm64)
`auto` on arm64 now tries: `frida → lldb → mach`  
Mach is broken on arm64 for two reasons (LDR literal encodings wrong, PAC on __DATA_CONST).  
Frida is the original working method — NativeFunction calls over WebSocket, no injected code.

---

## Immediate next step

Run `sudo python3 chroma.py --scan` and verify:

```
[chroma/scan] arm64: searching for outer DevTools wrapper via 'remote-debugging-port' ...
[chroma/scan]   remote-debugging-port: setup fn at 0x2ed5e58
[chroma/scan]   → arm64 factory vtable (via 0x2475 scan): 0xcf99820
[chroma/scan]   → arm64 outer wrapper (via 0x2475+BL): 0x2ed62ac
```

Then verify CDP is alive: `curl http://localhost:9222/json/version`
