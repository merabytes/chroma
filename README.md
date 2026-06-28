# chroma

> **Runtime activation of Chrome DevTools Protocol (CDP) on a live, fully-stripped Chrome process — no restart required.**

```
$ python3 chroma.py
[chroma] attaching to PID 89638…
[chroma] module base = 0x130c27000
[chroma] ASLR slide  = 0x130326f7b
[chroma] createSocket(9222) -> 1
[chroma] DevToolsHttpHandler::Start called — CDP should be up on port 9222

[chroma] ✅ CDP active!
  Browser : Chrome/149.0.7827.103
  WS URL  : ws://localhost:9222/devtools/browser/ae25cd80-5106-4fcd-b45c-6ce8ace18289
```

---

## What this does

Chrome exposes its [DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/) only when launched with `--remote-debugging-port=<N>`. If it wasn't started with that flag, you get nothing on port 9222.

**chroma** uses [Frida](https://frida.re) to locate the internal `DevToolsHttpHandler::Start` function inside a live, fully-stripped Chrome binary and calls it directly — activating CDP without restarting the browser, without losing any open tabs or session state, and without touching the filesystem.

Tested on:
- Chrome **149.0.7827.103** / macOS 13 (x86_64)
- Frida **17.x**

---

## Background: the debugging journey

This tool didn't come from documentation — it came from about 3 hours of blind reverse engineering on a stripped binary. Here's the full process, decision by decision.

### 1. Recon: what does Chrome expose?

The first question is always: *does this binary export anything useful?*

```python
import frida
session = frida.attach(pid)
script = session.create_script("""
Process.enumerateModules().forEach(mod => {
    mod.enumerateExports().forEach(exp => {
        if (exp.name.toLowerCase().includes('devtools'))
            console.log(mod.name, exp.name, exp.address);
    });
});
""")
```

**Result: zero exports.** Chrome's production macOS binary is fully stripped. No symbols, no debug info. This rules out the easy path of `Module.findExportByName()`.

### 2. String hunting via the FAT binary on disk

The next step is finding any string that could anchor us to the right code. The target: `"DevTools listening on ws:"` — the string Chrome prints to stdout when CDP is active.

The key insight here is that Chrome's macOS build is a **FAT binary** (contains both x86_64 and arm64 slices). Frida's `Memory.scanSync` on a 230MB module is unreliable and slow. Instead, we parse the binary on disk:

```python
import struct, glob, numpy as np

paths = glob.glob("/Applications/Google Chrome.app/Contents/Frameworks/"
                  "Google Chrome Framework.framework/Versions/*/"
                  "Google Chrome Framework")
with open(paths[0], 'rb') as f:
    data = f.read()

# Parse FAT header → find x86_64 slice
narch = struct.unpack('>I', data[4:8])[0]
for i in range(narch):
    cputype, _, offset, fsize, _ = struct.unpack('>5I', data[8+i*20:8+i*20+20])
    if cputype == 0x01000007:  # x86_64
        slice_off, slice_sz = offset, fsize
        break

# Get section offsets — sfoff is ABSOLUTE from start of FAT file
# (critical: do NOT add slice_off to sfoff values)
vm_base   = struct.unpack_from('<Q', data, slice_off + 24)[0]
# ... parse LC_SEGMENT_64 → __TEXT,__cstring ...

# Scan for the string
cstring_data = data[cstring_foff : cstring_foff + cstring_sz]
idx = cstring_data.find(b"DevTools listening on ws:")
str_vm = cstring_va + idx
```

> **Pitfall #1:** On Chrome 149 macOS, `sfoff` values in the Mach-O section headers are **absolute file offsets** — they already account for the FAT header. Adding `slice_off` on top is a classic mistake that shifts all addresses by ~0x4000 and produces zero scan hits. Found this the hard way after 45 minutes.

> **Pitfall #2:** `lipo -extract x86_64` produces a **thin binary** with different file offsets than the in-memory layout. Never use the thin binary for offset calculations — always work from the original FAT binary with absolute `sfoff` values.

### 3. Finding the xref with numpy

We have the string's VM address. Now we need to find the code that references it — a `LEA RIP+disp32, [string]` instruction somewhere in `__TEXT,__text`.

Pure Python scan of 207MB → **timeout at ~120 seconds**. Solution: numpy vectorization.

```python
text_np = np.frombuffer(data[text_foff : text_foff + text_sz], dtype=np.uint8)
N = len(text_np)

# Mask for LEA/MOV [RIP+disp32] instruction patterns:
# REX (48/4C) + opcode (8D/8B) + ModRM where (byte & 0xC7) == 0x05
b0 = text_np[:N-7]; b1 = text_np[1:N-6]; b2 = text_np[2:N-5]
mask = (np.isin(b0, [0x48, 0x4C])) & \
       (np.isin(b1, [0x8D, 0x8B])) & \
       ((b2 & 0xC7) == 0x05)

candidates = np.where(mask)[0]
# ~0.1% of positions — now check the displacement for each
for i in candidates:
    disp = struct.unpack_from('<i', text_np[i+3:i+7].tobytes())[0]
    ins_vm = text_va + int(i)
    if ins_vm + 7 + disp == str_vm:
        print(f"Hit at 0x{ins_vm + slide:x}")
```

This found **one hit** in under 3 seconds. The xref pointed to a function at `0x133a8e8c3` (post-ASLR).

### 4. Mapping the control flow

With the xref hit in hand, we disassemble backwards to find the function entry point and understand the full control flow:

```
0x133a8e600  ← function start (prologue: push rbp; mov rbp, rsp)
  │
  ├─ 0x133a8e645: call DevToolsPortProvider  → returns suggested port in eax
  ├─ 0x133a8e6bd: call HasSwitch("remote-debugging-pipe")
  │     └─ if true → 0x133a8ea0e (pipe path, irrelevant)
  ├─ 0x133a8e6f5: call GetSwitchValueASCII("remote-debugging-port") → port string
  ├─ 0x133a8e722: call StringToUint → parse port string → r15d
  ├─ 0x133a8e752: test r15d, r15d
  │     └─ if r15d == 0: call CreateServerSocket(0x3e9=1001, &socket_buf)
  ├─ 0x133a8e774: call HasSwitch("custom-devtools-frontend")  ← THIS is the check at 0x783
  │     └─ if false → fall through
  ├─ 0x133a8e7ba: alloc 0x10 bytes (factory object)
  │     vtable   = 0x13f1710e8
  │     port     = r15w
  │     field    = 0x2475
  ├─ 0x133a8e7e6: call DevToolsHttpHandler::Start (0x133a8eb10)
  └─ 0x133a8e888: int3; ud2  ← DCHECK assert (refcount overflow guard)
```

The `int3` at `0x133a8e888` caused the first few call attempts to crash. It's a Chromium `DCHECK` — an assert that fires when an `xadd` on a refcount hits `0x7FFFFFFF`. Our early attempts were hitting this because we were calling the function with invalid object pointers.

### 5. Identifying `DevToolsHttpHandler::Start`

The function at `0x133a8eb10` is the real activation point. Its disassembly:

```asm
0x133a8eb10: push rbp
0x133a8eb11: mov rbp, rsp
; ... callee-save registers ...
0x133a8eb2a: call 0x1322b7c30        ; get current task runner
0x133a8eb2f: mov rbx, [rax + 8]      ; task_runner->task_queue
0x133a8eb33: test rbx, rbx
0x133a8eb36: je 0x133a8ec25          ; bail if no task runner
0x133a8eb3c: mov edi, 0x88
0x133a8eb41: call 0x130c2e410        ; operator new(0x88) → handler wrapper
0x133a8eb4c: mov rdi, rax
; rsi=rbx(queue), rdx=r13(factory), rcx=r12(socket), r8=r15(addr), r9d=r14d(flags)
0x133a8eb5c: call 0x133a8ec60        ; DevToolsHttpHandler constructor
```

**Signature:**
```c
void DevToolsHttpHandlerStart(
    DevToolsHttpHandlerFactory* factory,  // rdi
    std::string* socket_name,             // rsi
    std::string* addr,                    // rdx
    uint32_t flags                        // rcx
);
```

### 6. Building the factory object

The factory object is 0x10 bytes:

| Offset | Size | Value | Meaning |
|--------|------|-------|---------|
| `+0x0` | 8 | `0x13f1710e8` | vtable pointer (TCPServerSocketFactory) |
| `+0x8` | 2 | `9222` | port hint |
| `+0xA` | 2 | `0x2475` | internal field (9333 dec — fallback port) |

This was extracted directly from the disasm of `0x133a8e7ba`–`0x133a8e7e1`.

### 7. The actual call

```python
JS = """
var opNew         = new NativeFunction(ptr('0x130c2e410'), 'pointer', ['uint32']);
var createSocket  = new NativeFunction(ptr('0x131f3da20'), 'uint8',   ['uint32', 'pointer']);
var devtoolsStart = new NativeFunction(ptr('0x133a8eb10'), 'void',    ['pointer', 'pointer', 'pointer', 'uint32']);

var socketBuf = opNew(0x20); socketBuf.writeByteArray(new Array(0x20).fill(0));
var addrBuf   = opNew(0x50); addrBuf.writeByteArray(new Array(0x50).fill(0));

createSocket(9222, socketBuf);

var factory = opNew(0x10); factory.writeByteArray(new Array(0x10).fill(0));
factory.writePointer(ptr('0x13f1710e8'));
factory.add(8).writeU16(9222);
factory.add(0xa).writeU16(0x2475);

devtoolsStart(factory, socketBuf, addrBuf, 0);
"""
```

After calling this, `curl http://localhost:9222/json/version` returns:

```json
{
  "Browser": "Chrome/149.0.7827.103",
  "webSocketDebuggerUrl": "ws://localhost:9222/devtools/browser/ae25cd80-..."
}
```

### 8. Things that didn't work

| Attempt | Why it failed |
|---|---|
| `JSRemoteInspectorStart()` | Activates WebKit remote inspector (Safari protocol), not Chrome CDP |
| Hooking `HasSwitch()` to fake `--remote-debugging-port` | Startup checks already ran; function isn't called again during runtime |
| Calling `0x133a8e600` directly | Single caller thunk, never invoked post-startup; needs a valid `ContentBrowserClient*` |
| Patching `jne → jmp` at the `HasSwitch` check | The function doesn't run at all unless triggered from its call site |
| `Memory.scanSync` with wildcards | Frida 17 broke wildcard patterns (`?? ??` syntax) — use exact bytes only |
| In-memory string scan for `--remote-debugging-port` | Stripped from `__cstring` section in Chrome 149 production builds |
| `lipo -extract` + offset math | Thin binary has different file offsets than the FAT runtime layout |

---

## Requirements

```
frida >= 17.0
frida-tools
numpy
Python >= 3.11
macOS 13+ (x86_64)
Chrome 149 (other versions need offset re-derivation — see scripts/)
```

Install:
```bash
pip3 install frida frida-tools numpy
```

---

## Usage

```bash
# Default: port 9222, auto-detect Chrome PID
python3 chroma.py

# Custom port
python3 chroma.py 9223

# Explicit PID
python3 chroma.py 9222 89638

# Verify manually
curl http://localhost:9222/json/version
curl http://localhost:9222/json        # list all tabs
```

---

## Porting to other Chrome versions

The four addresses in `OFFSETS_149` need to be re-derived for each new Chrome build.

**Method:**

1. Find the `"DevTools listening on ws:"` string in `__TEXT,__cstring` (on-disk FAT binary)
2. Numpy-scan `__TEXT,__text` for `LEA RIP+disp32` pointing to that string
3. Disassemble backwards from the hit to the function prologue (`push rbp; mov rbp, rsp`)
4. Identify `CreateServerSocket` (called with `edi=0x3e9`), `DevToolsHttpHandler::Start`, and `operator new`
5. Extract the vtable pointer from the `lea rcx, [rip+...]` instruction before the factory alloc

Helper scripts are in `scripts/`:

| Script | Purpose |
|---|---|
| `scripts/find_string.py` | Locate any cstring in the FAT binary |
| `scripts/xref_scan.py` | Numpy xref scan for a given VM address |
| `scripts/disasm_fn.py` | Frida-based disassembler for a given runtime address |
| `scripts/scan_callers.py` | Find all CALL rel32 instructions targeting an address |

---

## Security note

This technique requires attaching to a running process with Frida. On macOS, Chrome is **not** SIP-protected and does **not** use `com.apple.security.cs.disable-library-validation` deny, so Frida can attach without SIP disable. Test with:

```bash
frida -p $(pgrep "Google Chrome") -e "console.log('attached')"
```

Once CDP is active, it is **unauthenticated** — any local process can connect. Bind a firewall rule or use `--remote-debugging-address` to limit exposure.

---

## License

MIT
