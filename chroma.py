#!/usr/bin/env python3
"""
chroma.py — Runtime CDP activation for Chrome (Frida-independent)

Activates Chrome DevTools Protocol on a live, fully-stripped Chrome process
without --remote-debugging-port at launch.

Backends (tried in order unless --backend is specified):
  mach    — Pure Python + ctypes + Mach task APIs. Compiles a minimal dylib
             on-the-fly and injects it via thread_create_running. No external
             tools required beyond a C compiler (cc, always available on macOS).
  lldb    — Uses lldb CLI (ships with Xcode Command Line Tools) to call
             DevToolsHttpHandler::Start directly inside the target process.
  frida   — Original approach via the Frida dynamic instrumentation toolkit.

Usage:
  python3 chroma.py [port] [pid] [--backend mach|lldb|frida]

Author: Merabytes
Target: Chrome 149 (macOS x86_64, fully stripped binary)
"""

import argparse
import ctypes
import ctypes.util
import glob
import os
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

# ── Known offsets for Chrome 149.0.7827.103 x86_64 macOS ────────────────────
#
# These are on-disk VM addresses (pre-ASLR).
# At runtime: runtime_addr = vm_addr + slide
# See scripts/ for how to re-derive these for a different Chrome version.

OFFSETS_149 = {
    # bool CreateServerSocket(uint32_t port_hint, std::string* socket_name_out)
    "create_server_socket": 0x00EF8A45,   # relative to vm_base

    # void DevToolsHttpHandlerStart(factory*, socket_str*, addr_str*, uint32_t flags)
    "devtools_start":       0x01101A35,

    # vtable for TCPServerSocketFactory (DevToolsHttpHandlerFactory impl)
    "handler_vtable":       0x02E4A111,

    # void* operator new(size_t)
    "op_new":               0x00001415,
}

# vm_base of __TEXT segment in the x86_64 slice (constant for a given build)
# Derived from: struct.unpack_from('<Q', fat_binary, slice_off+0x18+0x18)[0]
# (the vmaddr field of the first LC_SEGMENT_64 command)
_VM_BASE_149 = 0x130901529   # override in compute_slide() at runtime


# ── Utilities ────────────────────────────────────────────────────────────────

def get_chrome_pid() -> int:
    out = subprocess.check_output(["pgrep", "-x", "Google Chrome"], text=True).strip()
    pids = sorted(int(p) for p in out.splitlines())
    if not pids:
        raise RuntimeError("Chrome process not found (is Chrome running?)")
    return pids[0]


def get_framework_path() -> str:
    paths = glob.glob(
        "/Applications/Google Chrome.app/Contents/Frameworks/"
        "Google Chrome Framework.framework/Versions/*/"
        "Google Chrome Framework"
    )
    if not paths:
        raise FileNotFoundError("Google Chrome Framework binary not found")
    return paths[0]


def compute_slide(runtime_base: int) -> int:
    """Compute ASLR slide: runtime_base − on-disk vm_base."""
    fw = get_framework_path()
    with open(fw, "rb") as f:
        data = f.read()

    narch = struct.unpack(">I", data[4:8])[0]
    for i in range(narch):
        cputype, _, offset, _, _ = struct.unpack(">5I", data[8 + i * 20: 8 + i * 20 + 20])
        if cputype != 0x01000007:   # x86_64
            continue
        # Walk LC_SEGMENT_64 commands to find the first one (vmaddr = vm_base)
        off = offset + 32           # skip Mach-O 64-bit header (32 bytes)
        ncmds = struct.unpack_from("<I", data, offset + 16)[0]
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmd == 0x19:         # LC_SEGMENT_64
                vm_base = struct.unpack_from("<Q", data, off + 24)[0]
                return runtime_base - vm_base
            off += cmdsize
    raise RuntimeError("Could not compute ASLR slide from on-disk binary")


def runtime_offsets(base: int) -> dict:
    slide = compute_slide(base)
    return {k: v + slide for k, v in OFFSETS_149.items()}


def verify(port: int) -> dict | None:
    try:
        with urllib.request.urlopen(f"http://localhost:{port}/json/version", timeout=4) as r:
            import json
            return json.loads(r.read())
    except Exception:
        return None


# ── Backend: Mach task APIs + compiled dylib ─────────────────────────────────
#
# Strategy:
#   1. Compute the ASLR slide from /proc/pid/maps equivalent (vm_region scan)
#      → actually we read it from the running process's module list via task APIs
#   2. Compile a minimal C dylib with the activation code (baked-in runtime addrs)
#   3. Allocate memory in the target, write shellcode that calls dlopen(dylib, RTLD_NOW)
#   4. Spawn a Mach thread at the shellcode via thread_create_running()
#
# Key insight: macOS dyld shared cache is mapped at the same address in ALL
# processes (it's randomized once at boot). So dlopen()'s address in our process
# is valid in the target process too.

def activate_mach(pid: int, port: int = 9222) -> bool:
    """Inject a compiled activation dylib via Mach task APIs (no external tools)."""

    # ── 1. Get module base from target via vm_region scan ────────────────────
    base = _get_framework_base_mach(pid)
    print(f"[chroma/mach] framework base = 0x{base:x}")
    rt = runtime_offsets(base)
    print(f"[chroma/mach] slide = 0x{compute_slide(base):x}")

    # ── 2. Compile activation dylib ──────────────────────────────────────────
    src = _build_activation_source(rt, port)
    dylib_path = _compile_dylib(src)
    print(f"[chroma/mach] dylib compiled → {dylib_path}")

    # ── 3. Inject via Mach thread ────────────────────────────────────────────
    _mach_dlopen(pid, dylib_path)
    print(f"[chroma/mach] injection thread started")

    # ── 4. Verify ────────────────────────────────────────────────────────────
    for _ in range(8):
        time.sleep(0.5)
        info = verify(port)
        if info:
            return True
    return False


def _get_framework_base_mach(pid: int) -> int:
    """Walk the target's Mach VM map to find Google Chrome Framework's base."""
    import ctypes as C
    from ctypes import c_int, c_uint, c_uint32, c_uint64, byref, POINTER

    lib = C.CDLL("/usr/lib/libSystem.B.dylib")

    mach_port_t         = c_uint
    kern_return_t       = c_int
    mach_vm_address_t   = c_uint64
    mach_vm_size_t      = c_uint64

    # task_for_pid
    tfp = lib.task_for_pid
    tfp.restype  = kern_return_t
    tfp.argtypes = [mach_port_t, c_int, POINTER(mach_port_t)]

    mts = lib.mach_task_self
    mts.restype = mach_port_t

    # vm_region_64  (simplified — reads region info to find dylib paths)
    # We use proc_regionfilename via libproc as a simpler alternative
    libproc = C.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    proc_regionfilename = libproc.proc_regionfilename
    proc_regionfilename.restype  = c_int
    proc_regionfilename.argtypes = [c_int, c_uint64, C.c_char_p, c_uint32]

    buf    = C.create_string_buffer(4096)
    addr   = 0
    step   = 0x1000

    while addr < 0x7FFFFFFFFFFF:
        ret = proc_regionfilename(pid, addr, buf, 4096)
        if ret > 0:
            path = buf.value.decode(errors="replace")
            if "Google Chrome Framework" in path:
                # Back up to find the region start — read via mach_vm_region
                return _mach_region_start(lib, pid, addr)
        addr += step
        step = min(step * 2, 0x100000)

    raise RuntimeError("Google Chrome Framework not found in target vm map")


def _mach_region_start(lib, pid: int, hint: int) -> int:
    """Find the actual region start address for a hint address."""
    import ctypes as C
    from ctypes import c_int, c_uint, c_uint64, c_uint32, byref

    mach_port_t       = c_uint
    kern_return_t     = c_int
    mach_vm_address_t = c_uint64
    mach_vm_size_t    = c_uint64

    tfp = lib.task_for_pid
    tfp.restype  = kern_return_t
    tfp.argtypes = [c_uint, c_int, C.POINTER(c_uint)]

    task = c_uint(0)
    ret  = tfp(lib.mach_task_self(), pid, byref(task))
    if ret != 0:
        raise PermissionError(
            f"task_for_pid({pid}) failed with kern_return={ret}. "
            "Run as root or ensure SIP is configured to allow task_for_pid."
        )

    mach_vm_region_recurse = lib.mach_vm_region_recurse
    mach_vm_region_recurse.restype = kern_return_t

    # vm_region_submap_short_info_64 is 20 uint32s
    INFO_COUNT = 20
    addr   = mach_vm_address_t(hint)
    size   = mach_vm_size_t(0)
    depth  = c_uint32(99)
    info   = (c_uint32 * INFO_COUNT)()
    count  = c_uint32(INFO_COUNT)

    mach_vm_region_recurse.argtypes = [
        c_uint,
        C.POINTER(mach_vm_address_t), C.POINTER(mach_vm_size_t),
        C.POINTER(c_uint32),
        C.POINTER(c_uint32 * INFO_COUNT),
        C.POINTER(c_uint32),
    ]
    mach_vm_region_recurse(task, byref(addr), byref(size), byref(depth), byref(info), byref(count))
    return int(addr.value)


def _build_activation_source(rt: dict, port: int) -> str:
    return f"""\
#include <stdint.h>
#include <string.h>

__attribute__((constructor))
static void _chroma_activate(void) {{
    typedef void*    (*opnew_t) (size_t);
    typedef uint8_t  (*csock_t) (uint32_t, void*);
    typedef void     (*dstart_t)(void*, void*, void*, uint32_t);

    opnew_t  opnew  = (opnew_t) {rt['op_new']:#x}ULL;
    csock_t  csock  = (csock_t) {rt['create_server_socket']:#x}ULL;
    dstart_t dstart = (dstart_t){rt['devtools_start']:#x}ULL;
    void*    vtbl   = (void*)   {rt['handler_vtable']:#x}ULL;

    void* sb = opnew(0x20); memset(sb, 0, 0x20);
    void* ab = opnew(0x50); memset(ab, 0, 0x50);
    void* fc = opnew(0x10); memset(fc, 0, 0x10);
    *(void**)fc           = vtbl;
    ((uint16_t*)fc)[4]    = {port};
    ((uint16_t*)fc)[5]    = 0x2475;

    csock({port}, sb);
    dstart(fc, sb, ab, 0);
}}
"""


def _compile_dylib(src: str) -> str:
    tmpdir = tempfile.mkdtemp(prefix="chroma_")
    src_path   = os.path.join(tmpdir, "activate.c")
    dylib_path = os.path.join(tmpdir, "activate.dylib")
    with open(src_path, "w") as f:
        f.write(src)
    r = subprocess.run(
        ["cc", "-dynamiclib", "-arch", "x86_64",
         "-O0", "-o", dylib_path, src_path],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"Compilation failed:\n{r.stderr}")
    return dylib_path


def _mach_dlopen(pid: int, dylib_path: str):
    """
    Inject dylib_path into process pid by:
      1. Allocating RW memory → write the path string
      2. Allocating RX memory → write dlopen shellcode
      3. thread_create_running() pointing RIP at the shellcode
    """
    import ctypes as C
    from ctypes import c_int, c_uint, c_uint32, c_uint64, c_void_p, byref, POINTER

    lib = C.CDLL("/usr/lib/libSystem.B.dylib")

    mach_port_t         = c_uint
    kern_return_t       = c_int
    mach_vm_address_t   = c_uint64
    mach_vm_size_t      = c_uint64

    VM_FLAGS_ANYWHERE  = 1
    VM_PROT_READ       = 1
    VM_PROT_WRITE      = 2
    VM_PROT_EXEC       = 4

    # ── Mach API bindings ────────────────────────────────────────────────────
    tfp = lib.task_for_pid
    tfp.restype  = kern_return_t
    tfp.argtypes = [mach_port_t, c_int, POINTER(mach_port_t)]

    alloc = lib.mach_vm_allocate
    alloc.restype  = kern_return_t
    alloc.argtypes = [mach_port_t, POINTER(mach_vm_address_t), mach_vm_size_t, c_int]

    write = lib.mach_vm_write
    write.restype  = kern_return_t
    write.argtypes = [mach_port_t, mach_vm_address_t, c_void_p, c_uint32]

    protect = lib.mach_vm_protect
    protect.restype  = kern_return_t
    protect.argtypes = [mach_port_t, mach_vm_address_t, mach_vm_size_t, c_int, c_int]

    tcr = lib.thread_create_running
    tcr.restype  = kern_return_t

    # ── Get task port ────────────────────────────────────────────────────────
    task = mach_port_t(0)
    ret = tfp(lib.mach_task_self(), pid, byref(task))
    if ret != 0:
        raise PermissionError(
            f"task_for_pid({pid}) → kern_return={ret}. "
            "Need root or task_for_pid entitlement."
        )

    def _alloc_write(data: bytes, prot: int) -> int:
        addr = mach_vm_address_t(0)
        sz   = (len(data) + 0xFFF) & ~0xFFF
        ret = alloc(task, byref(addr), sz, VM_FLAGS_ANYWHERE)
        if ret: raise RuntimeError(f"mach_vm_allocate failed: {ret}")
        buf = C.create_string_buffer(data)
        ret = write(task, addr, buf, len(data))
        if ret: raise RuntimeError(f"mach_vm_write failed: {ret}")
        ret = protect(task, addr, sz, 0, prot)
        if ret: raise RuntimeError(f"mach_vm_protect failed: {ret}")
        return int(addr.value)

    # ── Write dylib path ─────────────────────────────────────────────────────
    path_bytes = dylib_path.encode() + b"\x00"
    path_addr  = _alloc_write(path_bytes, VM_PROT_READ)

    # ── Resolve dlopen + pthread_exit from our own process ───────────────────
    # macOS dyld shared cache is mapped at the SAME address in all processes
    # (randomised once at boot, shared across all). Reading from our process
    # gives a valid address for the target.
    _libdl  = C.CDLL(ctypes.util.find_library("dl")  or "/usr/lib/libdl.dylib")
    _libpth = C.CDLL(ctypes.util.find_library("pthread") or "/usr/lib/libpthread.dylib")

    dlopen_addr       = C.cast(_libdl.dlopen,         c_void_p).value
    pthread_exit_addr = C.cast(_libpth.pthread_exit,   c_void_p).value

    if not dlopen_addr or not pthread_exit_addr:
        raise RuntimeError("Could not resolve dlopen / pthread_exit addresses")

    # ── Build shellcode ──────────────────────────────────────────────────────
    #
    # x86_64, System V ABI:
    #   sub  rsp, 8                 ; 16-byte align
    #   mov  rdi, <path_addr>       ; arg1 = dylib path
    #   mov  esi, 2                 ; arg2 = RTLD_NOW
    #   mov  rax, <dlopen_addr>
    #   call rax
    #   xor  edi, edi               ; exit code 0
    #   mov  rax, <pthread_exit>
    #   call rax                    ; never returns
    sc  = b"\x48\x83\xec\x08"                               # sub rsp, 8
    sc += b"\x48\xbf" + struct.pack("<Q", path_addr)        # mov rdi, imm64
    sc += b"\xbe\x02\x00\x00\x00"                           # mov esi, 2
    sc += b"\x48\xb8" + struct.pack("<Q", dlopen_addr)      # mov rax, imm64
    sc += b"\xff\xd0"                                        # call rax
    sc += b"\x31\xff"                                        # xor edi, edi
    sc += b"\x48\xb8" + struct.pack("<Q", pthread_exit_addr)# mov rax, imm64
    sc += b"\xff\xd0"                                        # call rax

    sc_addr = _alloc_write(sc, VM_PROT_READ | VM_PROT_EXEC)

    # ── Allocate a stack ─────────────────────────────────────────────────────
    STACK_SIZE = 0x20000
    stk_base   = mach_vm_address_t(0)
    alloc(task, byref(stk_base), STACK_SIZE, VM_FLAGS_ANYWHERE)
    protect(task, stk_base, STACK_SIZE, 0, VM_PROT_READ | VM_PROT_WRITE)
    rsp_val = int(stk_base.value) + STACK_SIZE - 8   # top of stack, 8-byte aligned

    # ── Build x86_thread_state64_t ───────────────────────────────────────────
    # Layout (21 × uint64_t):
    #   rax rbx rcx rdx rdi rsi rbp rsp   (indices 0-7)
    #   r8  r9  r10 r11 r12 r13 r14 r15   (indices 8-15)
    #   rip rflags cs fs gs               (indices 16-20)
    # As uint32 array (× 2): rip at [32:34], rsp at [14:16], rflags at [34:36]

    X86_THREAD_STATE64       = 4
    X86_THREAD_STATE64_COUNT = 42   # state_count in uint32 units

    state = (c_uint32 * X86_THREAD_STATE64_COUNT)(*([0] * X86_THREAD_STATE64_COUNT))

    def _set64(state, idx64, val):
        state[idx64 * 2]     = val & 0xFFFFFFFF
        state[idx64 * 2 + 1] = (val >> 32) & 0xFFFFFFFF

    _set64(state, 16, sc_addr)    # __rip
    _set64(state, 7,  rsp_val)    # __rsp
    _set64(state, 17, 0x202)      # __rflags  (IF set)

    # ── Spawn the thread ─────────────────────────────────────────────────────
    thread = mach_port_t(0)
    tcr.argtypes = [
        mach_port_t, c_int, C.POINTER(c_uint32 * X86_THREAD_STATE64_COUNT),
        c_uint32, C.POINTER(mach_port_t)
    ]
    ret = tcr(task, X86_THREAD_STATE64, byref(state), X86_THREAD_STATE64_COUNT, byref(thread))
    if ret != 0:
        raise RuntimeError(f"thread_create_running failed: kern_return={ret}")

    print(f"[chroma/mach] thread 0x{thread.value:x} running dlopen({os.path.basename(dylib_path)})")


# ── Backend: lldb ────────────────────────────────────────────────────────────
#
# Uses `lldb -p PID --batch` with sequential `expr` commands to call the
# activation functions directly inside the Chrome process.
# lldb ships with Xcode Command Line Tools (xcode-select --install).

def activate_lldb(pid: int, port: int = 9222) -> bool:
    """Activate CDP by calling Chrome internals via lldb expr."""

    # ── 1. Get module base ────────────────────────────────────────────────────
    r = subprocess.run(
        ["lldb", "-p", str(pid), "--batch",
         "-o", 'image list "Google Chrome Framework"'],
        capture_output=True, text=True, timeout=15,
    )
    import re
    m = re.search(r"\]\s+\S+\s+(0x[0-9a-f]+)\s+.*Google Chrome Framework", r.stdout, re.I)
    if not m:
        raise RuntimeError(f"Could not parse module base from lldb:\n{r.stdout}\n{r.stderr}")

    base = int(m.group(1), 16)
    print(f"[chroma/lldb] framework base = 0x{base:x}")
    rt = runtime_offsets(base)

    # ── 2. Build lldb command script ──────────────────────────────────────────
    # Each `expr` runs C in the target process. We chain them using lldb
    # convenience variables ($name).
    cmds = [
        # Allocate and zero buffers
        f"expr void* $sb = ((void*(*)(size_t)){rt['op_new']:#x}ULL)(0x20)",
        f"expr (void)memset($sb, 0, 0x20)",
        f"expr void* $ab = ((void*(*)(size_t)){rt['op_new']:#x}ULL)(0x50)",
        f"expr (void)memset($ab, 0, 0x50)",
        # Build factory object: [vtable | port(u16) | 0x2475(u16) | pad]
        f"expr void* $fc = ((void*(*)(size_t)){rt['op_new']:#x}ULL)(0x10)",
        f"expr (void)memset($fc, 0, 0x10)",
        f"expr *(void**)$fc = (void*){rt['handler_vtable']:#x}ULL",
        f"expr ((unsigned short*)$fc)[4] = (unsigned short){port}",
        f"expr ((unsigned short*)$fc)[5] = (unsigned short)0x2475",
        # Create socket
        f"expr (unsigned char)((unsigned char(*)(unsigned int, void*)){rt['create_server_socket']:#x}ULL)({port}, $sb)",
        # Start DevTools handler
        f"expr (void)((void(*)(void*,void*,void*,unsigned int)){rt['devtools_start']:#x}ULL)($fc, $sb, $ab, 0)",
        "quit",
    ]

    with tempfile.NamedTemporaryFile("w", suffix=".lldb", delete=False) as f:
        f.write("\n".join(cmds) + "\n")
        cmd_file = f.name

    try:
        r = subprocess.run(
            ["lldb", "-p", str(pid), "--batch", "-s", cmd_file],
            capture_output=True, text=True, timeout=20,
        )
        if r.returncode not in (0, 1):   # lldb returns 1 on "quit"
            print(f"[chroma/lldb] stderr: {r.stderr[:400]}")
    finally:
        os.unlink(cmd_file)

    # ── 3. Verify ─────────────────────────────────────────────────────────────
    for _ in range(8):
        time.sleep(0.5)
        info = verify(port)
        if info:
            return True
    return False


# ── Backend: Frida ───────────────────────────────────────────────────────────

def activate_frida(pid: int, port: int = 9222) -> bool:
    """Original Frida-based activation (requires: pip install frida)."""
    try:
        import frida
    except ImportError:
        raise RuntimeError("frida not installed — run: pip install frida")

    import json

    session = _frida_get_session(pid)
    info    = _frida_module_info(session)
    base    = int(info["base"], 16)
    rt      = runtime_offsets(base)
    print(f"[chroma/frida] framework base = 0x{base:x}")

    JS = """
(function() {
    var rt = RUNTIME_OFFSETS;
    var port = TARGET_PORT;
    try {
        var opNew  = new NativeFunction(ptr(rt.op_new),                'pointer', ['uint32']);
        var csock  = new NativeFunction(ptr(rt.create_server_socket),  'uint8',   ['uint32','pointer']);
        var dstart = new NativeFunction(ptr(rt.devtools_start),        'void',    ['pointer','pointer','pointer','uint32']);

        var sb = opNew(0x20); sb.writeByteArray(new Array(0x20).fill(0));
        var ab = opNew(0x50); ab.writeByteArray(new Array(0x50).fill(0));
        var fc = opNew(0x10); fc.writeByteArray(new Array(0x10).fill(0));
        fc.writePointer(ptr(rt.handler_vtable));
        fc.add(8).writeU16(port);
        fc.add(0xa).writeU16(0x2475);

        csock(port, sb);
        dstart(fc, sb, ab, 0);
        send('[chroma/frida] DevToolsHttpHandler::Start called');
    } catch(e) {
        send('[chroma/frida] ERROR: ' + e.message);
    }
})();
""".replace("RUNTIME_OFFSETS", json.dumps({k: hex(v) for k, v in rt.items()})) \
   .replace("TARGET_PORT", str(port))

    msgs = []
    def on_msg(msg, _):
        if msg["type"] == "send":
            print(msg["payload"])
            msgs.append(msg["payload"])

    script = session.create_script(JS)
    script.on("message", on_msg)
    script.load()
    time.sleep(3)
    session.detach()

    for _ in range(8):
        time.sleep(0.5)
        info = verify(port)
        if info:
            return True
    return False


def _frida_get_session(pid):
    import frida
    return frida.attach(pid)

def _frida_module_info(session) -> dict:
    import frida
    result = {}
    def on_msg(msg, _):
        if msg["type"] == "send":
            result.update(msg["payload"])
    scr = session.create_script(
        "var m=Process.getModuleByName('Google Chrome Framework');"
        "send({base:m.base.toString(),size:m.size});"
    )
    scr.on("message", on_msg)
    scr.load()
    time.sleep(2)
    return result


# ── Main ─────────────────────────────────────────────────────────────────────

BACKENDS = {
    "mach":  activate_mach,
    "lldb":  activate_lldb,
    "frida": activate_frida,
}

def activate(port: int = 9222, pid: int | None = None, backend: str = "auto") -> bool:
    if pid is None:
        pid = get_chrome_pid()
    print(f"[chroma] target PID {pid}, port {port}")

    # Quick check — maybe CDP is already up
    if verify(port):
        print(f"[chroma] CDP already active on port {port}")
        return True

    order = list(BACKENDS.keys()) if backend == "auto" else [backend]

    for name in order:
        print(f"[chroma] trying backend: {name}")
        try:
            ok = BACKENDS[name](pid, port)
            if ok:
                info = verify(port)
                print(f"\n[chroma] ✅  CDP active!")
                print(f"  Browser : {info.get('Browser')}")
                print(f"  WS URL  : {info.get('webSocketDebuggerUrl')}")
                return True
            else:
                print(f"[chroma] {name}: handler started but port not responding yet")
        except Exception as e:
            print(f"[chroma] {name} failed: {e}")
            if backend != "auto":
                raise

    print("[chroma] ❌  All backends failed")
    return False


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="chroma — runtime CDP activation")
    ap.add_argument("port",    nargs="?", type=int, default=9222)
    ap.add_argument("pid",     nargs="?", type=int, default=None)
    ap.add_argument("--backend", choices=[*BACKENDS.keys(), "auto"], default="auto")
    args = ap.parse_args()

    ok = activate(port=args.port, pid=args.pid, backend=args.backend)
    sys.exit(0 if ok else 1)
