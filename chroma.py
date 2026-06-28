#!/usr/bin/env python3
"""
chroma.py — Runtime CDP activation for Chrome via Frida
Activates Chrome DevTools Protocol on a live, stripped Chrome process
without --remote-debugging-port at launch.

Author: Merabytes
Target: Chrome 149 (macOS x86_64, fully stripped binary)
Tested: Chrome 149.0.7827.103 / macOS 13+
"""

import frida
import glob
import struct
import sys
import time

import numpy as np


# ── helpers ──────────────────────────────────────────────────────────────────

def get_chrome_pid() -> int:
    """Return the PID of the main Chrome browser process."""
    import subprocess
    out = subprocess.check_output(
        ["pgrep", "-x", "Google Chrome"], text=True
    ).strip()
    pids = [int(p) for p in out.splitlines()]
    if not pids:
        raise RuntimeError("Chrome process not found")
    # Prefer the lowest PID (usually the browser process, not renderers)
    return min(pids)


def get_module_info(session: frida.core.Session) -> dict:
    """Return base address and size of Google Chrome Framework."""
    result = {}

    def on_msg(msg, _data):
        if msg["type"] == "send":
            result.update(msg["payload"])

    script = session.create_script(
        "var m = Process.getModuleByName('Google Chrome Framework');"
        "send({base: m.base.toString(), size: m.size});"
    )
    script.on("message", on_msg)
    script.load()
    time.sleep(2)
    return result


def compute_slide(base: int) -> int:
    """Compute ASLR slide from the on-disk FAT binary."""
    paths = glob.glob(
        "/Applications/Google Chrome.app/Contents/Frameworks/"
        "Google Chrome Framework.framework/Versions/*/"
        "Google Chrome Framework"
    )
    if not paths:
        raise FileNotFoundError("Google Chrome Framework binary not found")

    with open(paths[0], "rb") as f:
        data = f.read()

    narch = struct.unpack(">I", data[4:8])[0]
    slices = []
    for i in range(narch):
        cputype, _subtype, offset, fsize, _align = struct.unpack(
            ">5I", data[8 + i * 20 : 8 + i * 20 + 20]
        )
        slices.append((cputype, offset, fsize))

    x64 = next((s for s in slices if s[0] == 0x01000007), None)
    if x64 is None:
        raise RuntimeError("x86_64 slice not found in FAT binary")

    slice_off = x64[1]
    vm_base = struct.unpack_from("<Q", data, slice_off + 24)[0]
    return base - vm_base


def scan_callers(binary_path: str, target_vm: int, vm_base: int, slice_off: int, slice_sz: int) -> list:
    """Fast numpy scan for CALL rel32 instructions that target target_vm."""
    with open(binary_path, "rb") as f:
        f.seek(slice_off)
        raw = f.read(slice_sz)

    arr = np.frombuffer(raw, dtype=np.uint8)
    e8_positions = np.where(arr == 0xE8)[0]

    callers = []
    for pos in e8_positions:
        if pos + 5 > len(arr):
            continue
        rel = struct.unpack_from("<i", arr[pos + 1 : pos + 5].tobytes())[0]
        dest_vm = vm_base + int(pos) + 5 + rel
        if dest_vm == target_vm:
            callers.append(vm_base + int(pos))
    return callers


# ── known offsets (Chrome 149.0.7827.103 x86_64 macOS) ──────────────────────
#
# These are VM addresses relative to the x86_64 slice vm_base.
# At runtime: runtime_addr = vm_addr + slide
#
# To port to a different version, re-derive them with the accompanying
# analysis scripts in scripts/.

OFFSETS_149 = {
    # bool CreateServerSocket(int port_hint, std::string* socket_name_out)
    "create_server_socket": 0x131f3da20,

    # void DevToolsHttpHandlerStart(
    #     DevToolsHttpHandlerFactory* factory,
    #     std::string* socket_name,
    #     std::string* addr,
    #     int flags)
    "devtools_start": 0x133a8eb10,

    # vtable for the DevToolsHttpHandlerFactory (TCPServerSocketFactory)
    "handler_vtable": 0x13f1710e8,

    # operator new(size_t)
    "op_new": 0x130c2e410,
}


# ── Frida JS payload ──────────────────────────────────────────────────────────

JS_ACTIVATE = """
(function() {
    var offsets = {offsets_json};

    try {{
        var opNew         = new NativeFunction(ptr(offsets.op_new),            'pointer', ['uint32']);
        var createSocket  = new NativeFunction(ptr(offsets.create_server_socket), 'uint8',   ['uint32', 'pointer']);
        var devtoolsStart = new NativeFunction(ptr(offsets.devtools_start),    'void',    ['pointer', 'pointer', 'pointer', 'uint32']);

        // Allocate buffers (zeroed)
        var socketBuf = opNew(0x20);
        socketBuf.writeByteArray(new Array(0x20).fill(0));

        var addrBuf = opNew(0x50);
        addrBuf.writeByteArray(new Array(0x50).fill(0));

        // Create TCP server socket on the requested port
        var sockOk = createSocket(TARGET_PORT, socketBuf);
        send('[chroma] createSocket(' + TARGET_PORT + ') -> ' + sockOk);

        // Build the factory object: [vtable | port(u16) | field(u16=0x2475) | pad]
        var factory = opNew(0x10);
        factory.writeByteArray(new Array(0x10).fill(0));
        factory.writePointer(ptr(offsets.handler_vtable));
        factory.add(8).writeU16(TARGET_PORT);
        factory.add(0xa).writeU16(0x2475);

        // Start the DevTools HTTP handler
        devtoolsStart(factory, socketBuf, addrBuf, 0);
        send('[chroma] DevToolsHttpHandler::Start called — CDP should be up on port ' + TARGET_PORT);

    }} catch(e) {{
        send('[chroma] ERROR: ' + e.message);
    }}
}})();
""".replace("{offsets_json}", "{offsets_json}").replace("TARGET_PORT", "TARGET_PORT")


# ── main ─────────────────────────────────────────────────────────────────────

def activate(port: int = 9222, pid: int | None = None) -> bool:
    """
    Attach to Chrome and activate CDP on the given port.
    Returns True if the handler was started successfully.
    """
    if pid is None:
        pid = get_chrome_pid()

    print(f"[chroma] attaching to PID {pid}…")
    session = frida.attach(pid)

    info = get_module_info(session)
    base = int(info["base"], 16)
    print(f"[chroma] module base = 0x{base:x}")

    slide = compute_slide(base)
    print(f"[chroma] ASLR slide  = 0x{slide:x}")

    # Apply slide to known offsets
    runtime_offsets = {k: hex(v + slide) for k, v in OFFSETS_149.items()}
    print(f"[chroma] runtime offsets: {runtime_offsets}")

    import json
    js = JS_ACTIVATE.replace("{offsets_json}", json.dumps(runtime_offsets))
    js = js.replace("TARGET_PORT", str(port))

    messages = []

    def on_msg(msg, _data):
        if msg["type"] == "send":
            print(msg["payload"])
            messages.append(msg["payload"])
        elif msg["type"] == "error":
            print(f"[frida ERROR] {msg['description']}")

    script = session.create_script(js)
    script.on("message", on_msg)
    script.load()
    time.sleep(3)
    session.detach()

    # Verify
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://localhost:{port}/json/version", timeout=3) as r:
            import json as _json
            data = _json.loads(r.read())
            print(f"\n[chroma] ✅ CDP active!")
            print(f"  Browser : {data.get('Browser')}")
            print(f"  WS URL  : {data.get('webSocketDebuggerUrl')}")
            return True
    except Exception as e:
        print(f"[chroma] ❌ Verification failed: {e}")
        return False


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9222
    pid  = int(sys.argv[2]) if len(sys.argv) > 2 else None
    ok   = activate(port=port, pid=pid)
    sys.exit(0 if ok else 1)
