#!/usr/bin/env python3
"""Find all CALL rel32 instructions in the Chrome binary that target a given address."""
import frida, glob, struct, sys, time
import numpy as np

TARGET = int(sys.argv[1], 16)

session = frida.attach(int(sys.argv[2]) if len(sys.argv) > 2 else int(
    __import__("subprocess").check_output(["pgrep", "-x", "Google Chrome"]).split()[0]
))
result = {}
def on_msg(msg, _): result.update(msg["payload"]) if msg["type"] == "send" else None
scr = session.create_script("var m=Process.getModuleByName('Google Chrome Framework');send({base:m.base.toString()});")
scr.on("message", on_msg); scr.load(); time.sleep(2); session.detach()
base = int(result["base"], 16)

paths = glob.glob("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/*/Google Chrome Framework")
with open(paths[0], "rb") as f: data = f.read()

narch = struct.unpack(">I", data[4:8])[0]
slices = [struct.unpack(">5I", data[8+i*20:8+i*20+20]) for i in range(narch)]
x64 = next(s for s in slices if s[0] == 0x01000007)
slice_off, slice_sz = x64[2], x64[3]
vm_base = struct.unpack_from("<Q", data, slice_off + 24)[0]
slide = base - vm_base
target_vm = TARGET - slide

arr = np.frombuffer(data[slice_off:slice_off+slice_sz], dtype=np.uint8)
e8_pos = np.where(arr == 0xE8)[0]
callers = []
for pos in e8_pos:
    if pos + 5 > len(arr): continue
    rel = struct.unpack_from("<i", arr[pos+1:pos+5].tobytes())[0]
    if vm_base + int(pos) + 5 + rel == target_vm:
        callers.append(f"0x{vm_base + int(pos) + slide:x}")

print(f"Callers of 0x{TARGET:x} ({len(callers)}):")
for c in callers: print(f"  {c}")
