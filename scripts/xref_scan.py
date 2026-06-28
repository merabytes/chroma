#!/usr/bin/env python3
"""Scan __TEXT,__text for LEA/MOV [RIP+disp32] instructions pointing to a VM address."""
import frida, glob, struct, sys, time
import numpy as np

TARGET_VM = int(sys.argv[1], 16)

# Get runtime base
session = frida.attach(int(sys.argv[2]) if len(sys.argv) > 2 else int(
    __import__("subprocess").check_output(["pgrep", "-x", "Google Chrome"]).split()[0]
))
result = {}
def on_msg(msg, _): result.update(msg["payload"]) if msg["type"] == "send" else None
scr = session.create_script("var m=Process.getModuleByName('Google Chrome Framework');send({base:m.base.toString(),size:m.size});")
scr.on("message", on_msg); scr.load(); time.sleep(2); session.detach()

base = int(result["base"], 16)

paths = glob.glob("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/*/Google Chrome Framework")
with open(paths[0], "rb") as f: data = f.read()

narch = struct.unpack(">I", data[4:8])[0]
slices = [(struct.unpack(">5I", data[8+i*20:8+i*20+20])) for i in range(narch)]
x64 = next(s for s in slices if s[0] == 0x01000007)
slice_off = x64[2]
vm_base = struct.unpack_from("<Q", data, slice_off + 24)[0]
slide = base - vm_base

off = slice_off + 32
ncmds = struct.unpack_from("<I", data, slice_off + 16)[0]
sections = {}
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        nsects = struct.unpack_from("<I", data, off+64)[0]
        for j in range(nsects):
            soff2 = off + 72 + j * 80
            secname = data[soff2:soff2+16].rstrip(b"\x00").decode()
            seg     = data[soff2+16:soff2+32].rstrip(b"\x00").decode()
            saddr, ssz = struct.unpack_from("<QQ", data, soff2+32)
            sfoff = struct.unpack_from("<I", data, soff2+48)[0]
            sections[f"{seg},{secname}"] = (saddr, sfoff, ssz)
    off += cmdsize

tva, tfo, tsz = sections["__TEXT,__text"]
arr = np.frombuffer(data[tfo:tfo+tsz], dtype=np.uint8)
N = len(arr)

b0 = arr[:N-7]; b1 = arr[1:N-6]; b2 = arr[2:N-5]
mask = (np.isin(b0, [0x48,0x4C])) & (np.isin(b1, [0x8D,0x8B])) & ((b2 & 0xC7)==0x05)
candidates = np.where(mask)[0]

str_vm = TARGET_VM - slide  # on-disk VM
hits = []
for i in candidates:
    disp = struct.unpack_from("<i", arr[i+3:i+7].tobytes())[0]
    if tva + int(i) + 7 + disp == str_vm:
        hits.append(tva + int(i) + slide)

print(f"Xref hits ({len(hits)}):")
for h in hits: print(f"  0x{h:x}")
