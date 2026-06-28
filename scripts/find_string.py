#!/usr/bin/env python3
"""Find a cstring in the Chrome FAT binary and return its VM address + file offset."""
import glob, struct, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "DevTools listening on ws:"

paths = glob.glob(
    "/Applications/Google Chrome.app/Contents/Frameworks/"
    "Google Chrome Framework.framework/Versions/*/"
    "Google Chrome Framework"
)
with open(paths[0], "rb") as f:
    data = f.read()

narch = struct.unpack(">I", data[4:8])[0]
slices = []
for i in range(narch):
    cputype, _, offset, fsize, _ = struct.unpack(">5I", data[8+i*20:8+i*20+20])
    slices.append((cputype, offset, fsize))

x64 = next(s for s in slices if s[0] == 0x01000007)
slice_off = x64[1]
vm_base = struct.unpack_from("<Q", data, slice_off + 24)[0]

# Parse sections
off = slice_off + 32
ncmds = struct.unpack_from("<I", data, slice_off + 16)[0]
sections = {}
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        nsects = struct.unpack_from("<I", data, off+64)[0]
        for j in range(nsects):
            soff = off + 72 + j * 80
            secname = data[soff:soff+16].rstrip(b"\x00").decode()
            seg     = data[soff+16:soff+32].rstrip(b"\x00").decode()
            saddr, ssz = struct.unpack_from("<QQ", data, soff+32)
            sfoff = struct.unpack_from("<I", data, soff+48)[0]
            sections[f"{seg},{secname}"] = (saddr, sfoff, ssz)
    off += cmdsize

cva, cfo, csz = sections["__TEXT,__cstring"]
needle = TARGET.encode()
idx = data[cfo:cfo+csz].find(needle)
if idx < 0:
    print(f"String not found: {TARGET!r}")
    sys.exit(1)

str_vm  = cva + idx
str_foff = cfo + idx
print(f"String   : {TARGET!r}")
print(f"VM addr  : 0x{str_vm:x}")
print(f"File off : 0x{str_foff:x}")
print(f"vm_base  : 0x{vm_base:x}")
