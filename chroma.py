#!/usr/bin/env python3
"""
chroma.py — Runtime CDP activation for Chrome (version-agnostic)

Activates Chrome DevTools Protocol on a live, fully-stripped Chrome process
without --remote-debugging-port at launch.

Offset discovery (in order, per Chrome version + arch):
  1. Cache  — ~/.chroma/offsets.json keyed by "<version>-<arch>"
  2. String-xref scan — find unique strings in the binary, locate RIP/ADRP refs
  3. Signature scan  — known byte patterns stored per milestone
  4. (Fallback) manual — user supplies offsets via --offset key=0xADDR

Injection backends (tried in order unless --backend is specified):
  mach  — Pure Python + ctypes + Mach task APIs. Compiles a minimal dylib
           on-the-fly and injects it via thread_create_running. No external
           tools required beyond a C compiler (cc, always available on macOS).
  lldb  — Uses lldb CLI (ships with Xcode Command Line Tools).
  frida — Original Frida-based approach (requires: pip install frida).

Usage:
  python3 chroma.py [port] [pid] [--backend auto|mach|lldb|frida]
                    [--scan] [--offset key=0xADDR ...]

Author: Merabytes
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import glob
import json
import os
import plistlib
import re
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Optional

# ── Paths ──────────────────────────────────────────────────────────────────
CACHE_FILE = Path.home() / ".chroma" / "offsets.json"
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

# ── Byte-signature database ────────────────────────────────────────────────
#
# Stored as lists of hex strings with '??' wildcards.
# Add new entries when a version's signatures are known.
# These tend to be stable within a major Chrome milestone.
#
# To re-derive for a new version:
#   python3 chroma.py --scan
# or manually:
#   otool -d <framework> -arch x86_64 | grep -A1 <offset>
#
# Format: each entry is (milestone_range, hex_pattern_with_wildcards)
# milestone_range: (min_major, max_major) inclusive, None = any
SIGNATURES: dict[str, list[tuple[tuple[int,int]|None, str, str]]] = {
    # (milestone_range, hex_pattern_with_wildcards, arch)
    # arch: "x86_64", "arm64", or "any"
    "create_server_socket": [
        # Chrome 120–149 x86_64 — derived from 149.0.7827.103
        ((120, 149), "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec ?? ?? ?? ?? 48 89 f3", "x86_64"),
        # Chrome 120–149 arm64 — STP x29,x30 prologue + unique pattern
        ((120, 149), "fd 7b ?? a9 f4 ?? ?? a9 f6 ?? ?? a9 fd ?? ?? 91 f4 03 00 aa", "arm64"),
    ],
    "devtools_start": [
        # Chrome 120–149 x86_64
        ((120, 149), "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec ?? ?? ?? ?? 4c 89 e3", "x86_64"),
        # Chrome 120–149 arm64 — DevToolsHttpHandler::Start prologue
        ((120, 149), "fd 7b ?? a9 f4 ?? ?? a9 f6 ?? ?? a9 f8 ?? ?? a9 fd ?? ?? 91 f4 03 00 aa f5 03 01 aa", "arm64"),
    ],
    "handler_vtable_region": [
        # vtable is found via RTTI name string — handled by scanner
    ],
}

# ── Strings used for xref-based discovery ─────────────────────────────────
#
# These strings appear verbatim in Chrome's framework binary and are
# referenced by the DevTools startup code. Stable across many versions.
DISCOVERY_STRINGS = [
    # DevTools port file written to the profile dir
    b"DevToolsActivePort",
    # Log message in DevToolsHttpHandler::Start
    b"Listening on ",
    # TCPServerSocketFactory RTTI mangled name (x86_64 / arm64)
    b"_ZTV",
]

# ── MachO helpers ──────────────────────────────────────────────────────────

def _macho_parse(data: bytes, arch: str = "x86_64") -> dict:
    """
    Parse a thin or fat Mach-O and return info for the requested arch.
    Returns dict with keys: file_offset, vm_base, sections[name→(vmaddr,size,file_offset)]
    """
    CPU_TYPE = {"x86_64": 0x01000007, "arm64": 0x0100000C}
    target_cpu = CPU_TYPE.get(arch)

    magic_be = struct.unpack_from(">I", data)[0]
    magic_le = struct.unpack_from("<I", data)[0]

    if magic_be == 0xCAFEBABE:   # fat binary — header is always big-endian
        narch = struct.unpack_from(">I", data, 4)[0]
        for i in range(narch):
            cputype, _, offset, size, _ = struct.unpack_from(">5I", data, 8 + i * 20)
            if cputype == target_cpu:
                return _macho_parse(data[offset: offset + size], arch)
        raise ValueError(f"arch {arch} not found in fat binary")

    if magic_le == 0xFEEDFACF:   # little-endian 64-bit Mach-O
        ncmds, = struct.unpack_from("<I", data, 16)
        off = 32   # sizeof(mach_header_64)
        vm_base = None
        sections: dict[str, tuple[int, int, int]] = {}
        file_offset = 0

        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmd == 0x19:   # LC_SEGMENT_64
                segname = data[off+8: off+24].rstrip(b"\x00").decode()
                vmaddr, vmsize, fileoff = struct.unpack_from("<QQQ", data, off + 24)
                nsects, = struct.unpack_from("<I", data, off + 64)
                if segname == "__TEXT":
                    vm_base = vmaddr
                for s in range(nsects):
                    soff = off + 72 + s * 80
                    sectname = data[soff: soff+16].rstrip(b"\x00").decode()
                    sva, ssz, sfoff = struct.unpack_from("<QQI", data, soff + 32)
                    sections[f"{segname},{sectname}"] = (sva, ssz, sfoff)
            off += cmdsize

        if vm_base is None:
            raise ValueError("__TEXT segment not found")
        return {"vm_base": vm_base, "sections": sections}

    raise ValueError(f"Unsupported Mach-O magic: LE=0x{magic_le:08x} BE=0x{magic_be:08x}")


def _file_offset(macho: dict, vmaddr: int) -> int:
    """Convert a vmaddr to a file offset using section info."""
    for name, (sva, ssz, sfoff) in macho["sections"].items():
        if sva <= vmaddr < sva + ssz:
            return sfoff + (vmaddr - sva)
    raise ValueError(f"vmaddr 0x{vmaddr:x} not in any known section")


def _vmaddr_to_fileoff(macho: dict, vmaddr: int) -> int:
    return _file_offset(macho, vmaddr)


# ── Chrome version & framework detection ───────────────────────────────────

def get_chrome_version() -> str:
    paths = glob.glob(
        "/Applications/Google Chrome.app/Contents/Frameworks/"
        "Google Chrome Framework.framework/Versions/*/Resources/Info.plist"
    )
    if not paths:
        raise FileNotFoundError("Google Chrome Info.plist not found")
    with open(paths[0], "rb") as f:
        pl = plistlib.load(f)
    return pl["CFBundleShortVersionString"]


def get_framework_path() -> str:
    paths = glob.glob(
        "/Applications/Google Chrome.app/Contents/Frameworks/"
        "Google Chrome Framework.framework/Versions/*/Google Chrome Framework"
    )
    if not paths:
        raise FileNotFoundError("Google Chrome Framework binary not found")
    return paths[0]


def get_arch() -> str:
    import platform
    m = platform.machine()
    return "arm64" if m == "arm64" else "x86_64"


def version_key(version: str, arch: str) -> str:
    return f"{version}-{arch}"


# ── Offset cache ───────────────────────────────────────────────────────────

def cache_load() -> dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except Exception:
            pass
    return {}


def cache_save(db: dict):
    CACHE_FILE.write_text(json.dumps(db, indent=2))


def cache_get(key: str) -> Optional[dict]:
    return cache_load().get(key)


def cache_put(key: str, offsets: dict):
    db = cache_load()
    db[key] = offsets
    cache_save(db)
    print(f"[chroma/cache] saved offsets for {key} → {CACHE_FILE}")


# ── String-xref based discovery ────────────────────────────────────────────

def _find_string_fileoffs(data: bytes, needle: bytes) -> list[int]:
    """Return all file offsets where needle appears in data."""
    offs, start = [], 0
    while True:
        pos = data.find(needle, start)
        if pos == -1:
            break
        offs.append(pos)
        start = pos + 1
    return offs


def _x86_64_rip_refs(data: bytes, macho: dict, target_fileoff: int) -> list[int]:
    """
    Scan __TEXT,__text for RIP-relative instructions (LEA/MOV) that reference
    target_fileoff. Returns list of instruction file offsets.
    """
    text_va, text_sz, text_fo = macho["sections"].get("__TEXT,__text", (0, 0, 0))
    if not text_sz:
        return []

    vm_base = macho["vm_base"]
    # Convert target file offset to its vmaddr
    # (assumes target is in a section we know about)
    target_va = None
    for name, (sva, ssz, sfoff) in macho["sections"].items():
        if sfoff <= target_fileoff < sfoff + ssz:
            target_va = sva + (target_fileoff - sfoff)
            break
    if target_va is None:
        return []

    results = []
    text = data[text_fo: text_fo + text_sz]
    # Scan for 32-bit RIP-relative instructions:
    # LEA Rxx, [RIP+disp32] — many encodings; look for disp32 that resolves to target_va
    for i in range(len(text) - 7):
        # RIP-relative addressing: instruction end = i+7 (for 7-byte LEA)
        # effective_addr = (text_va + i + 7) + disp32
        for instr_len in (7, 8):   # 7 for REX+LEA, 8 for some variants
            if i + instr_len > len(text):
                continue
            # Read the last 4 bytes as disp32
            disp = struct.unpack_from("<i", text, i + instr_len - 4)[0]
            ref_va = text_va + i + instr_len + disp
            if ref_va == target_va:
                results.append(text_fo + i)
    return results


def _arm64_adrp_refs(data: bytes, macho: dict, target_fileoff: int) -> list[int]:
    """
    Scan __TEXT,__text for ADRP+ADD pairs referencing target_fileoff.
    Returns list of ADRP instruction file offsets.
    """
    text_va, text_sz, text_fo = macho["sections"].get("__TEXT,__text", (0, 0, 0))
    if not text_sz:
        return []

    target_va = None
    for name, (sva, ssz, sfoff) in macho["sections"].items():
        if sfoff <= target_fileoff < sfoff + ssz:
            target_va = sva + (target_fileoff - sfoff)
            break
    if target_va is None:
        return []

    results = []
    text = data[text_fo: text_fo + text_sz]
    target_page = target_va & ~0xFFF
    target_pgoff = target_va & 0xFFF

    for i in range(0, len(text) - 8, 4):
        instr = struct.unpack_from("<I", text, i)[0]
        # ADRP: bits[31:24]=1??10000, bit[28]=1
        if (instr & 0x9F000000) != 0x90000000:
            continue
        # Decode ADRP
        immhi = (instr >> 5) & 0x7FFFF
        immlo = (instr >> 29) & 0x3
        imm   = ((immhi << 2) | immlo) << 12
        if imm & (1 << 32):
            imm -= (1 << 33)
        instr_va = text_va + i
        page_va  = (instr_va & ~0xFFF) + imm
        if page_va != target_page:
            continue
        # Check following ADD
        if i + 4 >= len(text):
            continue
        add = struct.unpack_from("<I", text, i + 4)[0]
        if (add & 0xFF800000) != 0x91000000:
            continue
        add_imm = (add >> 10) & 0xFFF
        if add_imm == target_pgoff:
            results.append(text_fo + i)

    return results


def _walk_to_prologue(data: bytes, ref_fileoff: int, max_walk: int = 256) -> Optional[int]:
    """
    Walk backwards from ref_fileoff to find the nearest function prologue.
    x86_64: look for PUSH RBP (0x55) followed by MOV RBP,RSP (0x48 0x89 0xE5)
    arm64:  look for STP x29, x30 (common prologue pattern)
    """
    start = max(0, ref_fileoff - max_walk)
    window = data[start: ref_fileoff + 1]

    # x86_64 prologue: 55 48 89 e5
    pattern_x86 = bytes([0x55, 0x48, 0x89, 0xE5])
    idx = window.rfind(pattern_x86)
    if idx != -1:
        return start + idx

    # arm64 prologue: STP x29, x30, [sp, #-N]!  → D1 xx xx F8 (approx)
    # More precisely: FD 7B xx A9 (common encoding)
    for i in range(len(window) - 4, -1, -1):
        b = window[i: i + 4]
        if len(b) == 4 and b[0] == 0xFD and b[1] == 0x7B and b[3] == 0xA9:
            return start + i

    return None


def _find_vtable_rtti(data: bytes, macho: dict, class_substr: bytes) -> Optional[int]:
    """
    Find a C++ vtable by locating its RTTI typeinfo name string and following
    the reference chain:
      __DATA,__const → typeinfo ptr → vtable
    This is architecture-independent (pointer size 8 for 64-bit).
    """
    # Find the mangled name string, e.g. b"TCPServerSocketFactory"
    offs = _find_string_fileoffs(data, class_substr)
    if not offs:
        return None

    # For each occurrence, check if it's preceded by a length (RTTI format is:
    # _ZTS<len><name>\x00 in __TEXT,__cstring, then typeinfo in __DATA)
    # Simpler: just return the vmaddr of the first match and let the caller handle
    return offs[0] if offs else None


def discover_offsets(fw_path: str, arch: str, force: bool = False) -> Optional[dict]:
    """
    Scan the framework binary to discover DevTools function offsets.
    Returns dict with keys: create_server_socket, devtools_start, handler_vtable
    (all as vmaddr integers, relative to the binary's vm_base — ASLR slide applied at runtime).
    """
    print(f"[chroma/scan] loading framework ({arch}) ...")
    with open(fw_path, "rb") as f:
        data = f.read()

    macho = _macho_parse(data, arch)
    vm_base = macho["vm_base"]
    print(f"[chroma/scan] vm_base = 0x{vm_base:x}, sections: {list(macho['sections'].keys())}")

    found: dict[str, Optional[int]] = {}

    # ── 1. Find DevToolsActivePort xrefs → locate devtools_start nearby ──────
    print("[chroma/scan] searching for 'DevToolsActivePort' xrefs ...")
    string_fo_list = _find_string_fileoffs(data, b"DevToolsActivePort")
    for string_fo in string_fo_list:
        if arch == "x86_64":
            refs = _x86_64_rip_refs(data, macho, string_fo)
        else:
            refs = _arm64_adrp_refs(data, macho, string_fo)

        for ref_fo in refs:
            prologue_fo = _walk_to_prologue(data, ref_fo)
            if prologue_fo is not None:
                # Convert file offset → vmaddr
                for name, (sva, ssz, sfoff) in macho["sections"].items():
                    if sfoff <= prologue_fo < sfoff + ssz:
                        fn_va = sva + (prologue_fo - sfoff)
                        fn_rel = fn_va - vm_base
                        print(f"[chroma/scan]   DevTools candidate: 0x{fn_rel:x} (via '{b'DevToolsActivePort'.decode()}')")
                        if "devtools_start" not in found:
                            found["devtools_start"] = fn_rel

    # ── 2. Find "Listening on " xrefs → secondary devtools_start candidate ───
    if "devtools_start" not in found:
        print("[chroma/scan] searching for 'Listening on ' xrefs ...")
        for string_fo in _find_string_fileoffs(data, b"Listening on "):
            if arch == "x86_64":
                refs = _x86_64_rip_refs(data, macho, string_fo)
            else:
                refs = _arm64_adrp_refs(data, macho, string_fo)
            for ref_fo in refs:
                prologue_fo = _walk_to_prologue(data, ref_fo)
                if prologue_fo is not None:
                    for name, (sva, ssz, sfoff) in macho["sections"].items():
                        if sfoff <= prologue_fo < sfoff + ssz:
                            fn_va = sva + (prologue_fo - sfoff)
                            fn_rel = fn_va - vm_base
                            print(f"[chroma/scan]   DevTools candidate (listening): 0x{fn_rel:x}")
                            if "devtools_start" not in found:
                                found["devtools_start"] = fn_rel

    # ── 3. operator new — always resolved via libc++ export (no offset) ───────
    # Stored as None to signal "use dlsym" path
    found["op_new"] = None

    # ── 4. Signature scan (arch-filtered) ────────────────────────────────────
    print(f"[chroma/scan] signature scan ({arch}) ...")
    text_va, text_sz, text_fo = macho["sections"].get("__TEXT,__text", (0, 0, 0))
    if text_sz:
        text_bytes = data[text_fo: text_fo + text_sz]
        step = 4 if arch == "arm64" else 1

        for sig_name, entries in SIGNATURES.items():
            if sig_name in found and found[sig_name] is not None:
                continue  # already found via xref
            for (milestone_range, pat_hex, sig_arch) in entries:
                if sig_arch != "any" and sig_arch != arch:
                    continue  # skip signatures for wrong arch
                pat_bytes  = pat_hex.split()
                pat        = bytes(int(b, 16) if b != "??" else 0x00 for b in pat_bytes)
                mask       = bytes(0x00 if b == "??" else 0xFF for b in pat_bytes)
                pat_len    = len(pat)
                idx = 0
                while idx <= len(text_bytes) - pat_len:
                    if all((text_bytes[idx + j] & mask[j]) == (pat[j] & mask[j])
                           for j in range(pat_len)):
                        fn_va  = text_va + idx
                        fn_rel = fn_va - vm_base
                        print(f"[chroma/scan]   sig hit '{sig_name}' ({arch}): rel=0x{fn_rel:x}")
                        found[sig_name] = fn_rel
                        break
                    idx += step

    # ── 5. Vtable — scan for known RTTI name ─────────────────────────────────
    print("[chroma/scan] searching for TCPServerSocketFactory vtable ...")
    # The mangled RTTI name for TCPServerSocketFactory or DevToolsHttpHandlerFactory
    rtti_candidates = [
        b"TCPServerSocketFactory",
        b"DevToolsHttpHandlerFactory",
        b"DevToolsSocketFactory",
    ]
    data_const_va, data_const_sz, data_const_fo = macho["sections"].get(
        "__DATA_CONST,__const", macho["sections"].get("__DATA,__const", (0, 0, 0))
    )

    for rtti_name in rtti_candidates:
        name_fo_list = _find_string_fileoffs(data, rtti_name)
        for name_fo in name_fo_list:
            # The typeinfo object in __DATA references this string
            # Vtable is typically 2 pointers after the typeinfo header in __DATA,__const
            # Search __DATA,__const for a pointer to this string's vmaddr
            name_va = None
            for sec_name, (sva, ssz, sfoff) in macho["sections"].items():
                if sfoff <= name_fo < sfoff + ssz:
                    name_va = sva + (name_fo - sfoff)
                    break
            if name_va is None:
                continue
            name_va_bytes = struct.pack("<Q", name_va)
            ptr_fo = data.find(name_va_bytes, data_const_fo,
                               data_const_fo + data_const_sz)
            if ptr_fo == -1:
                continue
            # vtable pointer is at ptr_fo - 8 (points to the function pointers array)
            # The actual vtable data starts 16 bytes after the typeinfo pointer
            ti_va = data_const_va + (ptr_fo - data_const_fo) - 8
            vtbl_va = ti_va + 16
            vtbl_rel = vtbl_va - vm_base
            print(f"[chroma/scan]   vtable candidate ('{rtti_name.decode()}') 0x{vtbl_rel:x}")
            if "handler_vtable" not in found:
                found["handler_vtable"] = vtbl_rel

    # ── 6. Frida runtime scan (best effort — finds xrefs in live process) ────
    # If Frida is available and devtools_start is still missing, use it to scan
    # the live process memory. Far more reliable than static analysis on arm64.
    missing = [k for k in ("devtools_start", "handler_vtable") if not found.get(k)]
    if missing:
        print(f"[chroma/scan] static scan incomplete ({missing}), trying Frida live scan ...")
        try:
            frida_offsets = _frida_scan_offsets(arch)
            for k in missing:
                if frida_offsets.get(k):
                    found[k] = frida_offsets[k]
                    print(f"[chroma/scan]   frida found '{k}': rel=0x{frida_offsets[k]:x}")
        except Exception as e:
            print(f"[chroma/scan]   frida scan skipped: {e}")

    return found if any(v is not None for v in found.values()) else None


def _frida_scan_offsets(arch: str) -> dict:
    """
    Use Frida to scan the live Chrome process for DevTools function addresses.
    Uses NativePointer arithmetic throughout to avoid JS 32-bit integer overflow.
    Returns offsets relative to the framework vm_base (ASLR-independent).
    """
    frida = _import_frida()
    pid = get_chrome_pid()
    session = frida.attach(pid)

    result: dict = {}
    errors: list = []
    import threading
    done = threading.Event()

    # Language: Frida JS (V8). All address arithmetic via NativePointer to avoid
    # 32-bit overflow. arm64 ADRP+LDR/ADD decoded with BigInt for safety.
    JS = r"""
(function() {
    var results = {};
    var errs = [];

    try {
        var mod = Process.getModuleByName('Google Chrome Framework');
    } catch(e) {
        send({__error: 'module not found: ' + e.message});
        return;
    }

    var base    = mod.base;
    var modEnd  = base.add(mod.size);
    var arch    = Process.arch;

    // ── Helper: walk backwards to find function prologue ──────────────────
    function findPrologue(addr) {
        var step = (arch === 'arm64') ? 4 : 1;
        for (var i = step; i <= 1024; i += step) {
            var p = addr.sub(i);
            if (p.compare(base) < 0) break;
            try {
                var b = p.readByteArray(4);
                var v = new Uint8Array(b);
                if (arch === 'arm64') {
                    // STP x29, x30, [sp, #-N]!  →  FD 7B ?? A9
                    if (v[0] === 0xFD && v[1] === 0x7B && v[3] === 0xA9) return p;
                    // PACIBSP / PACIASP (hint #25 / #27) — also a valid prologue marker
                    if (v[0] === 0x5F && v[1] === 0x23 && v[2] === 0x03 && v[3] === 0xD5) return p;
                    if (v[0] === 0xFF && v[1] === 0x23 && v[2] === 0x03 && v[3] === 0xD5) return p;
                } else {
                    if (v[0] === 0x55 && v[1] === 0x48 && v[2] === 0x89 && v[3] === 0xE5) return p;
                }
            } catch(e) { break; }
        }
        return null;
    }

    // ── Helper: string → Frida scan pattern ──────────────────────────────
    function strPattern(s) {
        var out = [];
        for (var i = 0; i < s.length; i++)
            out.push(('0' + s.charCodeAt(i).toString(16)).slice(-2));
        return out.join(' ');
    }

    // ── Helper: decode arm64 ADRP at a NativePointer, return page NativePointer
    function decodeAdrp(instrPtr) {
        var b = instrPtr.readByteArray(4);
        var v = new Uint8Array(b);
        var instr = v[0] | (v[1] << 8) | (v[2] << 16) | (v[3] << 24);
        if ((instr & 0x9F000000) !== 0x90000000) return null;
        // Use BigInt to avoid 32-bit overflow
        var instrBig = BigInt(instr) & BigInt('0xFFFFFFFF');
        var immhi = Number((instrBig >> BigInt(5)) & BigInt('0x7FFFF'));
        var immlo = Number((instrBig >> BigInt(29)) & BigInt(3));
        var imm21 = (immhi << 2) | immlo;
        // Sign extend 21-bit → 32-bit
        if (imm21 & (1 << 20)) imm21 = imm21 - (1 << 21);
        // Page offset = imm21 * 4096
        var pageOff = imm21 * 4096;
        // instrPage = instrPtr & ~0xFFF
        var instrAddr = Number(BigInt('0x' + instrPtr.toString(16)) & BigInt('0xFFFFFFFFFFFFF000'));
        var targetPage = instrAddr + pageOff;
        return ptr(targetPage.toString());
    }

    // ── Scan for a string and find the function that references it ────────
    function findFnForString(needle, label) {
        try {
            var matches = Memory.scanSync(base, mod.size, strPattern(needle));
            if (matches.length === 0) {
                errs.push(label + ': string not found in memory');
                return null;
            }
            for (var mi = 0; mi < matches.length; mi++) {
                var strAddr = matches[mi].address;
                var strPage = ptr((Number(BigInt('0x' + strAddr.toString(16)) & BigInt('0xFFFFFFFFFFFFF000'))).toString());

                // Scan the 4MB of code before the string for ADRP instructions
                // that target the same 4K page as strAddr
                var scanStart = strAddr.sub(4 * 1024 * 1024);
                if (scanStart.compare(base) < 0) scanStart = base;
                var scanSize  = strAddr.sub(scanStart).toInt32();
                if (scanSize < 4) continue;

                var buf  = scanStart.readByteArray(scanSize);
                var arr  = new Uint32Array(buf);
                // Walk backwards from the string (most likely callers are just before it)
                for (var i = arr.length - 1; i >= 0; i--) {
                    var instrPtr = scanStart.add(i * 4);
                    var page = decodeAdrp(instrPtr);
                    if (page === null) continue;
                    if (page.equals(strPage)) {
                        var prologue = findPrologue(instrPtr);
                        if (prologue) {
                            errs.push(label + ': found at ' + prologue.toString(16) +
                                      ' (xref from ' + instrPtr.sub(base).toString(16) + ')');
                            return prologue.sub(base).toString(16);
                        }
                    }
                }
                errs.push(label + ': ADRP xref not found in 4MB window before string');
            }
        } catch(e) {
            errs.push(label + ': exception: ' + e.message + '\n' + e.stack);
        }
        return null;
    }

    // ── DevTools start: try multiple stable strings ───────────────────────
    var devtoolsStrings = ['DevToolsActivePort', 'Listening on '];
    for (var di = 0; di < devtoolsStrings.length && !results.devtools_start; di++) {
        var r = findFnForString(devtoolsStrings[di], 'devtools_start[' + devtoolsStrings[di] + ']');
        if (r) results.devtools_start = r;
    }

    // ── Vtable: RTTI name → typeinfo ptr → vtable ─────────────────────────
    var vtblNames = ['TCPServerSocketFactory', 'DevToolsHttpHandlerFactory'];
    for (var vi = 0; vi < vtblNames.length && !results.handler_vtable; vi++) {
        try {
            var ms = Memory.scanSync(base, mod.size, strPattern(vtblNames[vi]));
            if (ms.length === 0) continue;
            var nameAddr = ms[0].address;
            // Encode nameAddr as little-endian 8-byte pattern
            var na = BigInt('0x' + nameAddr.toString(16));
            var naBytes = [];
            for (var bi = 0; bi < 8; bi++) {
                naBytes.push(('0' + Number(na & BigInt(0xFF)).toString(16)).slice(-2));
                na = na >> BigInt(8);
            }
            var ptrPat = naBytes.join(' ');
            // Scan all readable ranges within the module for a pointer to nameAddr
            var ranges = Process.enumerateRanges('r--');
            for (var ri = 0; ri < ranges.length && !results.handler_vtable; ri++) {
                var r2 = ranges[ri];
                if (r2.base.compare(base) < 0 || r2.base.compare(modEnd) > 0) continue;
                var ptrs2 = Memory.scanSync(r2.base, r2.size, ptrPat);
                if (ptrs2.length > 0) {
                    var vtbl = ptrs2[0].address.add(16);
                    results.handler_vtable = vtbl.sub(base).toString(16);
                    errs.push('handler_vtable: found via ' + vtblNames[vi]);
                }
            }
        } catch(e) {
            errs.push('handler_vtable[' + vtblNames[vi] + ']: ' + e.message);
        }
    }

    send({results: results, errors: errs});
})();
"""

    def on_msg(msg, data):
        if msg["type"] == "send":
            payload = msg["payload"]
            if isinstance(payload, dict) and "results" in payload:
                result.update(payload["results"])
                for e in payload.get("errors", []):
                    errors.append(e)
            elif isinstance(payload, dict) and "__error" in payload:
                errors.append(payload["__error"])
            done.set()
        elif msg["type"] == "error":
            errors.append(f"script error: {msg.get('description')} @ {msg.get('lineNumber')}")
            done.set()

    scr = session.create_script(JS)
    scr.on("message", on_msg)
    scr.load()
    done.wait(timeout=20)
    session.detach()

    if errors:
        print(f"[chroma/frida-scan] diagnostics:")
        for e in errors:
            print(f"  {e}")

    # Convert hex strings to relative ints
    out = {}
    for k, v in result.items():
        if v:
            try:
                out[k] = int(v, 16)
            except (ValueError, TypeError):
                print(f"[chroma/frida-scan] bad value for {k}: {v!r}")
    return out


# ── Offset resolution entry point ─────────────────────────────────────────

def resolve_offsets(
    version: str,
    arch: str,
    fw_path: str,
    force_scan: bool = False,
    manual: Optional[dict] = None,
) -> dict:
    """
    Return runtime-ready offsets for the current Chrome version.
    Applies ASLR slide before returning.
    """
    key = version_key(version, arch)

    # Manual overrides take highest priority
    if manual:
        print(f"[chroma] using manual offsets: {manual}")
        return manual

    # Cache hit — but only if it contains the critical offsets
    REQUIRED = {"devtools_start"}
    if not force_scan:
        cached = cache_get(key)
        if cached:
            cached_parsed = {k: int(v, 16) if isinstance(v, str) else v
                             for k, v in cached.items()}
            missing_req = [r for r in REQUIRED if not cached_parsed.get(r)]
            if missing_req:
                print(f"[chroma] cache for {key} is incomplete (missing: {missing_req}), re-scanning ...")
            else:
                print(f"[chroma] offsets loaded from cache for {key}")
                return cached_parsed

    # Discover via scanning
    print(f"[chroma] no cached offsets for {key} — running scanner ...")
    offsets = discover_offsets(fw_path, arch, force=force_scan)
    if offsets is None:
        raise RuntimeError(
            f"Could not auto-discover offsets for Chrome {version} ({arch}).\n"
            "Run with --scan to debug, or supply --offset key=0xVALUE manually."
        )

    # Store in cache (as hex strings for readability)
    cache_entry = {
        k: hex(v) if v is not None else None
        for k, v in offsets.items()
    }
    cache_put(key, cache_entry)
    return offsets


def apply_slide(offsets: dict, slide: int) -> dict:
    """Add ASLR slide to all non-None offsets."""
    return {
        k: (v + slide if v is not None else None)
        for k, v in offsets.items()
    }


def resolve_op_new() -> int:
    """
    Resolve operator new (_Znwm) from libc++.
    This is always from the dyld shared cache — same address in all processes.
    Never uses a Chrome-internal offset.
    """
    import ctypes as C
    libcpp = C.CDLL(ctypes.util.find_library("c++") or "libc++.1.dylib")
    addr = C.cast(libcpp.__getattr__("_Znwm") if hasattr(libcpp, "_Znwm") else None,
                  C.c_void_p)
    if addr.value:
        return addr.value
    # Fallback: dlsym via libdl
    libdl = C.CDLL(ctypes.util.find_library("dl") or "/usr/lib/libdl.dylib")
    libdl.dlsym.restype = C.c_void_p
    RTLD_DEFAULT = C.c_void_p(-2)
    val = libdl.dlsym(RTLD_DEFAULT, b"_Znwm")
    if val:
        return val
    raise RuntimeError("Could not resolve _Znwm (operator new) from libc++")


# ── ASLR slide computation ─────────────────────────────────────────────────

def compute_slide(fw_path: str, runtime_base: int, arch: str) -> int:
    """Compute ASLR slide: runtime_base − on-disk vm_base."""
    with open(fw_path, "rb") as f:
        data = f.read()
    macho = _macho_parse(data, arch)
    return runtime_base - macho["vm_base"]


# ── Utilities ──────────────────────────────────────────────────────────────

def get_chrome_pid() -> int:
    out = subprocess.check_output(["pgrep", "-x", "Google Chrome"], text=True).strip()
    pids = sorted(int(p) for p in out.splitlines())
    if not pids:
        raise RuntimeError("Chrome process not found (is Chrome running?)")
    return pids[0]


def verify(port: int) -> Optional[dict]:
    try:
        with urllib.request.urlopen(f"http://localhost:{port}/json/version", timeout=4) as r:
            return json.loads(r.read())
    except Exception:
        return None


# ── Backend: Mach task APIs + compiled dylib ───────────────────────────────

def activate_mach(pid: int, port: int, offsets_rel: dict, fw_path: str, arch: str) -> bool:
    base = _get_framework_base_mach(pid)
    slide = compute_slide(fw_path, base, arch)
    print(f"[chroma/mach] framework base=0x{base:x}  slide=0x{slide:x}")

    rt = apply_slide(offsets_rel, slide)
    rt["op_new"] = resolve_op_new()
    print(f"[chroma/mach] op_new (libc++)=0x{rt['op_new']:x}")

    if not rt.get("devtools_start") or not rt.get("handler_vtable"):
        raise RuntimeError("Missing devtools_start or handler_vtable offsets")

    src = _build_activation_source(rt, port, arch)
    dylib_path = _compile_dylib(src, arch)
    print(f"[chroma/mach] dylib compiled → {dylib_path}")

    _mach_dlopen(pid, dylib_path, arch)
    print("[chroma/mach] injection thread started")

    for _ in range(10):
        time.sleep(0.5)
        info = verify(port)
        if info:
            return True
    return False


def _get_framework_base_mach(pid: int) -> int:
    import ctypes as C
    from ctypes import c_int, c_uint, c_uint32, c_uint64

    libproc = C.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    proc_regionfilename = libproc.proc_regionfilename
    proc_regionfilename.restype  = c_int
    proc_regionfilename.argtypes = [c_int, c_uint64, C.c_char_p, c_uint32]

    lib = C.CDLL("/usr/lib/libSystem.B.dylib")
    buf  = C.create_string_buffer(4096)
    addr = 0
    step = 0x1000

    while addr < 0x7FFFFFFFFFFF:
        ret = proc_regionfilename(pid, addr, buf, 4096)
        if ret > 0:
            path = buf.value.decode(errors="replace")
            if "Google Chrome Framework" in path:
                return _mach_region_start(lib, pid, addr)
        addr += step
        step  = min(step * 2, 0x100000)

    raise RuntimeError("Google Chrome Framework not found in target vm map")


def _mach_region_start(lib, pid: int, hint: int) -> int:
    import ctypes as C
    from ctypes import c_int, c_uint, c_uint64, c_uint32, byref

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
            f"task_for_pid({pid}) kern_return={ret} — need root or entitlement"
        )

    INFO_COUNT = 20
    addr  = mach_vm_address_t(hint)
    size  = mach_vm_size_t(0)
    depth = c_uint32(99)
    info  = (c_uint32 * INFO_COUNT)()
    count = c_uint32(INFO_COUNT)

    mrr = lib.mach_vm_region_recurse
    mrr.restype  = kern_return_t
    mrr.argtypes = [
        c_uint,
        C.POINTER(mach_vm_address_t), C.POINTER(mach_vm_size_t),
        C.POINTER(c_uint32),
        C.POINTER(c_uint32 * INFO_COUNT),
        C.POINTER(c_uint32),
    ]
    mrr(task, byref(addr), byref(size), byref(depth), byref(info), byref(count))
    return int(addr.value)


def _build_activation_source(rt: dict, port: int, arch: str) -> str:
    # create_server_socket may not be discovered; fall back to a direct
    # TCPServerSocket approach if missing
    csock_line = ""
    if rt.get("create_server_socket"):
        csock_line = f"    ((uint8_t(*)(uint32_t,void*)){rt['create_server_socket']:#x}ULL)({port}, sb);"
    else:
        # Without create_server_socket offset, skip it and pass NULL socket buffer
        # (DevToolsHttpHandler::Start will create its own socket internally on some versions)
        csock_line = "    /* create_server_socket not available for this version */"

    vtable_line = ""
    if rt.get("handler_vtable"):
        vtable_line = f"    *(void**)fc = (void*){rt['handler_vtable']:#x}ULL;"

    return f"""\
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// chroma activation dylib — auto-generated for Chrome {port}
// Version-agnostic: operator new from libc++, offsets from runtime discovery.

__attribute__((constructor))
static void _chroma_activate(void) {{
    void*  (*opnew) (size_t) = (void*(*)(size_t)){rt['op_new']:#x}ULL;
    void   (*dstart)(void*,void*,void*,uint32_t)
                             = (void(*)(void*,void*,void*,uint32_t)){rt.get('devtools_start', 0):#x}ULL;

    void* sb = opnew(0x20); memset(sb, 0, 0x20);
    void* ab = opnew(0x50); memset(ab, 0, 0x50);
    void* fc = opnew(0x20); memset(fc, 0, 0x20);
{vtable_line}
    ((uint16_t*)fc)[4] = (uint16_t){port};
    ((uint16_t*)fc)[5] = (uint16_t)0x2475;

{csock_line}
    dstart(fc, sb, ab, 0);
}}
"""


def _compile_dylib(src: str, arch: str) -> str:
    tmpdir = tempfile.mkdtemp(prefix="chroma_")
    src_p   = os.path.join(tmpdir, "activate.c")
    out_p   = os.path.join(tmpdir, "activate.dylib")
    with open(src_p, "w") as f:
        f.write(src)
    r = subprocess.run(
        ["cc", "-dynamiclib", f"-arch", arch, "-O0", "-o", out_p, src_p],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"Compilation failed:\n{r.stderr}")
    return out_p


def _mach_dlopen(pid: int, dylib_path: str, arch: str):
    import ctypes as C
    from ctypes import c_int, c_uint, c_uint32, c_uint64, c_void_p, byref, POINTER

    lib = C.CDLL("/usr/lib/libSystem.B.dylib")

    mach_port_t       = c_uint
    kern_return_t     = c_int
    mach_vm_address_t = c_uint64
    mach_vm_size_t    = c_uint64
    VM_FLAGS_ANYWHERE = 1
    VM_PROT_READ      = 1
    VM_PROT_WRITE     = 2
    VM_PROT_EXEC      = 4

    tfp     = lib.task_for_pid
    tfp.restype  = kern_return_t
    tfp.argtypes = [mach_port_t, c_int, POINTER(mach_port_t)]

    alloc   = lib.mach_vm_allocate
    alloc.restype  = kern_return_t
    alloc.argtypes = [mach_port_t, POINTER(mach_vm_address_t), mach_vm_size_t, c_int]

    write_m = lib.mach_vm_write
    write_m.restype  = kern_return_t
    write_m.argtypes = [mach_port_t, mach_vm_address_t, c_void_p, c_uint32]

    protect = lib.mach_vm_protect
    protect.restype  = kern_return_t
    protect.argtypes = [mach_port_t, mach_vm_address_t, mach_vm_size_t, c_int, c_int]

    tcr = lib.thread_create_running
    tcr.restype = kern_return_t

    task = mach_port_t(0)
    ret  = tfp(lib.mach_task_self(), pid, byref(task))
    if ret != 0:
        raise PermissionError(f"task_for_pid({pid}) → kern_return={ret}")

    def _alloc_write(data: bytes, prot: int) -> int:
        addr = mach_vm_address_t(0)
        sz   = (len(data) + 0xFFF) & ~0xFFF
        ret = alloc(task, byref(addr), sz, VM_FLAGS_ANYWHERE)
        if ret: raise RuntimeError(f"mach_vm_allocate: {ret}")
        buf = C.create_string_buffer(data)
        ret = write_m(task, addr, buf, len(data))
        if ret: raise RuntimeError(f"mach_vm_write: {ret}")
        ret = protect(task, addr, sz, 0, prot)
        if ret: raise RuntimeError(f"mach_vm_protect: {ret}")
        return int(addr.value)

    path_addr = _alloc_write(dylib_path.encode() + b"\x00", VM_PROT_READ)

    _libdl  = C.CDLL(ctypes.util.find_library("dl") or "/usr/lib/libdl.dylib")
    _libpth = C.CDLL(ctypes.util.find_library("pthread") or "/usr/lib/libpthread.dylib")
    dlopen_addr       = C.cast(_libdl.dlopen,       c_void_p).value
    pthread_exit_addr = C.cast(_libpth.pthread_exit, c_void_p).value
    if not dlopen_addr:
        raise RuntimeError("dlopen address not found in dyld shared cache")

    if arch == "x86_64":
        sc  = b"\x48\x83\xec\x08"
        sc += b"\x48\xbf" + struct.pack("<Q", path_addr)
        sc += b"\xbe\x02\x00\x00\x00"
        sc += b"\x48\xb8" + struct.pack("<Q", dlopen_addr)
        sc += b"\xff\xd0"
        sc += b"\x31\xff"
        sc += b"\x48\xb8" + struct.pack("<Q", pthread_exit_addr)
        sc += b"\xff\xd0"

        sc_addr = _alloc_write(sc, VM_PROT_READ | VM_PROT_EXEC)

        STACK_SIZE = 0x20000
        stk = mach_vm_address_t(0)
        alloc(task, byref(stk), STACK_SIZE, VM_FLAGS_ANYWHERE)
        protect(task, stk, STACK_SIZE, 0, VM_PROT_READ | VM_PROT_WRITE)
        rsp_val = int(stk.value) + STACK_SIZE - 8

        X86_THREAD_STATE64       = 4
        X86_THREAD_STATE64_COUNT = 42
        state = (c_uint32 * X86_THREAD_STATE64_COUNT)(*([0] * X86_THREAD_STATE64_COUNT))

        def s64(idx64, val):
            state[idx64*2]   = val & 0xFFFFFFFF
            state[idx64*2+1] = (val >> 32) & 0xFFFFFFFF

        s64(16, sc_addr); s64(7, rsp_val); s64(17, 0x202)

        thread = mach_port_t(0)
        tcr.argtypes = [
            mach_port_t, c_int,
            C.POINTER(c_uint32 * X86_THREAD_STATE64_COUNT),
            c_uint32, C.POINTER(mach_port_t),
        ]
        ret = tcr(task, X86_THREAD_STATE64, byref(state), X86_THREAD_STATE64_COUNT, byref(thread))
        if ret != 0:
            raise RuntimeError(f"thread_create_running: kern_return={ret}")
        print(f"[chroma/mach] thread 0x{thread.value:x} executing dlopen")

    elif arch == "arm64":
        # arm64 shellcode: call dlopen(path, RTLD_NOW=2), then pthread_exit(0)
        # Using BLR Xn pattern; load addresses via LDR literal from a pool
        pool = struct.pack("<QQ", path_addr, dlopen_addr) + \
               struct.pack("<QQ", pthread_exit_addr, 0)
        # Instructions (offsets relative to shellcode start):
        # LDR  x0, #16      ; path_addr
        # MOV  w1, #2       ; RTLD_NOW
        # LDR  x8, #16      ; dlopen_addr
        # BLR  x8
        # MOV  x0, #0       ; exit code
        # LDR  x8, #16      ; pthread_exit_addr
        # BLR  x8
        # <literal pool>
        sc = struct.pack("<IIIIIII",
            0x58000080,   # LDR x0, #16  (pc+16)
            0x52800041,   # MOV w1, #2
            0x580000C8,   # LDR x8, #24  (pc+24)
            0xD63F0100,   # BLR x8
            0xAA1F03E0,   # MOV x0, xzr
            0x58000088,   # LDR x8, #16  (pc+16)
            0xD63F0100,   # BLR x8
        )
        sc += pool

        sc_addr = _alloc_write(sc, VM_PROT_READ | VM_PROT_EXEC)

        ARM_THREAD_STATE64       = 6
        ARM_THREAD_STATE64_COUNT = 68   # 34 × uint64 as uint32 pairs

        state = (c_uint32 * ARM_THREAD_STATE64_COUNT)(*([0] * ARM_THREAD_STATE64_COUNT))
        # PC is at index 32 (arm64 thread state layout: x0-x28, fp, lr, sp, pc, cpsr)
        PC_IDX = 32
        SP_IDX = 31

        STACK_SIZE = 0x20000
        stk = mach_vm_address_t(0)
        alloc(task, byref(stk), STACK_SIZE, VM_FLAGS_ANYWHERE)
        protect(task, stk, STACK_SIZE, 0, VM_PROT_READ | VM_PROT_WRITE)
        sp_val = int(stk.value) + STACK_SIZE - 16

        def s64a(idx, val):
            state[idx*2]   = val & 0xFFFFFFFF
            state[idx*2+1] = (val >> 32) & 0xFFFFFFFF

        s64a(PC_IDX, sc_addr)
        s64a(SP_IDX, sp_val)

        thread = mach_port_t(0)
        tcr.argtypes = [
            mach_port_t, c_int,
            C.POINTER(c_uint32 * ARM_THREAD_STATE64_COUNT),
            c_uint32, C.POINTER(mach_port_t),
        ]
        ret = tcr(task, ARM_THREAD_STATE64, byref(state), ARM_THREAD_STATE64_COUNT, byref(thread))
        if ret != 0:
            raise RuntimeError(f"thread_create_running (arm64): kern_return={ret}")
        print(f"[chroma/mach] arm64 thread 0x{thread.value:x} executing dlopen")
    else:
        raise ValueError(f"Unsupported arch for mach backend: {arch}")


# ── Backend: lldb ──────────────────────────────────────────────────────────

def activate_lldb(pid: int, port: int, offsets_rel: dict, fw_path: str, arch: str) -> bool:
    r = subprocess.run(
        ["lldb", "-p", str(pid), "--batch",
         "-o", 'image list "Google Chrome Framework"'],
        capture_output=True, text=True, timeout=15,
    )
    m = re.search(r"\]\s+\S+\s+(0x[0-9a-f]+)\s+.*Google Chrome Framework", r.stdout, re.I)
    if not m:
        raise RuntimeError(f"lldb could not find module base:\n{r.stdout}\n{r.stderr}")

    base  = int(m.group(1), 16)
    slide = compute_slide(fw_path, base, arch)
    print(f"[chroma/lldb] framework base=0x{base:x}  slide=0x{slide:x}")

    rt = apply_slide(offsets_rel, slide)
    rt["op_new"] = resolve_op_new()

    if not rt.get("devtools_start"):
        raise RuntimeError("devtools_start offset required for lldb backend")

    cmds = [
        f"expr void* $opnew = (void*){rt['op_new']:#x}ULL",
        f"expr void* $sb = ((void*(*)(size_t))$opnew)(0x20)",
        f"expr (void)memset($sb, 0, 0x20)",
        f"expr void* $ab = ((void*(*)(size_t))$opnew)(0x50)",
        f"expr (void)memset($ab, 0, 0x50)",
        f"expr void* $fc = ((void*(*)(size_t))$opnew)(0x20)",
        f"expr (void)memset($fc, 0, 0x20)",
    ]
    if rt.get("handler_vtable"):
        cmds += [
            f"expr *(void**)$fc = (void*){rt['handler_vtable']:#x}ULL",
        ]
    cmds += [
        f"expr ((unsigned short*)$fc)[4] = (unsigned short){port}",
        f"expr ((unsigned short*)$fc)[5] = (unsigned short)0x2475",
    ]
    if rt.get("create_server_socket"):
        cmds.append(
            f"expr (unsigned char)"
            f"((unsigned char(*)(unsigned int,void*)){rt['create_server_socket']:#x}ULL)"
            f"({port}, $sb)"
        )
    cmds += [
        f"expr (void)((void(*)(void*,void*,void*,unsigned int)){rt['devtools_start']:#x}ULL)"
        f"($fc, $sb, $ab, 0)",
        "quit",
    ]

    with tempfile.NamedTemporaryFile("w", suffix=".lldb", delete=False) as f:
        f.write("\n".join(cmds) + "\n")
        cmd_file = f.name

    try:
        r = subprocess.run(
            ["lldb", "-p", str(pid), "--batch", "-s", cmd_file],
            capture_output=True, text=True, timeout=25,
        )
        if r.returncode not in (0, 1):
            print(f"[chroma/lldb] stderr: {r.stderr[:600]}")
    finally:
        os.unlink(cmd_file)

    for _ in range(10):
        time.sleep(0.5)
        info = verify(port)
        if info:
            return True
    return False


def _import_frida():
    """
    Import frida, trying Homebrew site-packages if the default import fails.
    This handles `sudo python3` which may use /usr/bin/python3 instead of
    the Homebrew python that has frida installed.
    """
    try:
        import frida
        return frida
    except ImportError:
        pass

    # Try known Homebrew paths (arm64 + x86_64 prefixes)
    homebrew_roots = [
        "/opt/homebrew/lib",           # arm64 (Apple Silicon)
        "/usr/local/lib",              # x86_64 (Intel)
    ]
    import importlib, importlib.util, glob as _glob, sys as _sys

    for root in homebrew_roots:
        for sp in _glob.glob(f"{root}/python3*/site-packages"):
            if sp not in _sys.path:
                _sys.path.insert(0, sp)
            try:
                import frida
                return frida
            except ImportError:
                continue

    raise RuntimeError(
        "frida not importable — run: pip install frida\n"
        "If using sudo, ensure frida is installed for the system python:\n"
        "  sudo /opt/homebrew/bin/pip3 install frida"
    )


def activate_frida(pid: int, port: int, offsets_rel: dict, fw_path: str, arch: str) -> bool:
    frida = _import_frida()

    session  = frida.attach(pid)
    result   = {}
    done_evt = __import__("threading").Event()

    def on_msg(msg, _):
        if msg["type"] == "send":
            result.update({"module_base": msg["payload"]})
            done_evt.set()

    scr = session.create_script(
        "var m=Process.getModuleByName('Google Chrome Framework');"
        "send({base:m.base.toString()});"
    )
    scr.on("message", on_msg)
    scr.load()
    done_evt.wait(timeout=5)

    base  = int(result["module_base"], 16)
    slide = compute_slide(fw_path, base, arch)
    print(f"[chroma/frida] framework base=0x{base:x}  slide=0x{slide:x}")

    rt = apply_slide(offsets_rel, slide)
    rt["op_new"] = resolve_op_new()

    if not rt.get("devtools_start"):
        raise RuntimeError("devtools_start offset required for frida backend")

    JS = """
(function() {
    var rt = RT; var port = PORT;
    try {
        var opNew  = new NativeFunction(ptr(rt.op_new), 'pointer', ['uint32']);
        var dstart = new NativeFunction(ptr(rt.devtools_start), 'void',
                                        ['pointer','pointer','pointer','uint32']);
        var sb = opNew(0x20); sb.writeByteArray(new Array(0x20).fill(0));
        var ab = opNew(0x50); ab.writeByteArray(new Array(0x50).fill(0));
        var fc = opNew(0x20); fc.writeByteArray(new Array(0x20).fill(0));
        if (rt.handler_vtable) fc.writePointer(ptr(rt.handler_vtable));
        fc.add(8).writeU16(port); fc.add(10).writeU16(0x2475);
        if (rt.create_server_socket) {
            var csock = new NativeFunction(ptr(rt.create_server_socket),
                                            'uint8', ['uint32','pointer']);
            csock(port, sb);
        }
        dstart(fc, sb, ab, 0);
        send('[chroma/frida] DevToolsHttpHandler::Start called');
    } catch(e) { send('[chroma/frida] ERROR: ' + e.message); }
})();
""".replace("RT", json.dumps({k: hex(v) if v else None for k, v in rt.items()})) \
   .replace("PORT", str(port))

    msgs = []
    scr2 = session.create_script(JS)
    scr2.on("message", lambda m, _: (print(m.get("payload", "")),
                                      msgs.append(m)) if m["type"] == "send" else None)
    scr2.load()
    time.sleep(3)
    session.detach()

    for _ in range(10):
        time.sleep(0.5)
        info = verify(port)
        if info:
            return True
    return False


# ── Orchestrator ───────────────────────────────────────────────────────────

BACKENDS = {
    "mach":  activate_mach,
    "lldb":  activate_lldb,
    "frida": activate_frida,
}


def activate(
    port: int = 9222,
    pid: Optional[int] = None,
    backend: str = "auto",
    force_scan: bool = False,
    manual_offsets: Optional[dict] = None,
) -> bool:
    if pid is None:
        pid = get_chrome_pid()
    print(f"[chroma] target PID {pid}, port {port}")

    if verify(port):
        print(f"[chroma] CDP already active on :{port}")
        return True

    arch    = get_arch()
    version = get_chrome_version()
    fw_path = get_framework_path()
    print(f"[chroma] Chrome {version} ({arch})")

    offsets_rel = resolve_offsets(
        version, arch, fw_path,
        force_scan=force_scan,
        manual=manual_offsets,
    )
    print(f"[chroma] offsets resolved: { {k: hex(v) if v else None for k,v in offsets_rel.items()} }")

    order = list(BACKENDS.keys()) if backend == "auto" else [backend]
    for name in order:
        print(f"[chroma] trying backend: {name}")
        try:
            ok = BACKENDS[name](pid, port, offsets_rel, fw_path, arch)
            if ok:
                info = verify(port)
                print(f"\n[chroma] ✅  CDP active!")
                print(f"  Browser : {info.get('Browser')}")
                print(f"  WS URL  : {info.get('webSocketDebuggerUrl')}")
                return True
            else:
                print(f"[chroma] {name}: started but port not responding")
        except Exception as e:
            print(f"[chroma] {name} failed: {e}")
            if backend != "auto":
                raise

    print("[chroma] ❌  All backends failed")
    return False


# ── CLI ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="chroma — version-agnostic runtime CDP activation for Chrome"
    )
    ap.add_argument("port",      nargs="?", type=int, default=9222)
    ap.add_argument("pid",       nargs="?", type=int, default=None)
    ap.add_argument("--backend", choices=[*BACKENDS.keys(), "auto"], default="auto")
    ap.add_argument("--scan",    action="store_true",
                    help="Force re-scan even if offsets are cached")
    ap.add_argument("--offset",  action="append", default=[], metavar="KEY=0xVALUE",
                    help="Manual offset override, e.g. --offset devtools_start=0x1234")
    args = ap.parse_args()

    manual = {}
    for o in args.offset:
        k, v = o.split("=", 1)
        manual[k.strip()] = int(v.strip(), 16)

    ok = activate(
        port=args.port,
        pid=args.pid,
        backend=args.backend,
        force_scan=args.scan,
        manual_offsets=manual or None,
    )
    sys.exit(0 if ok else 1)
