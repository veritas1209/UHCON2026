#!/usr/bin/env python3
"""Create a local ELF copy whose PT_INTERP names the provided loader.

This copy lets WSL exercise the challenge's normal kernel exec path with the
provided glibc. The original extracted binary is never modified.
"""
import os
import struct
from pathlib import Path

root = Path(__file__).resolve().parent
src = root / "extracted/deploy/blitter"
dst = root / "blitter-direct"
interp = str(root / "extracted/lib/ld-linux-x86-64.so.2").encode() + b"\0"
buf = bytearray(src.read_bytes())
assert buf[:4] == b"\x7fELF" and buf[4] == 2 and buf[5] == 1
phoff = struct.unpack_from("<Q", buf, 32)[0]
phentsize, phnum = struct.unpack_from("<HH", buf, 54)
assert phentsize == 56
found = False
for i in range(phnum):
    off = phoff + i * phentsize
    ptype = struct.unpack_from("<I", buf, off)[0]
    if ptype == 3:  # PT_INTERP
        struct.pack_into("<Q", buf, off+8, len(buf))
        struct.pack_into("<Q", buf, off+32, len(interp))
        struct.pack_into("<Q", buf, off+40, len(interp))
        found = True
        break
assert found
buf.extend(interp)
dst.write_bytes(buf)
os.chmod(dst, 0o755)
print(dst)
