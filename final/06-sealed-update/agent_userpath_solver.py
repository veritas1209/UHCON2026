#!/usr/bin/env python3
"""Model and invert the original ARM64 uhattest user-space token path.

This tool never opens /dev/uhsec and never submits a flag.  `forward` shows the
canonical FLAG string that uhattest would place in its ioctl request. `inverse`
turns a kernel-required 32-byte value into the exact argv FLAG preimage.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
from pathlib import Path


MASK = 0xFFFFFFFF
MOD32 = 1 << 32
ROOT = Path(__file__).resolve().parent
INITRAMFS = ROOT / "extracted" / "initramfs"
UHATTEST = INITRAMFS / "uhattest"
BLOB_PATH = INITRAMFS / "attest_blob.bin"
POLICY_PATH = INITRAMFS / "device-policy.bin"

EXPECTED = {
    UHATTEST: "588318a2dcfe727e7582e28623b60d10686d0c68eae48f6235118f7c7e690924",
    BLOB_PATH: "43acc44831dde00ff4f0657667a11ba4ccbd2401642104f82cbb8a1b2d11e8a6",
    POLICY_PATH: "73ff827c4a4fd6c51a2a3de6bf395c7f52c1c9ed7ad5db9015b1ab9b10765d69",
}

FLAG_RE = re.compile(r"FLAG\{([0-9a-f]{64})\}\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")


def u32(value: int) -> int:
    return value & MASK


def rol(value: int, count: int) -> int:
    count &= 31
    value &= MASK
    return u32((value << count) | (value >> ((32 - count) & 31)))


def ror(value: int, count: int) -> int:
    return rol(value, -count)


def bitrev32(value: int) -> int:
    value = ((value << 1) & 0xAAAAAAAA) | ((value & 0xAAAAAAAA) >> 1)
    value = ((value << 2) & 0xCCCCCCCC) | ((value & 0xCCCCCCCC) >> 2)
    value = ((value << 4) & 0xF0F0F0F0) | ((value & 0xF0F0F0F0) >> 4)
    return int.from_bytes(u32(value).to_bytes(4, "little"), "big")


def mix(keys: tuple[int, int, int, int], seed: int, index: int) -> int:
    """16-round mixer at uhattest 0x40131c."""

    seed = u32(seed)
    index = u32(index)
    left = u32(index * 0xA24BAED5) ^ seed ^ 0xD62F91B5
    right = u32(index * 0x6D2B79F5) ^ ror(seed, 16) ^ 0x13579BDF
    total = 0
    while True:
        nonlinear = u32(((right >> 5) ^ u32(right << 4)) + right)
        left = u32(left + (u32(keys[total & 3] + total) ^ nonlinear))
        total = u32(total + 0x9E3779B9)
        nonlinear = u32(((left >> 5) ^ u32(left << 4)) + left)
        right = u32(
            right + (u32(keys[(total >> 11) & 3] + total) ^ nonlinear)
        )
        if total == 0xE3779B90:
            break
    return u32(left ^ ror(right, 19))


def mix_byte(keys: tuple[int, int, int, int], seed: int, index: int) -> int:
    return (mix(keys, seed, index) >> ((index & 3) * 8)) & 0xFF


def decode_u16(
    raw: bytes,
    offset: int,
    keys: tuple[int, int, int, int],
    seed: int,
    index: int,
) -> int:
    key = mix_byte(keys, seed, index)
    key |= mix_byte(keys, seed, index + 1) << 8
    return struct.unpack_from("<H", raw, offset)[0] ^ key


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_inputs() -> tuple[bytes, bytes]:
    for path, expected in EXPECTED.items():
        actual = digest(path)
        if actual != expected:
            raise ValueError(f"identity mismatch for {path}: {actual} != {expected}")

    elf = UHATTEST.read_bytes()
    external_blob = BLOB_PATH.read_bytes()
    # 0x400710..0x4007f8 reconstructs the blob by round-robin selection from
    # seven rodata tables, starting 0x10 bytes into each table.
    tables = [
        0x4639C0,
        0x4614C0,
        0x45EFC0,
        0x45CAC0,
        0x45A5C0,
        0x4580C0,
        0x455BC0,
    ]
    embedded_blob = bytes(
        elf[(tables[i % 7] - 0x400000) + i // 7 + 0x10]
        for i in range(0x10260)
    )
    if embedded_blob != external_blob:
        raise ValueError("embedded blob reconstruction does not match attest_blob.bin")
    return external_blob, POLICY_PATH.read_bytes()


def inverse_xor_lshift(value: int, shift: int) -> int:
    result = value & MASK
    for amount in range(shift, 32, shift):
        result ^= u32(value << amount)
    return u32(result)


def inverse_xor_rshift(value: int, shift: int) -> int:
    result = value & MASK
    for amount in range(shift, 32, shift):
        result ^= value >> amount
    return u32(result)


def reverse_bytes32(value: int) -> int:
    return int.from_bytes(u32(value).to_bytes(4, "little"), "big")


def decode_trace(blob: bytes) -> list[tuple[int, int, int, int, int]]:
    """Decode all 4096*8 state-independent micro-operations."""

    if len(blob) != 0x10260:
        raise ValueError(f"unexpected blob size {len(blob):#x}")
    if struct.unpack_from("<hhhh", blob, 8) != (5, 0x60, 0x40, 8):
        raise ValueError("unexpected attest-blob header")
    if struct.unpack_from("<I", blob, 0x10)[0] != 0x1000:
        raise ValueError("unexpected instruction count")
    if struct.unpack_from("<I", blob, 0x24)[0] != len(blob):
        raise ValueError("unexpected declared blob size")

    keys = (
        struct.unpack_from("<I", blob, 0x18)[0],
        *struct.unpack_from("<3I", blob, 0x34),
    )
    pc = struct.unpack_from("<H", blob, 0x2C)[0]
    final_pc = struct.unpack_from("<H", blob, 0x2E)[0]
    previous_pc = 0xFFFF
    trace: list[tuple[int, int, int, int, int]] = []

    for counter in range(0x1000):
        offset = 0x260 + pc * 16
        record = blob[offset : offset + 16]
        if len(record) != 16:
            raise ValueError(f"record outside blob: pc={pc:#x}")
        base = pc * 16
        opcode = record[0] ^ mix_byte(keys, 0x91E10DA5, base)
        reg_a = record[1] ^ mix_byte(keys, 0xD192ED03, base + 1)
        reg_b = record[2] ^ mix_byte(keys, 0x94D049BB, base + 2)
        rotate_base = record[3] ^ mix_byte(keys, 0x8538ECB5, base + 3)
        rotate_base -= 1
        immediate = struct.unpack_from("<I", record, 4)[0]
        immediate ^= mix(keys, 0xB5297A4D, counter)
        check_counter = decode_u16(record, 8, keys, 0x68E31DA4, base + 8)
        check_previous = decode_u16(record, 10, keys, 0xA54FF53A, base + 10)
        next_pc = decode_u16(record, 12, keys, 0x510E527F, base + 12)
        checksum = decode_u16(record, 14, keys, 0x9B05688C, base + 14)
        expected_checksum = mix(
            keys,
            (next_pc << 16) ^ check_previous ^ 0x9B05688C,
            counter ^ (pc << 16),
        ) & 0xFFFF

        if not (opcode <= 0x3F and reg_a <= 7 and reg_b <= 7):
            raise ValueError(f"bad opcode/register at instruction {counter}")
        if reg_a == reg_b or not (0 <= rotate_base <= 30):
            raise ValueError(f"bad register/rotation at instruction {counter}")
        if (check_counter, check_previous, checksum) != (
            counter,
            previous_pc,
            expected_checksum,
        ):
            raise ValueError(f"record-chain failure at instruction {counter}")

        salt = immediate ^ 0xA24BAED5
        for micro_index in range(8):
            control_index = opcode * 8 + micro_index
            control = blob[0x60 + control_index]
            control ^= mix_byte(keys, 0xC13FA9A9, control_index)
            subop = control & 0x1F
            if subop > 23:
                raise ValueError(f"bad micro-op {subop} at instruction {counter}")
            dst = (((control >> 5) & 3) + reg_a) & 7
            src = ((control >> 7) + reg_b) & 7
            if dst == src:
                src = (dst + 1) & 7
            rotate = (((control >> 5) * 5 + rotate_base) % 31) + 1
            random = mix(
                keys,
                salt,
                (counter ^ (opcode << 24)) ^ (micro_index << 16),
            )
            trace.append((subop, dst, src, rotate, random))
            reg_a = u32(reg_a + 1)
            reg_b = u32(reg_b + 3)
            rotate_base = u32(rotate_base + 7)

        if counter == 0xFFF:
            if next_pc != 0xFFFF or pc != final_pc:
                raise ValueError("bad final record or terminator")
        else:
            if next_pc > 0xFFF:
                raise ValueError(f"bad next pc at instruction {counter}")
            previous_pc = pc
            pc = next_pc

    return trace


def forward_vm(blob: bytes, raw: bytes) -> bytes:
    if len(raw) != 32:
        raise ValueError("argv payload must be exactly 32 bytes")
    state = list(struct.unpack("<8I", raw))

    for subop, dst, src, rotate, random in decode_trace(blob):
        if subop == 18:
            state[dst], state[src] = state[src], state[dst]
            continue
        x = state[dst]
        y = state[src]
        p = rol(random ^ y, rotate)
        q = rol(u32(random + y), rotate)

        if subop == 0:
            x ^= random
        elif subop == 1:
            x = u32(x + random)
        elif subop == 2:
            x = u32(x - random)
        elif subop == 3:
            x = rol(x, rotate)
        elif subop == 4:
            x = ror(x, rotate)
        elif subop == 5:
            x ^= p
        elif subop == 6:
            x = u32(x + p)
        elif subop == 7:
            x = u32(x - p)
        elif subop == 8:
            x = u32(x * (random | 1))
        elif subop == 9:
            x ^= u32(x << rotate)
        elif subop == 10:
            x ^= x >> rotate
        elif subop == 11:
            x = ~x
        elif subop == 12:
            x = -x
        elif subop == 13:
            x = reverse_bytes32(x)
        elif subop == 14:
            x = bitrev32(x)
        elif subop == 15:
            x ^= q
        elif subop == 16:
            x = u32(x + q)
        elif subop == 17:
            x = u32(x - q)
        elif subop == 19:
            x = rol(x ^ random, rotate)
        elif subop == 20:
            x = rol(u32(x + random), rotate)
        elif subop == 21:
            x = rol(u32(x - random), rotate)
        elif subop == 22:
            x ^= ror(random ^ y, rotate)
        elif subop == 23:
            x = u32(x + ror(u32(random + y), rotate))
        else:
            raise AssertionError(subop)
        state[dst] = u32(x)

    return struct.pack("<8I", *state)


def invert_vm(blob: bytes, desired: bytes) -> bytes:
    if len(desired) != 32:
        raise ValueError("desired kernel payload must be exactly 32 bytes")
    state = list(struct.unpack("<8I", desired))

    for subop, dst, src, rotate, random in reversed(decode_trace(blob)):
        if subop == 18:
            state[dst], state[src] = state[src], state[dst]
            continue
        x = state[dst]
        y = state[src]
        p = rol(random ^ y, rotate)
        q = rol(u32(random + y), rotate)

        if subop == 0:
            x ^= random
        elif subop == 1:
            x = u32(x - random)
        elif subop == 2:
            x = u32(x + random)
        elif subop == 3:
            x = ror(x, rotate)
        elif subop == 4:
            x = rol(x, rotate)
        elif subop == 5:
            x ^= p
        elif subop == 6:
            x = u32(x - p)
        elif subop == 7:
            x = u32(x + p)
        elif subop == 8:
            x = u32(x * pow(random | 1, -1, MOD32))
        elif subop == 9:
            x = inverse_xor_lshift(x, rotate)
        elif subop == 10:
            x = inverse_xor_rshift(x, rotate)
        elif subop == 11:
            x = ~x
        elif subop == 12:
            x = -x
        elif subop == 13:
            x = reverse_bytes32(x)
        elif subop == 14:
            x = bitrev32(x)
        elif subop == 15:
            x ^= q
        elif subop == 16:
            x = u32(x - q)
        elif subop == 17:
            x = u32(x + q)
        elif subop == 19:
            x = ror(x, rotate) ^ random
        elif subop == 20:
            x = u32(ror(x, rotate) - random)
        elif subop == 21:
            x = u32(ror(x, rotate) + random)
        elif subop == 22:
            x ^= ror(random ^ y, rotate)
        elif subop == 23:
            x = u32(x - ror(u32(random + y), rotate))
        else:
            raise AssertionError(subop)
        state[dst] = u32(x)

    return struct.pack("<8I", *state)


def parse_argv_flag(value: str) -> bytes:
    match = FLAG_RE.fullmatch(value)
    if not match:
        raise ValueError("expected exactly FLAG{64 lowercase hex}")
    return bytes.fromhex(match.group(1))


def parse_kernel_target(value: str) -> bytes:
    match = FLAG_RE.fullmatch(value)
    if match:
        value = match.group(1)
    if not HEX_RE.fullmatch(value):
        raise ValueError("expected FLAG{64 lowercase hex} or 64 lowercase hex")
    return bytes.fromhex(value)


def format_flag(value: bytes) -> str:
    return f"FLAG{{{value.hex()}}}"


def policy_kdf(policy: bytes) -> int:
    value = struct.unpack_from("<I", policy, 0x14)[0]
    value = ror(value ^ 0x6C8E9CF5, 23)
    value = u32(value + 0x2D358DCC)
    value ^= value >> 17
    value = u32(value * 0xA4C7E395)
    value ^= value >> 11
    return u32(value)


def ioctl_request(policy: bytes) -> int:
    derived = policy_kdf(policy)
    return u32(
        0x40200000
        | ((derived & 0xF8000000) >> 19)
        | ((derived ^ len(policy)) & 0xFF)
    )


def show_info(blob: bytes, policy: bytes) -> None:
    request = ioctl_request(policy)
    print(f"uhattest_sha256={digest(UHATTEST)}")
    print(f"attest_blob_sha256={digest(BLOB_PATH)}")
    print(f"device_policy_sha256={digest(POLICY_PATH)}")
    print(f"initial_pc=0x{struct.unpack_from('<H', blob, 0x2c)[0]:04x}")
    print(f"final_pc=0x{struct.unpack_from('<H', blob, 0x2e)[0]:04x}")
    print(f"micro_ops={len(decode_trace(blob))}")
    print(f"policy_length={len(policy)}")
    print(f"policy_kdf=0x{policy_kdf(policy):08x}")
    print(f"ioctl_request=0x{request:08x}")
    print(f"ioctl_dir={(request >> 30) & 3}")
    print(f"ioctl_size={(request >> 16) & 0x3fff}")
    print(f"ioctl_type=0x{(request >> 8) & 0xff:02x}")
    print(f"ioctl_nr=0x{request & 0xff:02x}")


def selftest(blob: bytes) -> None:
    vectors = [
        bytes(range(32)),
        bytes(reversed(range(32))),
        hashlib.sha256(b"UHCON-2026-uhattest-userpath-selftest").digest(),
    ]
    for index, raw in enumerate(vectors):
        transformed = forward_vm(blob, raw)
        recovered = invert_vm(blob, transformed)
        if recovered != raw:
            raise AssertionError(f"round trip failed for vector {index}")
        print(
            f"vector[{index}] input={raw.hex()} output={transformed.hex()} roundtrip=ok"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("info")
    forward = subs.add_parser("forward")
    forward.add_argument("token", help="exact FLAG{64 lowercase hex} argv token")
    inverse = subs.add_parser("inverse")
    inverse.add_argument("target", help="desired kernel FLAG or its 64 hex bytes")
    subs.add_parser("selftest")
    args = parser.parse_args()

    blob, policy = validate_inputs()
    if args.command == "info":
        show_info(blob, policy)
    elif args.command == "forward":
        raw = parse_argv_flag(args.token)
        print(f"argv_token={format_flag(raw)}")
        print(f"kernel_token={format_flag(forward_vm(blob, raw))}")
    elif args.command == "inverse":
        target = parse_kernel_target(args.target)
        raw = invert_vm(blob, target)
        if forward_vm(blob, raw) != target:
            raise AssertionError("inverse/forward round trip failed")
        print(f"kernel_token={format_flag(target)}")
        print(f"argv_token={format_flag(raw)}")
    elif args.command == "selftest":
        selftest(blob)
    else:
        raise AssertionError(args.command)


if __name__ == "__main__":
    main()
