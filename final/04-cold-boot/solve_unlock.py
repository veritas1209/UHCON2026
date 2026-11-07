#!/usr/bin/env python3
"""Compute the HomeHub service-console `unlock` response from serial and nonce."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


MASK64 = (1 << 64) - 1
TABLE_OFFSET = 0x5DFB8
BYTECODE_OFFSET = 0x5DFD8
BYTECODE_SIZE = 0x90


def u64(value: int) -> int:
    return value & MASK64


def ror64(value: int, count: int) -> int:
    count &= 63
    value &= MASK64
    if count == 0:
        return value
    return ((value >> count) | (value << (64 - count))) & MASK64


def decode_program(blob: bytes) -> list[tuple[int, int, int, int]]:
    encoded = blob[BYTECODE_OFFSET : BYTECODE_OFFSET + BYTECODE_SIZE]
    if len(encoded) != BYTECODE_SIZE:
        raise ValueError("platform binary is truncated")
    decoded = [byte ^ (((index * 61) - 0x59) & 0xFF) for index, byte in enumerate(encoded)]
    return [tuple(decoded[index : index + 4]) for index in range(0, BYTECODE_SIZE, 4)]


def solve(blob: bytes, serial: int, nonce: int, trace: bool = False) -> int:
    tables = struct.unpack_from("<4Q", blob, TABLE_OFFSET)
    nonce &= 0xFFFFFFFF
    state = [
        serial,
        (nonce << 32) | nonce,
        serial ^ 0xD6E8FEB86659FD93,
        (nonce << 17) ^ 0xA0761D6478BD642F,
    ]
    state = [u64(value) for value in state]

    for pc, (b0, b1, b2, b3) in enumerate(decode_program(blob)):
        word = b1 | (b2 << 8)
        other = (b0 >> 5) & 3
        source = (b0 >> 3) & 3
        opcode = b0 & 7
        immediate = u64((b3 | (word << 40)) ^ tables[b3 & 3])
        source_value = state[source]

        if opcode == 0:
            value = ror64(immediate ^ state[other], -word) + source_value
        elif opcode == 1:
            value = ror64(immediate + state[other], -(word ^ b3)) ^ source_value
        elif opcode == 2:
            multiplier = tables[(b3 >> 2) & 3] | 1
            mixed = (immediate + state[other]) ^ source_value
            value = multiplier * mixed + word
        elif opcode == 3:
            mixed = ror64(immediate + state[other], -word)
            # b3&3 selects the immediate-XOR table; it is not a state
            # destination.  The native loop writes the mixed value back to
            # the state selected by b0 bits 3..4 (x5 at 0x8ec0).
            state[source] = u64(mixed)
            state[other] = u64(source_value ^ tables[(b3 >> 4) & 3] ^ mixed)
            if trace:
                print(f"{pc:02d}: op={opcode} state=" + " ".join(f"{x:016x}" for x in state))
            continue
        elif opcode == 4:
            shift = (word & 0xF) + 5
            mixed = (source_value >> shift) ^ source_value
            value = mixed * (tables[(b3 >> 5) & 3] | 1)
        elif opcode == 5:
            value = (ror64(source_value, -b3) + state[other]) ^ immediate
        elif opcode == 6:
            shift = (b3 & 7) + 7
            mixed = (state[other] >> shift) ^ state[other]
            value = mixed * (immediate | 1) + source_value
        else:
            value = ror64(source_value + state[other] + immediate, -(word ^ b3))

        state[source] = u64(value)
        if trace:
            print(f"{pc:02d}: op={opcode} state=" + " ".join(f"{x:016x}" for x in state))

    result = ror64(state[2], 35) ^ ror64(state[1], 53)
    # The native code reloads [sp+0x48] after the VM.  That slot is state[0]
    # and may have been mutated; it is not the original serial anymore.
    result ^= state[0] ^ state[3]
    result ^= result >> 31
    result = u64(result * 0x9FB21C651E98DF25)
    result ^= result >> 28
    return u64(result)


def parse_number(value: str) -> int:
    return int(value, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("platform", type=Path)
    parser.add_argument("serial", type=parse_number, help="printed device serial, e.g. 0x0123...")
    parser.add_argument("nonce", type=parse_number, help="printed maintenance nonce")
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_args()
    response = solve(args.platform.read_bytes(), args.serial, args.nonce, args.trace)
    print(f"unlock {response:016x}")


if __name__ == "__main__":
    main()
