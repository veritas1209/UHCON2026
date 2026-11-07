#!/usr/bin/env python3
"""Latchwork trace replayer and solver.

Load the shipped PIE ELF without executing it, apply its static relocations,
and emulate only the pure dispatcher at virtual address 0x90640.
"""

from __future__ import annotations

import argparse
import csv
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSP


ROOT = Path(__file__).resolve().parent
DEFAULT_BINARY = ROOT / "files" / "chall"
DEFAULT_CAPTURE = ROOT / "files" / "capture.csv"
MASK32 = 0xFFFFFFFF
ALPHABET = b"abcdefghijklmnopqrstuvwxyz0123456789_"
PHI32 = 0x9E3779B9
ROUND_CONST = 0x7F4A7C15
NONZERO_CYCLES = (107, 109, 110, 111, 112, 113, 115, 116, 117, 118,
                  120, 121, 122, 123, 124, 125, 126, 127)


def u32(value: int) -> int:
    return value & MASK32


def mix32(value: int) -> int:
    value = u32(value)
    value = u32((value ^ (value >> 16)) * 0x7FEB352D)
    value = u32((value ^ (value >> 15)) * 0x846CA68B)
    return u32(value ^ (value >> 16))


def rol32(value: int, amount: int) -> int:
    amount &= 31
    value = u32(value)
    if amount == 0:
        return value
    return u32((value << amount) | (value >> (32 - amount)))


def ror32(value: int, amount: int) -> int:
    return rol32(value, -amount)


class Latchwork:
    CODE_BASE = 0x10000
    CODE_SIZE = 0x1F0000
    STATE = 0x300000
    CONTEXT = 0x310000
    STACK_BASE = 0x400000
    STACK_SIZE = 0x20000
    STACK_TOP = 0x410000
    STOP = 0x500000
    DISPATCHER = 0x90640

    def __init__(self, binary: Path = DEFAULT_BINARY):
        self.binary = binary
        self.image = binary.read_bytes()
        self.seed = self._read_u32(0x17912C)
        self.table = [self._read_u32(0x179130 + 4 * i) for i in range(1024)]
        self.q = (
            self.table[384] ^ mix32(self.seed ^ 0x266F808D),
            self.table[385] ^ mix32(self.seed ^ 0x84360A46),
            self.table[386] ^ mix32(self.seed ^ 0x62FE941F),
        )
        assert self.q == (27, 21, 60)
        self.uc = self._load_unicorn()

    def _read_u32(self, address: int) -> int:
        return struct.unpack_from("<I", self.image, address)[0]

    def _prepare_call(self) -> None:
        self.uc.mem_write(self.STACK_TOP - 8, struct.pack("<Q", self.STOP))
        self.uc.reg_write(UC_X86_REG_RSP, self.STACK_TOP - 8)

    def _load_unicorn(self) -> Uc:
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(self.CODE_BASE, self.CODE_SIZE, 7)
        relative: list[tuple[int, int]] = []
        irelative: list[tuple[int, int]] = []
        with self.binary.open("rb") as stream:
            elf = ELFFile(stream)
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_LOAD" and segment["p_vaddr"] >= self.CODE_BASE:
                    uc.mem_write(segment["p_vaddr"], segment.data())
            for name in (".rela.dyn", ".rela.plt"):
                section = elf.get_section_by_name(name)
                if section is None:
                    continue
                for relocation in section.iter_relocations():
                    kind = relocation.entry.r_info_type
                    item = (relocation.entry.r_offset, relocation.entry.r_addend)
                    if kind == 8:
                        relative.append(item)   # R_X86_64_RELATIVE
                    elif kind == 37:
                        irelative.append(item)  # R_X86_64_IRELATIVE
        for offset, addend in relative:
            uc.mem_write(offset, struct.pack("<Q", addend))
        uc.mem_map(self.STATE, 0x20000, 7)
        uc.mem_map(self.STACK_BASE, self.STACK_SIZE, 7)
        self.uc = uc
        for offset, resolver in irelative:
            self._prepare_call()
            uc.emu_start(resolver, self.STOP, count=100_000)
            uc.mem_write(offset, struct.pack("<Q", uc.reg_read(UC_X86_REG_RAX)))
        return uc

    def _dispatch(self, state: list[int], flag: bytes, counter: int) -> tuple[list[int], int]:
        self.uc.mem_write(self.STATE, struct.pack("<128I", *state))
        self.uc.mem_write(self.CONTEXT, b"\0" * 0x80)
        context = struct.pack("<QQQI", self.STATE, 128, 128, counter) + flag
        self.uc.mem_write(self.CONTEXT, context)
        self._prepare_call()
        self.uc.reg_write(UC_X86_REG_RDI, self.CONTEXT)
        self.uc.emu_start(self.DISPATCHER, self.STOP, count=10_000_000)
        state = list(struct.unpack("<128I", self.uc.mem_read(self.STATE, 512)))
        counter = struct.unpack("<I", self.uc.mem_read(self.CONTEXT + 0x18, 4))[0]
        return state, counter

    def replay(self, flag: bytes | str) -> list[int]:
        if isinstance(flag, str):
            flag = flag.encode()
        if len(flag) != 32:
            raise ValueError("flag must be exactly 32 bytes")
        state = [0] * 128
        for i in range(128):
            destination = (73 * i) & 127
            encoded_zero = mix32(
                self.seed ^ u32((i + 1) * 0x85EBCA6B) ^ 0x2C8D4214
            )
            state[destination] = u32(encoded_zero + self.table[i + 128])
        counter = 0
        output: list[int] = []
        for cycle in range(128):
            def key(q: int, bp: int) -> int:
                return mix32(
                    self.seed
                    ^ u32((bp + 1) * 0xC2B2AE35)
                    ^ u32((q + 1) * 0x85EBCA6B)
                    ^ 0xEE3FEC21
                )
            q0 = self.q[0]
            destination = (73 * q0 + 29 * counter) & 127
            state[destination] = u32(
                key(q0, counter) + self.table[q0 + 128]
                + u32(self.table[q0] * cycle)
            )
            opaque = u32(cycle * 0x745D1747 + 0xE8BA2E8C)
            predicate = False
            if opaque >= 0x1745D175:
                predicate = u32(
                    cycle * 0xF0F0F0F1 + 0xB4B4B4B5
                ) >= 0x0F0F0F10
            q1 = self.q[1]
            destination = (73 * q1 + 29 * counter) & 127
            state[destination] = u32(
                key(q1, counter) + self.table[q1 + 128]
                + (self.table[q1] if predicate else 0)
            )
            state, counter = self._dispatch(state, flag, counter)
            q2 = self.q[2]
            destination = (73 * q2 + 29 * counter) & 127
            value = u32(
                (state[destination]
                 - u32(key(q2, counter) + self.table[q2 + 128]))
                * self.table[q2 + 256]
            )
            output.append(value)
        return output


def read_capture(path: Path = DEFAULT_CAPTURE) -> list[int]:
    with path.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != 128:
        raise ValueError(f"expected 128 capture rows, got {len(rows)}")
    return [int(row["sample"], 16) for row in rows]


def format_csv(values: list[int]) -> str:
    return "cycle,sample\n" + "\n".join(
        f"{cycle:03},{value:08x}" for cycle, value in enumerate(values)
    )


def solve_capture(values: list[int]) -> bytes:
    """Invert the reversible output, compression, schedule, and packing phases."""
    if len(values) != 128:
        raise ValueError("capture must contain exactly 128 samples")

    output_cycles = (107, 109, 110, 111, 112, 113, 115, 116, 117, 118)
    selection_order = (1, 4, 7, 0, 3, 6, 9, 2, 5, 8)
    ring10 = [0] * 10
    accumulator = 0x243F6A88
    for j, cycle in enumerate(output_cycles):
        pre = ror32(values[cycle] ^ 0xA5C31F27, cycle)
        mixed = pre ^ u32(cycle * PHI32)
        mask = u32((74 + j) * PHI32) ^ rol32(ROUND_CONST, 73 + j)
        selected = u32((mixed ^ mask) - rol32(accumulator, 5 + 3 * j))
        ring10[selection_order[j]] = selected
        accumulator = rol32(u32((accumulator ^ selected) + mask), 9)

    for round_index in range(79, -1, -1):
        destination = round_index % 10
        source = (round_index - 1 - 4 * (round_index // 16)) % 10
        amount = ((11 * round_index + 7) % 31) + 1
        delta = (
            rol32(ring10[source], amount)
            ^ u32((round_index + 1) * PHI32)
            ^ rol32(ROUND_CONST, round_index)
        )
        if round_index & 1:
            ring10[destination] ^= delta
        else:
            ring10[destination] = u32(ring10[destination] - delta)

    ring8 = [
        ring10[7], ring10[5], ring10[8], ring10[3],
        ring10[9], ring10[2], ring10[0], ring10[1],
    ]
    word15 = ring10[4]
    word28 = ring10[6]
    for round_index in range(47, -1, -1):
        destination = round_index % 8
        source_b = (round_index - 1) % 8
        source_a = (
            round_index
            + (5 if ((round_index // 8) & 1) == 0 else 2)
        ) % 8
        core = (
            u32((round_index + 1) * PHI32)
            ^ rol32(ROUND_CONST, round_index)
        )
        branch_a = u32(
            rol32(core, 11) + ring8[source_b] + rol32(word15, 11)
        )
        branch_b = rol32(
            u32(ring8[source_a] + core) ^ rol32(word28, 5),
            3 + (round_index % 5),
        )
        ring8[destination] = u32(
            ring8[destination] - (branch_a ^ branch_b)
        )

    input_masks = (
        0x4712371E, 0x7B32742E, 0xDE999F55, 0x8183C0D1,
        0x8D5FBD04, 0x1D2E42E6, 0x36C276ED, 0xB096A45A,
    )
    chunk_ring_indices = (0, 7, 6, 5, 4, 3, 2, 1)
    recovered = bytearray()
    for mask, ring_index in zip(input_masks, chunk_ring_indices):
        packed = u32(ring8[ring_index] - mask)
        recovered.extend((
            (packed >> 16) & 0xFF,
            (packed >> 24) & 0xFF,
            packed & 0xFF,
            (packed >> 8) & 0xFF,
        ))
    flag = bytes(recovered)
    if not (
        len(flag) == 32
        and flag.startswith(b"FLAG{")
        and flag.endswith(b"}")
        and all(byte in ALPHABET for byte in flag[5:-1])
    ):
        raise ValueError(f"inversion produced an invalid flag: {flag!r}")
    return flag


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("flag", nargs="?", help="replay one 32-byte FLAG{...}")
    parser.add_argument("--capture", type=Path, default=DEFAULT_CAPTURE)
    args = parser.parse_args()
    if args.flag:
        machine = Latchwork()
        print(format_csv(machine.replay(args.flag)))
        return
    target = read_capture(args.capture)
    flag = solve_capture(target)
    machine = Latchwork()
    replayed = machine.replay(flag)
    if replayed != target:
        mismatches = [
            cycle for cycle, (actual, expected)
            in enumerate(zip(replayed, target)) if actual != expected
        ]
        raise RuntimeError(f"replay verification failed at cycles {mismatches}")
    print(flag.decode())
    print("verified: 128/128 capture samples match")


if __name__ == "__main__":
    main()
