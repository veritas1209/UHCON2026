#!/usr/bin/env python3
"""Solve UHCON 2026 Final / Sealed Update.

The kernel VM trace (`work/sec2_ops.json`) was recovered from the unmodified
ARM64 verifier.  This script reverses that VM to obtain the credential passed
through the ioctl and then reverses the original `uhattest` userspace VM to
obtain the value that must be entered at the appliance prompt.

Only the Python standard library is required.  The script deliberately prints
the intermediate kernel credential separately because it is *not* the flag
that should be submitted.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parent
WORK = ROOT / "work"
OPS_PATH = WORK / "sec2_ops.json"
USER_SOLVER_PATH = WORK / "agent_userpath_solver.py"

EXPECTED_OPS_SHA256 = (
    "5aa1ab88476eb85fc88d111f43152a84e8acb38d4fb4350ef889933a3315b169"
)

# The 32 sec3 GF(2^8) equations and the eight final predicates recover this
# unique state after the kernel's bit permutation.
POST_BITPERM_TARGET = bytes.fromhex(
    "c2f17f0ac621686150bd4f24e3502cb0"
    "0ce94fc8da3b2b74b8320cc2cdd2ad5f"
)

# Applying the inverse of the recovered 256-bit permutation gives the target
# immediately before the permutation, i.e. after the 2048-op kernel VM.
SEC2_TARGET = bytes.fromhex(
    "d88a5251ca202087271e652bf9b833e4"
    "1dc02b9fe3a60ae5cc397b4c48f83fd0"
)

EXPECTED_KERNEL_CREDENTIAL = bytes.fromhex(
    "3de1183ba2a5ed773e21953c84869841"
    "7fc86974f7de1c02e282e46f037ee7a0"
)
EXPECTED_FINAL_PAYLOAD = bytes.fromhex(
    "5b6ddad4282d776ef24588d29d59a6b"
    "1a94908356666a9cba2422eaa8c3071a5"
)

MASK32 = 0xFFFFFFFF
MOD32 = 1 << 32


def rol32(value: int, count: int) -> int:
    count &= 31
    value &= MASK32
    return ((value << count) | (value >> ((32 - count) & 31))) & MASK32


def ror32(value: int, count: int) -> int:
    return rol32(value, -count)


def undo_xor_lshift(value: int, shift: int) -> int:
    result = value & MASK32
    amount = shift
    while amount < 32:
        result ^= (result << amount) & MASK32
        amount <<= 1
    return result & MASK32


def undo_xor_rshift(value: int, shift: int) -> int:
    result = value & MASK32
    amount = shift
    while amount < 32:
        result ^= result >> amount
        amount <<= 1
    return result & MASK32


def apply_kernel_op(state: list[int], insn: list[int]) -> None:
    op, dst, src, rotate, immediate = insn
    if op == 0:
        state[dst] ^= immediate
    elif op == 1:
        state[dst] += immediate
    elif op == 2:
        state[dst] -= immediate
    elif op == 3:
        state[dst] = rol32(state[dst], rotate)
    elif op == 4:
        state[dst] ^= rol32(immediate + state[src], rotate)
    elif op == 5:
        state[dst] += rol32(immediate ^ state[src], rotate)
    elif op == 6:
        state[dst] -= rol32(immediate ^ state[src], rotate)
    elif op == 7:
        state[dst], state[src] = state[src], state[dst]
    elif op == 8:
        state[dst] *= immediate
    elif op == 9:
        state[dst] ^= (state[dst] << rotate) & MASK32
    elif op == 10:
        state[dst] ^= state[dst] >> rotate
    elif op == 11:
        state[dst] = ~state[dst]
    elif op == 12:
        state[dst] = -state[dst]
    elif op == 13:
        state[dst] = int.from_bytes(
            (state[dst] & MASK32).to_bytes(4, "little"), "big"
        )
    elif op == 14:
        state[dst] = ror32(state[dst], rotate)
    elif op == 15:
        state[dst] = rol32(immediate ^ state[dst], rotate)
    else:
        raise ValueError(f"unknown kernel VM opcode {op}")
    state[dst] &= MASK32


def invert_kernel_vm(desired: bytes, ops: list[list[int]]) -> bytes:
    if len(desired) != 32:
        raise ValueError("kernel VM state must be 32 bytes")
    state = list(struct.unpack("<8I", desired))

    for op, dst, src, rotate, immediate in reversed(ops):
        if op == 0:
            state[dst] ^= immediate
        elif op == 1:
            state[dst] -= immediate
        elif op == 2:
            state[dst] += immediate
        elif op == 3:
            state[dst] = ror32(state[dst], rotate)
        elif op == 4:
            state[dst] ^= rol32(immediate + state[src], rotate)
        elif op == 5:
            state[dst] -= rol32(immediate ^ state[src], rotate)
        elif op == 6:
            state[dst] += rol32(immediate ^ state[src], rotate)
        elif op == 7:
            state[dst], state[src] = state[src], state[dst]
        elif op == 8:
            state[dst] *= pow(immediate, -1, MOD32)
        elif op == 9:
            state[dst] = undo_xor_lshift(state[dst], rotate)
        elif op == 10:
            state[dst] = undo_xor_rshift(state[dst], rotate)
        elif op == 11:
            state[dst] = ~state[dst]
        elif op == 12:
            state[dst] = -state[dst]
        elif op == 13:
            state[dst] = int.from_bytes(
                (state[dst] & MASK32).to_bytes(4, "little"), "big"
            )
        elif op == 14:
            state[dst] = rol32(state[dst], rotate)
        elif op == 15:
            state[dst] = ror32(state[dst], rotate) ^ immediate
        else:
            raise ValueError(f"unknown kernel VM opcode {op}")
        state[dst] &= MASK32

    return struct.pack("<8I", *state)


def load_kernel_ops() -> list[list[int]]:
    raw = OPS_PATH.read_bytes()
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != EXPECTED_OPS_SHA256:
        raise ValueError(
            f"unexpected sec2 trace hash: {actual_hash} != {EXPECTED_OPS_SHA256}"
        )
    ops = json.loads(raw)
    if len(ops) != 0x800 or any(len(insn) != 5 for insn in ops):
        raise ValueError("expected exactly 2048 five-field kernel VM operations")
    return ops


def load_user_solver():
    spec = importlib.util.spec_from_file_location("sealed_update_user_vm", USER_SOLVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {USER_SOLVER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def flag(payload: bytes) -> str:
    return f"FLAG{{{payload.hex()}}}"


def main() -> None:
    ops = load_kernel_ops()
    kernel_credential = invert_kernel_vm(SEC2_TARGET, ops)

    # Verify the kernel inverse independently in the forward direction.
    check_state = list(struct.unpack("<8I", kernel_credential))
    for insn in ops:
        apply_kernel_op(check_state, insn)
    if struct.pack("<8I", *check_state) != SEC2_TARGET:
        raise AssertionError("kernel VM inverse/forward round trip failed")
    if kernel_credential != EXPECTED_KERNEL_CREDENTIAL:
        raise AssertionError("unexpected kernel credential")

    user_vm = load_user_solver()
    blob, _policy = user_vm.validate_inputs()
    final_payload = user_vm.invert_vm(blob, kernel_credential)
    if user_vm.forward_vm(blob, final_payload) != kernel_credential:
        raise AssertionError("uhattest VM inverse/forward round trip failed")
    if final_payload != EXPECTED_FINAL_PAYLOAD:
        raise AssertionError("unexpected final payload")

    print(f"post_bitperm_target={POST_BITPERM_TARGET.hex()}")
    print(f"sec2_target={SEC2_TARGET.hex()}")
    print(f"kernel_credential_intermediate={flag(kernel_credential)}")
    print("kernel_credential_is_not_the_submission=true")
    print(f"final_flag={flag(final_payload)}")


if __name__ == "__main__":
    main()
