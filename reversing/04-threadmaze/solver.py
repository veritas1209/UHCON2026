#!/usr/bin/env python3
"""Final reproducible solver for UHCON ThreadMAZE."""

from __future__ import annotations

import subprocess
from pathlib import Path

import fork_stage_inverse as inverse

ROOT = Path(__file__).resolve().parent
ALPHABET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def solve() -> bytes:
    inverse.FRAME = (ROOT / "fork_perm_final_context_frame.bin").read_bytes()
    trace = (ROOT / "fork_perm_final_context_trace_A.bin").read_bytes()
    inverse.STATES = [trace[i : i + 48] for i in range(0, len(trace), 48)]
    inverse.ORDER = list((ROOT / "fork_perm_final_context_order.bin").read_bytes())
    state = (ROOT / "fork_perm_inverse_first.bin").read_bytes()

    assert len(inverse.FRAME) == 0x18C0
    assert len(inverse.STATES) == 14 and all(len(item) == 48 for item in inverse.STATES)
    assert inverse.ORDER == [11, 5, 4, 10, 12, 0, 1, 9, 6, 3, 8, 2, 7]
    assert len(state) == 48

    for position, stage in enumerate(inverse.ORDER):
        recovered = inverse.INVERSES[stage](inverse.STATES[position + 1])
        assert recovered == inverse.STATES[position], f"stage {stage} inverse mismatch"

    for stage in reversed(inverse.ORDER):
        state = inverse.INVERSES[stage](state)

    assert len(state) == 48 and all(byte in ALPHABET for byte in state)
    return state


def main() -> None:
    candidate = solve()
    text = candidate.decode("ascii")
    print(f"input={text}")
    print(f"flag=FLAG{{{text}}}")

    binary = ROOT / "extracted" / "prob"
    result = subprocess.run(
        [str(binary)],
        input=candidate + b"\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = result.stdout.decode("utf-8", "replace").strip()
    print(f"local={output}")
    assert "Correct!" in output


if __name__ == "__main__":
    main()
