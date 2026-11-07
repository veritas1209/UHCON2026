#!/usr/bin/env python3
"""Safe standard entry point for the Archive Relay solver.

The default action only validates the saved local/remote artifacts.  Pass
``--remote`` explicitly to run the timing-sensitive solver in
``solve_remote.py``; that action creates a fresh challenge instance.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent
FLAG_RE = re.compile(r"FLAG\{[0-9a-f]+\}")


def verify_artifacts() -> int:
    flag_path = ROOT / "flag.txt"
    reverse_path = ROOT / "root_sh_reverse_results.json"
    capture_path = ROOT / "root_sh_capture_results.json"
    marker_path = ROOT / "root_sh_reverse/010_separate_100_0/PWNED"

    flag = flag_path.read_text(encoding="utf-8").strip()
    reverse = json.loads(reverse_path.read_text(encoding="utf-8"))
    capture = json.loads(capture_path.read_text(encoding="utf-8"))

    checks = {
        "remote flag has the expected format": bool(FLAG_RE.fullmatch(flag)),
        "local sh-* race created PWNED": marker_path.is_file()
        and any(row.get("won") for row in reverse),
        "local active-socket redirection captured data": any(
            row.get("captured") for row in capture
        ),
    }
    for label, passed in checks.items():
        print(f"[{'OK' if passed else 'FAIL'}] {label}")
    if all(checks.values()):
        print(f"[OK] saved remote flag: {flag}")
        return 0
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--remote",
        action="store_true",
        help="run the network solver (fresh remote instance; explicit opt-in)",
    )
    args = parser.parse_args()
    if not args.remote:
        return verify_artifacts()

    from solve_remote import main as remote_main

    remote_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
