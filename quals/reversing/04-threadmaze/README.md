# ThreadMAZE 풀이

## 결과

- 정답 입력: `iB3F74InASXCvZ9WvxoqOtk943NzPOyi2xJB-DAg6Uzm-ra2`
- 플래그: `FLAG{iB3F74InASXCvZ9WvxoqOtk943NzPOyi2xJB-DAg6Uzm-ra2}`
- 원본 `extracted/prob` 검증 결과: `Correct!`

## 1. 바이너리 구조

바이너리는 섹션 헤더와 사용자 함수명이 제거된 Go ELF다. 초기화 함수에서 다음 공개 상수를 복구했다.

- seed: `5c10292963e2ecfa90795476389b5ae11c66606864c3dd24ebe8127b6afe1f7f`
- 최종 SHA-256 commitment: `23488fd14033922cac310d769b43a396f5af73ec5f8c820c9f531da35719d7f9`

검증기 `0x4fffa0`은 입력 48바이트를 `0x4ff6a0`의 13단계 가역 dispatcher에 넣고, 48·126·18바이트 세 스트림을 512개의 3비트 셀에 scatter한다. 이어 셀 VM과 permutation/add 변환을 적용하고 최종 transcript 해시를 비교한다.

## 2. 코드 레이아웃 캐리어

`0x504720`부터 512개의 primitive 함수가 있고 각 함수에는 다음 길이의 NOP run이 있다.

```text
nop_count = 17 + 32 * s,  0 <= s < 8
```

따라서 함수 레이아웃만으로 512개의 3비트 심볼을 얻는다. 공개 seed로 다음 연산을 역으로 적용했다.

1. `0x4fcc20` 역변환: `C[P[i]] = (B[i] + mask(P[i])) mod 8`
2. `0x4fc8a0`의 1536-op 셀 VM 역변환
3. 공유 visited set을 사용하는 세 scatter domain 역변환

복구된 scatter 직전 스트림은 다음과 같다.

- dispatcher 최종 상태 48바이트: `2fb9239d0fa930b2d8e854058b1f2f3c8acdc72ed5559b71fde353518855afd48245ca9b65095ccf70c6efd4f88543e5`
- post-capsule 126바이트: `09d18bead82e2057...af7fb65586cb`
- post-aux 18바이트: `42bacdb4210927aa27e4fc1dc9817aadd8a9`

## 3. 보조 스트림 언랩

중요한 점은 126·18바이트가 dispatcher의 원시 인자가 아니라 각각 `0x4fb580`, `0x4fb820`을 지난 뒤의 값이라는 것이다.

먼저 `0x4fb820`을 역으로 실행해 raw aux를 얻었다.

```text
5cd4943062f57980a2e3098a60511145be5b
```

그 다음 raw aux와 공개 seed로 `0x4fb580`을 역으로 실행해 raw capsule을 얻었다. 분석 중 가장 큰 함정은 Go stack ABI의 반환 슬롯이었다. 반환값은 callee entry 기준 `+0x70`, 즉 caller 기준 `+0x68`에 있으며 packed argument 뒤에 6바이트 정렬 padding이 있다. `+0x62`로 읽으면 그럴듯한 랜덤 값은 나오지만 최종 역산이 전부 실패한다.

## 4. 13단계 역연산

raw context에서 얻은 실제 단계 순서는 다음과 같다.

```text
11, 5, 4, 10, 12, 0, 1, 9, 6, 3, 8, 2, 7
```

각 단계는 byte permutation, feedback/rotate, HMAC-SHA256 Feistel, PRESENT-CBC, ARX, XTEA-CBC, ChaCha/Salsa 계열 stream XOR, RC4-drop, 그리고 두 개의 VM으로 구성된다. 임의의 `A * 48` 입력을 같은 target context로 순방향 실행해 14개 경계 상태를 캡처했고, 각 역함수가 바로 이전 상태를 정확히 복원하는지 13/13 확인했다.

마지막 48바이트 상태부터 위 순서를 거꾸로 적용하면 정답 입력이 나온다.

## 5. 재현

WSL에서 다음 명령으로 역산과 원본 검증을 동시에 수행한다.

```bash
cd reversing/04-threadmaze
python3 solver.py
```

예상 출력:

```text
input=iB3F74InASXCvZ9WvxoqOtk943NzPOyi2xJB-DAg6Uzm-ra2
flag=FLAG{iB3F74InASXCvZ9WvxoqOtk943NzPOyi2xJB-DAg6Uzm-ra2}
local=> Correct!
```

이 명령을 네트워크 없이 다시 실행한 결과와 핵심 파일의 SHA-256은
`verification.json`에 기록했다.

핵심 역함수 구현은 `fork_stage_inverse.py`, 최종 target context와 trace는 `fork_perm_final_context_*` 파일에 있다.

## 최종 풀이 코드 전체

표준 실행 진입점 `solve.py` 전체:

```python
#!/usr/bin/env python3
"""Standard entry point for the verified ThreadMAZE solver."""

from solver import main


if __name__ == "__main__":
    main()

```

실제 역산과 원본 바이너리 검증을 수행하는 `solver.py` 전체:

```python
#!/usr/bin/env python3
"""Final reproducible solver for UHCON ThreadMAZE."""

from __future__ import annotations

import subprocess
from pathlib import Path

import fork_stage_inverse as inverse

ROOT = Path(__file__).resolve().parent
ALPHABET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def solve() -> bytes:
    inverse.FRAME = (ROOT / "fork_perm_final_context_frame.bin").read_bytes()
    trace = (ROOT / "fork_perm_final_context_trace_A.bin").read_bytes()
    inverse.STATES = [trace[i : i + 48] for i in range(0, len(trace), 48)]
    inverse.ORDER = list((ROOT / "fork_perm_final_context_order.bin").read_bytes())
    state = (ROOT / "fork_perm_inverse_first.bin").read_bytes()

    assert len(inverse.FRAME) == 0x18C0
    assert len(inverse.STATES) == 14 and all(len(item) == 48 for item in inverse.STATES)
    assert inverse.ORDER == [11, 5, 4, 10, 12, 0, 1, 9, 6, 3, 8, 2, 7]
    assert len(state) == 48

    for position, stage in enumerate(inverse.ORDER):
        recovered = inverse.INVERSES[stage](inverse.STATES[position + 1])
        assert recovered == inverse.STATES[position], f"stage {stage} inverse mismatch"

    for stage in reversed(inverse.ORDER):
        state = inverse.INVERSES[stage](state)

    assert len(state) == 48 and all(byte in ALPHABET for byte in state)
    return state


def main() -> None:
    candidate = solve()
    text = candidate.decode("ascii")
    print(f"input={text}")
    print(f"flag=FLAG{{{text}}}")

    binary = ROOT / "extracted" / "prob"
    result = subprocess.run(
        [str(binary)],
        input=candidate + b"\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = result.stdout.decode("utf-8", "replace").strip()
    print(f"local={output}")
    assert "Correct!" in output


if __name__ == "__main__":
    main()

```

`solver.py`가 사용하는 13단계 역연산 구현
`fork_stage_inverse.py` 전체:

```python
#!/usr/bin/env python3
"""Invert ThreadMAZE's 13-stage 48-byte dispatcher for the recovered target ctx.

The correctly decrypted target context and a forward A*48 trace were captured
at the 0x4ff6a0 dispatcher with fork_stage_inverse_correcttrace.gdb.
Every inverse is checked against adjacent states in that trace before it is
used on the target state.
"""

from __future__ import annotations

import struct
import hashlib
import hmac
from pathlib import Path


HERE = Path(__file__).resolve().parent
FRAME = (HERE / "fork_stage_inverse_correct_frame.bin").read_bytes()
TRACE = (HERE / "fork_stage_inverse_correct_states.bin").read_bytes()
STATES = [TRACE[i:i + 48] for i in range(0, len(TRACE), 48)]
assert len(FRAME) == 0x18C0 and len(STATES) == 14

ORDER = [11, 2, 5, 1, 0, 6, 3, 9, 4, 7, 10, 12, 8]
TARGET = bytes.fromhex(
    "2fb9239d0fa930b2d8e854058b1f2f3c8acdc72ed5559b71"
    "fde353518855afd48245ca9b65095ccf70c6efd4f88543e5"
)
SBOX = [0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2]
ISBOX = [SBOX.index(i) for i in range(16)]


def rol(v: int, n: int, bits: int) -> int:
    n %= bits
    mask = (1 << bits) - 1
    return ((v << n) | (v >> (bits - n))) & mask


def ror(v: int, n: int, bits: int) -> int:
    return rol(v, bits - (n % bits), bits)


def u32(x: bytes, off: int = 0) -> int:
    return struct.unpack_from("<I", x, off)[0]


def u64(x: bytes, off: int = 0) -> int:
    return struct.unpack_from("<Q", x, off)[0]


def p32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def p64(v: int) -> bytes:
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def fixed_xor_inverse(stage: int, state: bytes) -> bytes:
    pos = ORDER.index(stage)
    stream = xor_bytes(STATES[pos], STATES[pos + 1])
    return xor_bytes(state, stream)


def inverse_stage0(state: bytes) -> bytes:
    key = FRAME[0xD08:0xD68]
    perm = list(range(48))
    cursor = 0
    for i in range(47, 0, -1):
        j = struct.unpack_from("<H", key, cursor)[0] % (i + 1)
        cursor += 2
        perm[i], perm[j] = perm[j], perm[i]
    out = bytearray(48)
    for dst, src in enumerate(perm):
        out[src] = state[dst]
    return bytes(out)


def inverse_stage1(state: bytes) -> bytes:
    cfg = FRAME[0xD68:0xD99]
    key, feedback = cfg[:48], cfg[48]
    out = bytearray(48)
    for i, cur in enumerate(state):
        r = i % 7 + 1
        mixed = ror(cur ^ feedback, r, 8)
        out[i] = (mixed - key[i] - i * 0x11 - 0x3D) & 0xFF
        feedback = (cur + key[(i * 7) % 48]) & 0xFF
    return bytes(out)


def inverse_stage2(state: bytes) -> bytes:
    """Reverse the 32-round 24+24-byte HMAC-SHA256 Feistel network."""
    key = FRAME[0xD99:0xDB9]
    left, right = state[:24], state[24:]
    for round_no in range(31, -1, -1):
        old_right = left
        msg = bytes([round_no, round_no ^ 0xA7]) + old_right
        mask = hmac.new(key, msg, hashlib.sha256).digest()[:24]
        old_left = xor_bytes(right, mask)
        left, right = old_left, old_right
    return left + right


def present_round_keys(key10: bytes) -> list[int]:
    assert len(key10) == 10
    key = int.from_bytes(key10, "big")
    mask80 = (1 << 80) - 1
    keys = []
    for round_no in range(1, 33):
        keys.append(key >> 16)
        if round_no == 32:
            break
        key = ((key << 61) | (key >> 19)) & mask80
        key = (key & ((1 << 76) - 1)) | (SBOX[(key >> 76) & 0xF] << 76)
        key ^= round_no << 15
    return keys


def inv_present_sbox(v: int) -> int:
    out = 0
    for i in range(16):
        out |= ISBOX[(v >> (i * 4)) & 0xF] << (i * 4)
    return out


def inv_present_player(v: int) -> int:
    out = 0
    # Forward P(i)=16*i mod 63 for i<63; bit 63 stays at 63.
    for i in range(63):
        out |= ((v >> ((16 * i) % 63)) & 1) << i
    out |= v & (1 << 63)
    return out


def inverse_stage3(state: bytes) -> bytes:
    cfg = FRAME[0xDB9:0xDCB]
    keys = present_round_keys(cfg[:10])
    iv = cfg[10:18]
    out = bytearray()
    prev = iv
    for off in range(0, 48, 8):
        cblock = state[off:off + 8]
        v = u64(cblock) ^ keys[31]
        for r in range(30, -1, -1):
            v = inv_present_player(v)
            v = inv_present_sbox(v)
            v ^= keys[r]
        out += xor_bytes(p64(v), prev)
        prev = cblock
    return bytes(out)


def arx_round_keys(key32: bytes) -> list[int]:
    words = list(struct.unpack("<4Q", key32))
    a = [words[0]]
    b = [words[1], words[2], words[3]]
    for i in range(33):
        x = ((ror(b[i], 8, 64) + a[i]) & 0xFFFFFFFFFFFFFFFF) ^ i
        b.append(x)
        a.append(rol(a[i], 3, 64) ^ x)
    return a[:34]


def inverse_stage5(state: bytes) -> bytes:
    cfg = FRAME[0xDCB:0xDFB]
    keys = arx_round_keys(cfg[:32])
    prev_l, prev_r = struct.unpack("<2Q", cfg[32:48])
    out = bytearray()
    for off in range(0, 48, 16):
        c_l, c_r = struct.unpack_from("<2Q", state, off)
        l, r = c_l, c_r
        for k in reversed(keys):
            old_r = ror(r ^ l, 3, 64)
            old_l = ror(((l ^ k) - old_r) & 0xFFFFFFFFFFFFFFFF, 56, 64)
            l, r = old_l, old_r
        out += p64(l ^ prev_l) + p64(r ^ prev_r)
        prev_l, prev_r = c_l, c_r
    return bytes(out)


def xtea_decrypt(v0: int, v1: int, key: tuple[int, ...]) -> tuple[int, int]:
    delta = 0x9E3779B9
    total = (delta * 64) & 0xFFFFFFFF
    for _ in range(64):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (total + key[(total >> 11) & 3]))) & 0xFFFFFFFF
        total = (total - delta) & 0xFFFFFFFF
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (total + key[total & 3]))) & 0xFFFFFFFF
    return v0, v1


def inverse_stage6(state: bytes) -> bytes:
    cfg = FRAME[0xCD0:0xCE8]
    key = struct.unpack("<4I", cfg[:16])
    prev = cfg[16:24]
    out = bytearray()
    for off in range(0, 48, 8):
        cblock = state[off:off + 8]
        v0, v1 = xtea_decrypt(*struct.unpack("<2I", cblock), key)
        out += xor_bytes(struct.pack("<2I", v0, v1), prev)
        prev = cblock
    return bytes(out)


def inverse_stage10(state: bytes) -> bytes:
    program = FRAME[0xE5B:0x125B]
    x = bytearray(state)
    for step in range(127, -1, -1):
        rec = program[step * 8:(step + 1) * 8]
        op = rec[0] % 6
        a = rec[1] % 48
        b = (a + rec[2] % 47 + 1) % 48
        if op == 0:
            x[a], x[b] = x[b], x[a]
        elif op == 1:
            r = rec[3] % 7 + 1
            x[a] = (ror(x[a] ^ x[b], r, 8) - rec[5]) & 0xFF
        elif op == 2:
            r1, r2 = rec[3] % 7 + 1, rec[4] % 7 + 1
            old_b = ror(x[b], r2, 8) ^ x[a]
            old_a = (x[a] - rol(old_b, r1, 8) - rec[5]) & 0xFF
            x[a], x[b] = old_a, old_b
        elif op == 3:
            aw = rec[1] % 12
            bw = (aw + rec[2] % 11 + 1) % 12
            off_a, off_b = aw * 4, bw * 4
            new_a, new_b = u32(x, off_a), u32(x, off_b)
            r1 = rec[3] % 31 + 1
            r2 = rec[4] % 31 + 1
            add = u32(rec, 4)
            old_b = ror(new_b, r2, 32) ^ new_a
            old_a = (new_a - rol(old_b, r1, 32) - add) & 0xFFFFFFFF
            x[off_a:off_a + 4], x[off_b:off_b + 4] = p32(old_a), p32(old_b)
        elif op == 4:
            y = x[a] ^ rec[6]
            x[a] = ISBOX[y & 0xF] | (ISBOX[y >> 4] << 4)
        else:
            shift = rec[1] % 47 + 1
            old = bytearray(48)
            for i in range(48):
                old[(i + shift) % 48] = x[i]
            x = old
    return bytes(x)


def inverse_stage11(state: bytes) -> bytes:
    program = FRAME[0x125B:0x155B]
    x = bytearray(state)
    for step in range(95, -1, -1):
        rec = program[step * 8:(step + 1) * 8]
        a = rec[0] % 48
        b = (a + rec[1] % 47 + 1) % 48
        new_a, new_b = x[a], x[b]
        r1, r2 = rec[2] % 7 + 1, rec[5] % 7 + 1
        old_b = (rol(new_b ^ new_a, r2, 8) - rec[4] - rec[6]) & 0xFF
        old_a = (ror(new_a ^ old_b, r1, 8) - rec[3] - step) & 0xFF
        x[a], x[b] = old_a, old_b
    return bytes(x)


def inverse_stage12(state: bytes) -> bytes:
    program = FRAME[0x155B:0x185B]
    x = bytearray(state)
    for step in range(95, -1, -1):
        rec = program[step * 8:(step + 1) * 8]
        a = rec[0] % 12
        b = (a + rec[1] % 11 + 1) % 12
        off_a, off_b = a * 4, b * 4
        new_a, new_b = u32(x, off_a), u32(x, off_b)
        r1, r2 = rec[2] % 31 + 1, rec[3] % 31 + 1
        add = u32(rec, 4)
        old_b = ror(new_b, r2, 32) ^ new_a
        old_a = ror((new_a - add - old_b - step) & 0xFFFFFFFF, r1, 32)
        x[off_a:off_a + 4], x[off_b:off_b + 4] = p32(old_a), p32(old_b)
    return bytes(x)


INVERSES = {
    0: inverse_stage0,
    1: inverse_stage1,
    2: inverse_stage2,
    3: inverse_stage3,
    4: lambda s: fixed_xor_inverse(4, s),
    5: inverse_stage5,
    6: inverse_stage6,
    7: lambda s: fixed_xor_inverse(7, s),
    8: lambda s: fixed_xor_inverse(8, s),
    9: lambda s: fixed_xor_inverse(9, s),
    10: inverse_stage10,
    11: inverse_stage11,
    12: inverse_stage12,
}


def validate() -> None:
    for pos, stage in enumerate(ORDER):
        if stage not in INVERSES:
            continue
        got = INVERSES[stage](STATES[pos + 1])
        assert got == STATES[pos], (
            f"stage {stage} inverse mismatch at order position {pos}\n"
            f"got  {got.hex()}\nwant {STATES[pos].hex()}"
        )
        print(f"stage {stage:2d}: inverse validated")


def main() -> None:
    validate()
    state = TARGET
    for stage in reversed(ORDER):
        if stage not in INVERSES:
            print(f"stopped before unresolved stage {stage}; state={state.hex()}")
            return
        state = INVERSES[stage](state)
        print(f"after inverse stage {stage:2d}: {state.hex()}")
    print("candidate bytes:", state)
    print("candidate text:", state.decode("ascii"))


if __name__ == "__main__":
    main()

```
