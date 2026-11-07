# UHCON 2026 FINAL — Latchwork 풀이

## 결과

- 플래그: `FLAG{0f540275bfce4640df5b2cb6af}`
- `solver.py`의 역산 결과와 제공된 `capture.csv`가 128개 cycle 모두 일치했다.
- 실제 제공 바이너리도 같은 플래그로 실행하여 `capture.csv`와 `diff`가 없음을 확인했다.
- 제출은 사용자가 직접 완료했으며, 사이트 팀 solves에서 challenge 7의 `Correct` 처리를 확인했다.
- 제출 시각: `2026-11-07 10:54:57 KST`

## 1. 바이너리와 VM 구조

`files/chall`은 stripped Rust x86-64 static PIE이다. 입력은 정확히 32바이트인
`FLAG{[a-z0-9_]{26}}` 형식이어야 한다.

주요 주소는 다음과 같다.

- Rust main: `0x906c0`
- 입력 검사: `0x90974..0x90a41`
- latch dispatcher: `0x90640`
- trait-object 표: `0x1d64b0`
- 각 vtable의 update 함수 포인터: `vtable + 0x18`

dispatcher는 0번 노드부터 시작하여 update 함수가 반환한 다음 노드 번호로 이동한다.
`-1`이 반환되면 한 outer cycle이 끝난다. 128 cycle 전체에서 4,594개 handler를
호출하며 251개 후보 중 238개 노드를 방문한다. 여러 유효 입력으로 확인한 결과
노드 경로는 입력과 무관했으므로 전체 계산을 직선형 32비트 프로그램으로 다룰 수 있었다.

실행 컨텍스트는 다음 구조다.

```text
+0x00  state 포인터
+0x08  길이
+0x10  용량
+0x18  u32 block_position
+0x1c  flag[32]
```

## 2. 난독화된 상태의 디코딩

물리 상태는 128개의 `u32`지만 각 handler 전후로 위치 순열과 가산·곱셈 마스킹이
적용된다. seed `K=0x3a0b2929`와 표 `A/B/C`는 각각 `0x17912c`,
`0x179130`, `0x179330`, `0x179530`에서 읽을 수 있다. 모든 `q`에 대해
`A[q] * C[q] == 1 (mod 2^32)`이다.

`bp`를 block position, `L[q]`를 논리 상태, `P`를 물리 상태라 하면 다음과 같다.

```text
p = (29*bp + 73*q) & 127
key = mix32(K ^ ((bp+1)*0xc2b2ae35)
              ^ ((q+1)*0x85ebca6b) ^ 0xee3fec21)

P[p] = key + B[q] + A[q]*L[q]                    (mod 2^32)
L[q] = (P[p] - key - B[q]) * C[q]                (mod 2^32)
```

`mix32`는 아래 함수다.

```text
x ^= x >> 16
x *= 0x7feb352d
x ^= x >> 15
x *= 0x846ca68b
x ^= x >> 16
```

main은 dispatch 전에 `L27`에 outer cycle을 기록하고 dispatch 뒤 `L60`을 CSV
sample로 꺼낸다.

## 3. 분석 및 재현 방법

ELF의 `R_X86_64_RELATIVE` relocation을 직접 적용하고 `IRELATIVE` resolver만
Unicorn으로 호출한 뒤, 외부 I/O 없이 순수 dispatcher `0x90640`만 재생했다.
handler 경계에서 물리 상태를 위 식으로 논리 상태로 변환하여 전후 차이를 기록했다.

각 handler의 공통 128-word decode/encode loop를 제외하고 semantic block만 비교하면
실제 연산은 add, xor, rotate, multiply 같은 작은 32비트 연산으로 정리된다. 일부
노드는 angr/claripy로 독립 교차검증했다. 예를 들어 node 235는 정확히 다음 식이다.

```text
L52 = L19 & L27
L60 = ROL32(L20, L52) ^ 0xa5c31f27
```

REA 워크플로우의 artifact-first, 좁은 런타임 관찰, 관찰/추론 분리 원칙을 적용했다.
이 세션에는 REA MCP와 `rea` CLI가 없어 Evidence ID 대신 `readelf`, `objdump`,
Unicorn, GDB, angr로 얻은 관찰을 상호 검증했다.

## 4. 첫 10개 출력에서 압축 링 복원

첫 10개 유효 출력 cycle은 다음과 같다.

```text
107, 109, 110, 111, 112, 113, 115, 116, 117, 118
```

`phi=0x9e3779b9`, `C=0x7f4a7c15`, 초기 누산기
`acc=0x243f6a88`로 두고 `j=0..9`에 대해 역산한다.

```text
pre  = ROR32(sample[cycle] ^ 0xa5c31f27, cycle)
v    = pre ^ (cycle*phi)
mask = ((74+j)*phi) ^ ROL32(C, 73+j)
sel  = (v ^ mask) - ROL32(acc, 5+3*j)
acc  = ROL32((acc ^ sel) + mask, 9)
```

`sel`을 순서 `[1,4,7,0,3,6,9,2,5,8]`에 넣으면 최종 10-word 링은 다음이다.

```text
ec47c8dd 6c15c648 19cdcb8b cea08cec 68eee90a
e563c795 b96ac4e6 d3384f69 8c9ab559 abe355ac
```

## 5. 80-round 압축 역산

forward round `r=0..79`의 핵심은 다음과 같다.

```text
d   = r % 10
src = (r - 1 - 4*(r//16)) % 10
amt = ((11*r + 7) % 31) + 1
tmp = ROL32(S[src], amt) ^ ((r+1)*phi) ^ ROL32(C, r)

r 짝수: S[d] += tmp
r 홀수: S[d] ^= tmp
```

따라서 `r=79..0` 역순으로 홀수 round는 같은 XOR을 하고 짝수 round는 `tmp`를
빼면 된다. 얻은 압축 전 상태는 다음과 같다.

```text
26245231 ca23a226 44687db5 70255528 23afe287
bd168e59 06fae8fa 6ce56176 c678a0cd 6dfd92ae
```

## 6. 48-round 입력 schedule 역산

8-word 링과 두 추가 워드는 다음 대응이다.

```text
R = [S7, S5, S8, S3, S9, S2, S0, S1]
X15 = S4
X28 = S6
```

forward step `t=0..47`은 아래 식이다.

```text
d = t % 8
b = (t-1) % 8
a = (t + (5 if ((t//8)&1)==0 else 2)) % 8
M = ((t+1)*phi) ^ ROL32(C, t)

q14 = ROL32(M,11) + R[b] + ROL32(X15,11)
q22 = ROL32((R[a]+M) ^ ROL32(X28,5), 3+(t%5))
R[d] += q14 ^ q22
```

`t=47..0`에서 같은 항을 빼면 초기 링을 얻는다.

```text
93587e5f 11cd21c0 6924d950 815e784c
c1c4f13a e3b92437 0ecdd687 abada994
```

## 7. 입력 패킹 해제

4바이트 `[b0,b1,b2,b3]`는 다음 순서로 한 워드에 패킹된다.

```text
packed = b1<<24 | b0<<16 | b3<<8 | b2
```

chunk별 mask는 다음과 같다.

```text
4712371e 7b32742e de999f55 8183c0d1
8d5fbd04 1d2e42e6 36c276ed b096a45a
```

chunk 0..7은 초기 링 인덱스 `[0,7,6,5,4,3,2,1]`에 대응한다. 각 링 워드에서
mask를 빼고 pair-swap을 해제하면 다음 문자열이 나온다.

```text
FLAG{0f540275bfce4640df5b2cb6af}
```

## 8. 실행 방법

Python 의존성은 `pyelftools`, `unicorn`이다.

```powershell
python .\solver.py
```

예상 출력:

```text
FLAG{0f540275bfce4640df5b2cb6af}
verified: 128/128 capture samples match
```

후보 플래그 하나의 128행 CSV를 재생하려면 다음처럼 실행한다.

```powershell
python .\solver.py 'FLAG{0f540275bfce4640df5b2cb6af}'
```
