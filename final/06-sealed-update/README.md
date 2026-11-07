# UHCON 2026 FINAL — Sealed Update 풀이

## 결과

최종 제출 플래그는 다음과 같습니다.

```text
FLAG{5b6ddad4282d776ef24588d29d59a6b1a94908356666a9cba2422eaa8c3071a5}
```

대회 서버 응답:

```json
{"message":"Correct","status":"correct"}
```

다음 값은 `uhattest`가 사용자 입력을 변환한 뒤 `/dev/uhsec` ioctl로
전달하는 **커널 중간 credential**입니다. 형식이 플래그와 같아도 제출값이
아닙니다.

```text
FLAG{3de1183ba2a5ed773e21953c848698417fc86974f7de1c02e282e46f037ee7a0}
```

## 분석 범위와 증거 기준

REA 지침에 따라 관찰, 계산 결과, 추론을 구분했습니다. 이 세션에는 REA
전용 MCP/CLI가 없어 Evidence ID는 만들지 못했습니다. 파일 해시를 먼저
고정하고 정적 분석, Unicorn 계측, GDB 읽기 전용 추적, 마지막 원본 QEMU
실행을 교차 검증했습니다.

주요 원본/추출물은 다음과 같습니다.

| 파일 | SHA-256 |
|---|---|
| `files/firmware.uhfw` | `1eaec2727d486954a3e956d5296d4134cc439e461df7009b85aeed116b8f3ea4` |
| `work/linux.img` | `6ca5f2fde7ea47faa52a13c5dd099da48475174c44e4116cb284b9bc87d3a8d8` |
| `work/extracted/initramfs/initramfs.cpio` | `5d15e8310ce8a8fa339de547b6b2fb579770ec43c0ebf92c421e5b6d3dea2824` |
| `uhattest` | `588318a2dcfe727e7582e28623b60d10686d0c68eae48f6235118f7c7e690924` |
| `attest_blob.bin` | `43acc44831dde00ff4f0657667a11ba4ccbd2401642104f82cbb8a1b2d11e8a6` |
| `device-policy.bin` | `73ff827c4a4fd6c51a2a3de6bf395c7f52c1c9ed7ad5db9015b1ab9b10765d69` |
| 정리된 `work/sec2_ops.json` | `5aa1ab88476eb85fc88d111f43152a84e8acb38d4fb4350ef889933a3315b169` |

## 1. 펌웨어 계층 해제

`firmware.uhfw`는 크기 `0x03fe5100`인 `UH26` 컨테이너입니다. `0x1000`에
SquashFS v4/XZ RCFS가 있고, 여기에서 정적 링크 AArch64 업데이터
`/usr/sbin/uhupd`와 다음 장치 설정을 얻었습니다.

```ini
model=UH-GW26-A
channel=final-2026
device_mix=2391d74ab80c5ef162a934cd771be083
```

`uhupd`의 컴포넌트 테이블과 KDF/HMAC/AES-CTR 경로를 복원하여 `BOOT`,
`KERN`, `IRFS`를 순서대로 인증·복호화했습니다. 관찰된 결과는 다음과
같습니다.

- `BOOT`: AArch64 부트 검증 코드
- `KERN`: 65,892,864바이트 플래시 이미지
- `IRFS`: gzip으로 감싼 newc CPIO initramfs
- KERN의 앞 `0x200000`바이트는 플래시용 prefix이고 그 뒤가 Linux ARM64
  `Image`였습니다.
- initramfs에서 `init`, `uhattest`, `device-policy.bin`,
  `attest_blob.bin`을 추출했습니다.

이 단계는 펌웨어 내용에 도달하기 위한 분석 단계입니다. 최종 `solver.py`는
해시가 고정된 추출물과 커널 VM 추적을 입력으로 사용하며, 전체 펌웨어
복호화를 다시 수행하지는 않습니다.

## 2. 사용자 공간 `uhattest` VM

`init`은 콘솔 입력을 다음과 같이 실행합니다.

```text
/usr/sbin/uhattest /var/lib/uhcon/device-policy.bin <사용자 입력>
```

`uhattest`의 관찰된 처리 순서는 다음과 같습니다.

1. `argv[2]`가 정확히 `FLAG{64 lowercase hex}`인지 검사합니다.
2. 중괄호 안 64글자를 32바이트로 디코드합니다.
3. `attest_blob.bin`이 정의하는 4,096개 레코드를 따라갑니다.
4. 레코드마다 8개 micro-op을 실행하므로 총 32,768개 연산입니다.
5. 결과 32바이트를 다시 `FLAG{...}`로 포맷합니다.
6. 이 **변환된 문자열**을 `/dev/uhsec` ioctl에 전달합니다.

ioctl request는 `0x40201d79`이고, 인자는 정책 포인터, 변환된 토큰 포인터,
정책 길이 `0x16490`, 토큰 길이 `0x46`, 정책 binding 값 `0xe9705ae9`를
포함합니다.

VM의 24개 micro-op은 XOR, 덧셈/뺄셈, rotate, 홀수 곱셈, xor-shift,
NOT/NEG, byte/bit reverse, register swap으로 구성됩니다. 모두 `2^32`
위에서 가역입니다. 특히 홀수 곱셈은 모듈러 역원을 사용하고, xor-shift는
shift를 두 배씩 늘리며 역변환했습니다.

초기 분석에서 `device-policy.bin[0xb0:0xd0]`을 최종 목표로 오인하면
사용자 입력 `199e...`와 변환 결과 `c66e...`를 얻습니다. 그러나 커널은
그 뒤에 별도의 검증 VM과 제약식을 수행하므로 둘 다 거부됩니다.

## 3. 커널 `/dev/uhsec` 검증기

복호화된 KERN을 QEMU로 부팅하면 `/dev/uhsec`가 생성됩니다. ioctl 처리
루틴을 추적한 결과 정책은 다음 다섯 섹션으로 나뉘었습니다.

| 섹션 | offset | length | 역할 |
|---:|---:|---:|---|
| 0 | `0x00a0` | `0x0030` | 기본 무결성/바인딩 |
| 1 | `0x00d0` | `0x0108` | 전처리/구조 검증 |
| 2 | `0x01e0` | `0x4020` | 2,048-op 가역 VM |
| 3 | `0x4200` | `0x12240` | GF(2^8) 선형 제약 |
| 4 | `0x16440` | `0x0050` | 마지막 8개 predicate |

커널 단계의 핵심 흐름은 다음과 같습니다.

```text
ioctl token 32B
  -> sec2 가역 VM 2,048회
  -> 256-bit permutation
  -> sec3의 32개 GF(2^8) 식
  -> 마지막 8개 predicate
  -> 승인/거부
```

sec3의 각 레코드는 post-permutation 상태 앞 16바이트에 대한 AES field
`GF(2^8)` 내적입니다. 32개 식에 가우스 소거를 적용해 앞 16바이트를
구했고, 마지막 predicate와 경로 제약으로 뒤 16바이트를 확정했습니다.

```text
post-bitperm target =
c2f17f0ac621686150bd4f24e3502cb00ce94fc8da3b2b74b8320cc2cdd2ad5f
```

256-bit permutation을 역으로 적용하면 sec2 VM 직후 목표 상태입니다.

```text
sec2 target =
d88a5251ca202087271e652bf9b833e41dc02b9fe3a60ae5cc397b4c48f83fd0
```

커널 VM의 opcode는 XOR, ADD/SUB, ROL/ROR, source word와 섞는 연산,
SWAP, 홀수 곱셈, xor-shift, NOT/NEG, byte-swap의 가역 조합입니다.
2,048개 연산을 역순으로 적용하면 커널이 ioctl에서 요구하는 값이 나옵니다.

```text
kernel/ioctl credential =
3de1183ba2a5ed773e21953c848698417fc86974f7de1c02e282e46f037ee7a0
```

GDB 하드웨어 브레이크포인트의 중복 stop이 섞였던 최초 추적본은
`work/sec2_ops.raw-gdb.json`으로 보존했습니다. 최종 솔버는 인덱스가
`0..2047`로 연속인 정리된 `work/sec2_ops.json`만 사용하며, 역산 뒤
정방향 2,048회를 다시 실행해 목표 상태와 같은지 검사합니다.

## 4. 최종 사용자 입력 역산

커널 중간 credential을 `uhattest` VM의 출력 목표로 놓고 32,768개
micro-op을 역순으로 적용했습니다.

```text
uhattest inverse(3de118...7ee7a0)
  = 5b6ddad4282d776ef24588d29d59a6b1a94908356666a9cba2422eaa8c3071a5
```

정방향 재검증도 일치합니다.

```text
uhattest forward(5b6dda...3071a5)
  = 3de1183ba2a5ed773e21953c848698417fc86974f7de1c02e282e46f037ee7a0
```

따라서 콘솔과 사이트에 넣어야 할 최종 값은 `5b6dda...`입니다.

## 5. 재현

챌린지 폴더에서 다음을 실행합니다.

```powershell
python solver.py
```

출력:

```text
post_bitperm_target=c2f17f0ac621686150bd4f24e3502cb00ce94fc8da3b2b74b8320cc2cdd2ad5f
sec2_target=d88a5251ca202087271e652bf9b833e41dc02b9fe3a60ae5cc397b4c48f83fd0
kernel_credential_intermediate=FLAG{3de1183ba2a5ed773e21953c848698417fc86974f7de1c02e282e46f037ee7a0}
kernel_credential_is_not_the_submission=true
final_flag=FLAG{5b6ddad4282d776ef24588d29d59a6b1a94908356666a9cba2422eaa8c3071a5}
```

`solver.py`는 다음을 모두 검사합니다.

- `sec2_ops.json`의 SHA-256과 정확히 2,048개 레코드인지 여부
- 커널 VM inverse/forward 왕복
- 원본 `uhattest`, `attest_blob.bin`, `device-policy.bin`의 SHA-256
- 사용자 VM inverse/forward 왕복
- 중간 credential과 최종 payload의 예상값

## 6. 원본 QEMU 및 서버 검증

패치하지 않은 `work/linux.img`와 원본 `initramfs.cpio`를 사용한 QEMU
실행 로그 `work/qemu_accept.log`의 마지막 부분은 다음과 같습니다.

```text
UHCON appliance boot complete
field service token: FLAG{5b6ddad4282d776ef24588d29d59a6b1a94908356666a9cba2422eaa8c3071a5}
service credential accepted
[   14.300081] reboot: Power down
```

분석용 분기 패치를 모두 원복한 검증 정보와 명령은
`work/final-qemu-validation.txt`에도 보존했습니다. 마지막으로 같은
`5b6dda...` 값을 대회 사이트에 제출해 다음 응답을 받았습니다.

```json
{"message":"Correct","status":"correct"}
```

제출 이력과 중간값 구분은 `ATTEMPTS.md`, 최종 서버 영수증은
`SUBMISSION_RESULT.txt`, 최종 플래그 한 줄은 `FINAL_CANDIDATE.txt`에
보존했습니다.
