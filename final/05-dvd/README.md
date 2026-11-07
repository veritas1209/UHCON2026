# UHCON 2026 FINAL — DVD

> 상태: **대회 중 미해결**
> 공개 자료: 실패한 CR4 기반 익스플로잇 시도와 사후 회고

## 대회 중 확인한 부분

- `0x222000` WRITE와 `0x222004` READ 모두 0x40-byte 커널 스택 버퍼에 사용자 길이를 그대로 사용한다.
- READ OOB로 stack cookie(`+0x40`)와 `nt!IofCallDriver+0x74` 계열 반환주소(`+0xc8`)를 누출했다.
- WRITE에서는 cookie를 보존하고 `+0x68`부터 반환주소를 제어했다.
- 로컬 환경에서는 CR4.SMEP을 내리고 사용자 셸코드로 점프하는 체인이 SYSTEM token과 더미 플래그를 읽었다.
- 원격에서는 최종 WRITE 뒤 실행이 중단됐고 실제 플래그를 얻지 못했다.

## 결정적 오판

대회 중 시도는 `CR4.SMEP clear`만으로 사용자 가상주소를 커널에서 실행할 수 있다고 가정했다. 공식 해설은 KVAS 환경의 페이지 테이블 속성을 직접 바꾸는 경로였다.

```text
READ 0x200
  -> cookie + nt base leak
  -> cookie-preserving WRITE ROP
  -> MiGetPteAddress(shellcode)
  -> PTE U/S bit clear
  -> self-reference로 상위 PXE/PML4E NX bit clear
  -> CR3 reload / TLB flush
  -> kernel shellcode
  -> token stealing
```

즉, 이 폴더의 `exploit_attempt.c`는 완성 solver가 아니다. [`ATTEMPT_WRITEUP.md`](ATTEMPT_WRITEUP.md)는 당시 관찰과 로컬 성공 경로를 보존한 기록이며, 공식 PTE/PXE 체인은 구현되지 않았다.

## 포함 파일

- `ATTEMPT_WRITEUP.md`: 대회 중 작성한 분석 및 로컬 검증 기록
- `exploit_attempt.c`: 원격에서 실패한 CR4 기반 시도
