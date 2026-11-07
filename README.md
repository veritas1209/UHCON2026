# UHCON 2026 Writeups

UHCON 2026 예선과 결선에서 사용한 풀이 기록과 최소 재현 코드를 정리한 저장소입니다.
공식 문제 바이너리, VM 이미지, 브라우저 번들, 세션 쿠키와 실행 로그는 포함하지 않습니다.

## 디렉터리

- [`quals/`](quals/): 2026-10-31 예선, 8 / 8 solved
- [`final/`](final/): 2026-11-07 결선 문제별 기록

## Final 상태

| ID | 문제 | 상태 | 공개 자료 범위 |
| ---: | --- | --- | --- |
| 1 | [SheBanG](final/01-shebang/) | KoTH 참가 완료 | 생성기, 누적 금지 바이트 대응, 라운드별 결과 |
| 2 | [Deadband](final/02-deadband/) | 해결·플랫폼 확인 | CDATA/HTML 재해석, manifest loader, 최종 solver |
| 3 | [Bot](final/03-bot/) | 팀 해결 확인 | 공개 산출물은 부분 재현이며 최종 live run 전체를 독립 재현하지 않음 |
| 4 | [Cold Boot](final/04-cold-boot/) | 플래그 회수·원격 solver 검증 | 펌웨어 분석, PAX/HENV/RMAP 체인 |
| 5 | [DVD](final/05-dvd/) | **대회 중 미해결** | 실패한 CR4 경로와 사후 공식 PTE/PXE 해법 비교 |
| 6 | [Sealed Update](final/06-sealed-update/) | 해결·Correct 응답 확인 | 사용자/커널 2단 검증 역산 |
| 7 | [Latchwork](final/07-latchwork/) | 해결·제출 확인 | 128-cycle 역산 solver |

## 재현 범위

각 문제 폴더에는 한국어 풀이와 최종 또는 가장 가까운 solver 소스만 남겼습니다.
공식 첨부 파일이 필요한 경우 문제 페이지에서 받은 파일을 해당 폴더에 별도로 배치해야 합니다.
대회 서버 종료 뒤에는 원격 단계가 그대로 재현되지 않을 수 있습니다.

```bash
python -m pip install -r final/requirements.txt
```

## 주의

이 코드는 종료된 CTF 문제의 학습과 재현을 위한 것입니다. 허가받지 않은 시스템에 사용하지 마세요.
