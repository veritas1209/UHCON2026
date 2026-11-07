# UHCON 2026 Quals Writeups

> 🥇 **예선 1위 · 8 / 8 solved**

2026년 10월 31일 진행된 UHCON 2026 예선의 전체 풀이와 최종 solver/exploit을 정리한 저장소입니다.

각 문제 디렉터리의 `README.md`에는 분석 과정, 핵심 취약점 또는 역산 방법, 재현 절차, 플래그, 최종 코드 전문이 들어 있습니다. 한 문서로 이어서 보고 싶다면 [FULL_WRITEUP.md](FULL_WRITEUP.md)를 확인하세요.

## Challenges

| ID | Challenge | Category | 핵심 아이디어 |
| ---: | --- | :---: | --- |
| 1 | [Circulation](pwn/01-circulation/) | Pwn / Kernel | lease UAF → PTE 재활용 → kCFI 대응 callback |
| 2 | [blitter](pwn/02-blitter/) | Pwn | UAF, safe-linking, large-tcache, wide-FILE FSOP |
| 3 | [Media Approval](web/03-media-approval/) | Web | TinyMCE DOM clobbering + NotchLC stale-stack leak |
| 4 | [ThreadMAZE](reversing/04-threadmaze/) | Reversing | 코드 레이아웃 복원 + 13단계 dispatcher 역연산 |
| 5 | [Archive Relay](pwn/05-archive-relay/) | Pwn / Web | 이중 디코딩 SQLi + SQLite race + `system(db)` |
| 6 | [KSMC](web/06-ksmc/) | Web | stored CSS oracle + reviewer capability + ZIP import |
| 7 | [Ghost Touch](reversing/07-ghost-touch/) | Reversing / Firmware | Cortex-M7 모델 복호화 + 제스처 합성 |
| 8 | [Block Inspection Service](web/08-block-inspection-service/) | Web | CRLF smuggling + Arrow fixed-width OOB read |

## Repository layout

```text
.
├── pwn/
│   ├── 01-circulation/
│   ├── 02-blitter/
│   └── 05-archive-relay/
├── reversing/
│   ├── 04-threadmaze/
│   └── 07-ghost-touch/
├── web/
│   ├── 03-media-approval/
│   ├── 06-ksmc/
│   └── 08-block-inspection-service/
├── FULL_WRITEUP.md
└── requirements.txt
```

문제별 디렉터리에는 다음 자료만 선별해 두었습니다.

- 전체 풀이가 담긴 `README.md`
- 실제 최종 solver/exploit 소스
- solver가 직접 사용하는 작은 상태 파일 또는 입력 샘플

브라우저 프로필, 쿠키, 계정 상태, 로그, 디버거 덤프, 컴파일 산출물과 대용량 중간 파일은 포함하지 않습니다.

## Reproduction

공통 Python 의존성은 다음과 같이 설치할 수 있습니다.

```bash
python -m pip install -r requirements.txt
```

공식 문제 첨부 파일은 이 저장소에서 재배포하지 않습니다. 바이너리나 컨테이너가 필요한 문제는 각 문제의 `README.md`에 적힌 위치에 공식 첨부 파일을 풀어 둔 뒤 실행하세요. 대회 서버가 종료된 경우 원격 제출 단계는 재현되지 않을 수 있습니다.

공개본에서는 개인 머신의 절대 경로만 현재 파일 기준의 상대 경로로 정리했으며, 공격 로직과 최종 코드는 그대로 보존했습니다.

## Disclaimer

이 코드는 종료된 CTF 문제의 학습과 재현을 위해 공개합니다. 허가받지 않은 시스템을 대상으로 사용하지 마세요.
