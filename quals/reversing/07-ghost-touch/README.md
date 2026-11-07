# Ghost Touch — UHCON

## 결과

```text
FLAG{228a5ebdb78f46f9829470e1704d8111}
```

최종 `candidate.json`의 128개 좌표를 공식 화면이 사용하는 `POST http://3.36.129.171:8080/api/capture`에 한 번 전송했다. HTTP 200과 아래 응답을 받았다.

```json
{"status":"OPEN","flag":"FLAG{228a5ebdb78f46f9829470e1704d8111}"}
```

원문 응답, 검증 시각, 요청 본문의 SHA-256은 `verification.json`에 있다. 대회 제출 사이트에는 제출하지 않았다.

## 제공 파일과 분석 환경

- `for_user.zip` SHA-256: `093e17eadbf940a1009adf815a279c86bec7bfe03a4d263cbfd3b1b53b56ca67`
- `firmware_m7.elf` SHA-256: `b77ccbeee97a5fb53ca3296e1f58f1588c4daf90e0c147b3dfe74b265a26a80f`
- ELF32 little-endian ARM, Cortex-M7/Thumb, 진입점 `0x15e9`
- `.gtvm`: 가상 주소 `0xc0`, 크기 64바이트
- `.text`: 가상 주소 `0x100`, 파일 오프셋 `0x1100`
- 웹 서버는 Python 3.12 `.pyc`, 화면 코드는 일반 JavaScript로 제공된다.

REA로 압축 파일을 검증하고 안전하게 추출했다. REA의 Windows Ghidra 경로는 ARM ELF를 지원하지 않아 이후 정적 분석은 WSL의 기존 Python 3.12와 `libcapstone.so.4`를 사용했다. 추가 패키지는 설치하지 않았다. `.pyc`는 `marshal`로 코드 객체를 읽고 `dis`로 해석했으며 서버 모듈을 실행하지 않았다.

REA 압축 파일 인벤토리 근거: `ev_123e6b2be75c119c7f064595646ca1eb20fa73637b6cc6469463cbce951ccb8b`. 네이티브 함수의 의미는 직접 디스어셈블리에서 추론했고, 최종 입력은 실제 서버의 `OPEN`으로 검증했다.

## 1. 브라우저 좌표 수집 경로

`runtime/server/web/app.js`는 빈 캔버스에서 누르고 이동하는 동작을 20 ms 간격으로 기록한다. 센서 좌표는 각 축 `0..4095`이고 다음 형태로 전송한다.

```json
{"points":[[x0,y0],[x1,y1], ...]}
```

`acquisition.pyc`의 `is_live`와 `crop_live_samples`를 분석하면 **두 축이 모두 `3712..3967`인 점만** 남기고 그중 처음 128개를 펌웨어에 전달한다. 이 영역 밖의 점은 잘리며, 유효 점이 128개보다 적으면 `E_TRACE`가 된다.

펌웨어 요청은 `GST1`, 버전 1, 형식 1, 샘플 수 128, 페이로드 크기 512, CRC32를 가진 528바이트 프레임이다. 웹 API는 이 프레임을 대신 만든다. 프레임에서 분리한 x/y 배열은 `0x106c` 함수가 검사하고 복사한다.

## 2. 펌웨어의 전체 검증 흐름

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

## 3. 모델 복호화

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

## 4. 좌표에서 특징 바이트로

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

## 5. 유효 입력 합성

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

## 재현 방법

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

## 저장 파일

- `analyze_firmware.py`: Capstone 기반 정적 디스어셈블리 및 Python bytecode 분석
- `solve.py`: 모델 복호화, 독립 Python 검증기, 공식 입력 재생
- `search.cpp`: 정확한 정수 검증기와 확률적 탐색기
- `candidate.json`: 실제 `OPEN` 응답을 받은 128점 입력
- `candidate_neural.json`: 해시 탐색 전의 중간 후보
- `model_decoded.bin`: CRC를 확인하고 첫 가중치를 전치한 모델
- `*_disassembly.txt`: 정적 분석 출력
- `verification.json`: 공식 서버의 성공 응답 증거
- `flag.txt`: 확인한 플래그

## 최종 풀이 코드 전체

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
