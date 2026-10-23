#!/usr/bin/env python3
"""Offline ELF inspection, candidate calibration, and target-manifest helper."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from elf import ElfError, inspect_elf, verify_elf_against_profile
from profile import (
    ProfileError,
    is_allowed_lab_address,
    load_json,
    load_profile,
    profile_as_mutable,
    require_verified,
    validate_profile,
)


def _write_json(value: Any, destination: str | None) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=False) + "\n"
    if destination is None or destination == "-":
        sys.stdout.write(encoded)
        return
    path = Path(destination)
    if path.exists():
        raise ProfileError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded, encoding="utf-8", newline="\n")


def _canonical_address(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ProfileError(f"invalid target address: {value!r}") from exc
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if not is_allowed_lab_address(addr):
        raise ProfileError(f"refusing non-lab target address: {addr}")
    return str(addr)


def command_inspect(args: argparse.Namespace) -> int:
    metadata = inspect_elf(args.libphp)
    output = metadata.as_dict()
    output["path"] = str(Path(args.libphp))
    _write_json(output, args.output)
    return 0


def command_verify(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile)
    metadata = verify_elf_against_profile(args.libphp, profile)
    print(
        f"OK: {profile.id}: sha256={metadata.sha256} "
        f"zif_system={hex(metadata.symbols['zif_system'])} "
        f"zval_ptr_dtor={hex(metadata.symbols['zval_ptr_dtor'])}"
    )
    return 0


def _parse_cli_hex(value: str, where: str) -> str:
    try:
        number = int(value, 0)
    except ValueError as exc:
        raise ProfileError(f"{where} is not an integer: {value!r}") from exc
    if number < 0:
        raise ProfileError(f"{where} must not be negative")
    return hex(number)


def command_calibrate(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile)
    if profile.raw["verification"]["state"] != "candidate":
        raise ProfileError("calibration only accepts a candidate profile")
    data = profile_as_mutable(profile)
    changed: list[str] = []
    recipe = data["request_recipe"]

    for option, key in (
        ("stage1_fillers", "fillers"),
    ):
        value = getattr(args, option)
        if value is not None:
            recipe["stage1"][key] = value
            changed.append(f"stage1.{key}={value}")
    fixed_stage2_updates = (
        ("stage2_fillers", "fillers"),
        ("stage2_target", "target"),
        ("stage2_target_count", "target_count"),
        ("stage2_value_len", "value_len"),
    )
    if any(getattr(args, option, None) is not None for option, _key in fixed_stage2_updates):
        if recipe["stage2"]["strategy"] != "fixed-array-v1":
            raise ProfileError("fixed stage2 calibration options require fixed-array-v1")
    for option, key in fixed_stage2_updates:
        value = getattr(args, option, None)
        if value is not None:
            recipe["stage2"][key] = value
            changed.append(f"stage2.{key}={value}")
    adaptive_stage2_updates = (
        ("stage2_window", "window"),
        ("stage2_arrays", "arrays"),
    )
    if any(getattr(args, option, None) is not None for option, _key in adaptive_stage2_updates):
        if recipe["stage2"]["strategy"] != "adaptive-window-v1":
            raise ProfileError("adaptive stage2 calibration options require adaptive-window-v1")
    if getattr(args, "stage2_window", None) is not None:
        recipe["stage2"]["window"] = _parse_cli_hex(args.stage2_window, "stage2 window")
        changed.append(f"stage2.window={recipe['stage2']['window']}")
    if getattr(args, "stage2_arrays", None) is not None:
        recipe["stage2"]["arrays"] = args.stage2_arrays
        changed.append(f"stage2.arrays={args.stage2_arrays}")

    stage3 = recipe["stage3"]
    if args.fixed_htdata_offset is not None:
        if stage3["strategy"] != "fixed-carrier-v1":
            raise ProfileError("--fixed-htdata-offset requires fixed-carrier-v1")
        stage3["htdata_offset"] = _parse_cli_hex(args.fixed_htdata_offset, "htdata offset")
        changed.append(f"stage3.htdata_offset={stage3['htdata_offset']}")
    r0_options = (
        args.r0_page_lo,
        args.r0_page_hi,
        args.r0_page_step,
        args.r0_lowbits,
        args.r0_releak_every,
    )
    if any(value is not None for value in r0_options):
        if stage3["strategy"] != "r0-spray-v1":
            raise ProfileError("r0 calibration options require r0-spray-v1")
        search = stage3["r0_search"]
        if args.r0_page_lo is not None:
            search["page_lo"] = _parse_cli_hex(args.r0_page_lo, "r0 page lo")
            changed.append(f"r0.page_lo={search['page_lo']}")
        if args.r0_page_hi is not None:
            search["page_hi_exclusive"] = _parse_cli_hex(args.r0_page_hi, "r0 page hi")
            changed.append(f"r0.page_hi_exclusive={search['page_hi_exclusive']}")
        if args.r0_page_step is not None:
            search["page_step"] = _parse_cli_hex(args.r0_page_step, "r0 page step")
            changed.append(f"r0.page_step={search['page_step']}")
        if args.r0_lowbits is not None:
            values = [x.strip() for x in args.r0_lowbits.split(",") if x.strip()]
            if not values:
                raise ProfileError("--r0-lowbits must contain at least one value")
            search["lowbits"] = [_parse_cli_hex(x, "r0 lowbit") for x in values]
            changed.append("r0.lowbits=" + ",".join(search["lowbits"]))
        if args.r0_releak_every is not None:
            search["releak_every"] = args.r0_releak_every
            changed.append(f"r0.releak_every={args.r0_releak_every}")
    pre_updates = (
        ("r0_pre_session_count", "count"),
        ("r0_pre_session_value_len", "value_len"),
        ("r0_pre_session_name_prefix", "name_prefix"),
    )
    if any(getattr(args, option, None) is not None for option, _key in pre_updates):
        if stage3["strategy"] != "r0-spray-v1":
            raise ProfileError("pre-session calibration options require r0-spray-v1")
        pre = stage3["pre_session_fields"]
        for option, key in pre_updates:
            value = getattr(args, option, None)
            if value is not None:
                pre[key] = value
                changed.append(f"r0.pre_session_fields.{key}={value}")

    if not changed:
        raise ProfileError("no calibration value was supplied")
    if args.id is not None:
        data["id"] = args.id
    data["verification"] = {
        "state": "candidate",
        "runs": 0,
        "proof": "not-yet-verified",
        "verified_at": None,
    }
    suffix = "offline calibration: " + "; ".join(changed)
    old_notes = data["provenance"]["notes"]
    data["provenance"]["notes"] = (old_notes + " | " + suffix).strip(" |")
    validate_profile(data, source="calibrated candidate")
    _write_json(data, args.output)
    return 0


def command_manifest(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile)
    require_verified(profile)
    verify_elf_against_profile(args.libphp, profile)

    if args.image_id != profile.raw["build"]["image"]["image_id"]:
        raise ProfileError("--image-id does not match the profile")
    if args.repo_digest != profile.raw["build"]["image"]["repo_digest"]:
        raise ProfileError("--repo-digest does not match the profile")
    runtime, _raw = load_json(args.runtime_json)
    if runtime != dict(profile.raw["runtime"]):
        raise ProfileError("runtime JSON does not exactly match the profile")
    addresses = sorted({_canonical_address(value) for value in args.address})
    if not addresses:
        raise ProfileError("at least one --address is required")
    if args.minutes < 1 or args.minutes > 60:
        raise ProfileError("--minutes must be between 1 and 60")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    expires = now + timedelta(minutes=args.minutes)
    image = profile.raw["build"]["image"]
    manifest = {
        "schema_version": 1,
        "profile_id": profile.id,
        "profile_sha256": profile.file_sha256,
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "image": {
            "repo_digest": image["repo_digest"],
            "image_id": image["image_id"],
            "platform": image["platform"],
        },
        "libphp_sha256": profile.raw["build"]["libphp"]["sha256"],
        "runtime": runtime,
        "resolved_addresses": addresses,
    }
    _write_json(manifest, args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="offline tools for exact-build php2shell profiles"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect-libphp", help="derive hashes/build-id/symbol offsets from an ELF")
    inspect.add_argument("libphp")
    inspect.add_argument("--output", "-o")
    inspect.set_defaults(func=command_inspect)

    verify = sub.add_parser("verify-libphp", help="compare an ELF with a complete profile")
    verify.add_argument("libphp")
    verify.add_argument("--profile", required=True)
    verify.set_defaults(func=command_verify)

    calibrate = sub.add_parser(
        "calibrate-candidate",
        help="record measured heap values while keeping the output non-runnable",
    )
    calibrate.add_argument("--profile", required=True)
    calibrate.add_argument("--output", required=True)
    calibrate.add_argument("--id")
    calibrate.add_argument("--stage1-fillers", type=int)
    calibrate.add_argument("--stage2-fillers", type=int)
    calibrate.add_argument("--stage2-target", type=int)
    calibrate.add_argument("--stage2-target-count", type=int)
    calibrate.add_argument("--stage2-value-len", type=int)
    calibrate.add_argument("--stage2-window")
    calibrate.add_argument("--stage2-arrays", type=int)
    calibrate.add_argument("--fixed-htdata-offset")
    calibrate.add_argument("--r0-page-lo")
    calibrate.add_argument("--r0-page-hi")
    calibrate.add_argument("--r0-page-step")
    calibrate.add_argument("--r0-lowbits", help="comma-separated hexadecimal values")
    calibrate.add_argument("--r0-releak-every", type=int)
    calibrate.add_argument("--r0-pre-session-count", type=int)
    calibrate.add_argument("--r0-pre-session-value-len", type=int)
    calibrate.add_argument("--r0-pre-session-name-prefix")
    calibrate.set_defaults(func=command_calibrate)

    manifest = sub.add_parser(
        "make-target-manifest",
        help="bind a verified profile to freshly inspected local-lab evidence",
    )
    manifest.add_argument("--profile", required=True)
    manifest.add_argument("--libphp", required=True)
    manifest.add_argument("--runtime-json", required=True)
    manifest.add_argument("--image-id", required=True)
    manifest.add_argument("--repo-digest", required=True)
    manifest.add_argument("--address", action="append", required=True)
    manifest.add_argument("--minutes", type=int, default=15)
    manifest.add_argument("--output", required=True)
    manifest.set_defaults(func=command_manifest)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (ProfileError, ElfError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

