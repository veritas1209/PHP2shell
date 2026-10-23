#!/usr/bin/env python3
"""Match a live mod_php observation to one exact, verified profile."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from profile import (
    PHP81_TRANS_SID_RUNTIME_KEYS,
    ProfileError,
    load_json,
    load_profile,
    require_verified,
)


def verify(
    profile_path: str,
    observation_path: str,
    expected_profile_id: str,
    expected_repo_digest: str,
    expected_image_id: str,
) -> dict[str, object]:
    profile = load_profile(profile_path)
    require_verified(profile)
    if profile.id != expected_profile_id:
        raise ProfileError(
            f"profile ID mismatch: {profile.id!r} != {expected_profile_id!r}"
        )

    image = profile.raw["build"]["image"]
    if image["repo_digest"] != expected_repo_digest:
        raise ProfileError("profile repository digest differs from the runner allow-list")
    if image["image_id"] != expected_image_id:
        raise ProfileError("profile image ID differs from the runner allow-list")

    observed, _ = load_json(observation_path)
    if set(observed) != {"php", "runtime"}:
        raise ProfileError("runtime observation has missing or unknown top-level keys")
    if observed["php"] != dict(profile.raw["build"]["php"]):
        raise ProfileError("live PHP build fingerprint does not match the profile")
    observed_runtime = observed["runtime"]
    if not isinstance(observed_runtime, dict):
        raise ProfileError("live runtime fingerprint must be an object")
    expected_runtime = dict(profile.raw["runtime"])
    missing = set(expected_runtime) - set(observed_runtime)
    unknown = set(observed_runtime) - set(expected_runtime) - set(
        PHP81_TRANS_SID_RUNTIME_KEYS
    )
    if missing or unknown:
        raise ProfileError("live runtime settings have missing or unknown keys")
    projected_runtime = {
        key: observed_runtime[key]
        for key in expected_runtime
    }
    if projected_runtime != expected_runtime:
        raise ProfileError("live runtime settings do not match the profile")
    # runtime.php reports the newer session/rewrite observations for every
    # strategy.  Older profiles intentionally omit those keys, so their
    # manifest retains the exact legacy runtime shape while the full observed
    # JSON artifact still records every live value.
    return projected_runtime


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--observation", required=True)
    parser.add_argument("--expected-profile-id", required=True)
    parser.add_argument("--expected-repo-digest", required=True)
    parser.add_argument("--expected-image-id", required=True)
    parser.add_argument("--runtime-output", required=True)
    args = parser.parse_args()
    runtime = verify(
        args.profile,
        args.observation,
        args.expected_profile_id,
        args.expected_repo_digest,
        args.expected_image_id,
    )
    Path(args.runtime_output).write_text(
        json.dumps(runtime, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
