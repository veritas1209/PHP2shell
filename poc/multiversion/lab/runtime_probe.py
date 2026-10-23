#!/usr/bin/env python3
"""Fetch the runtime fingerprint over the isolated Docker network."""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from pathlib import Path


def fetch(url: str, attempts: int = 60) -> dict[str, object]:
    last: Exception | None = None
    for _ in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"Connection": "close"})
            with urllib.request.urlopen(request, timeout=2.0) as response:
                if response.status != 200:
                    raise RuntimeError(f"unexpected HTTP status {response.status}")
                value = json.loads(response.read(65536).decode("utf-8"))
                if not isinstance(value, dict):
                    raise RuntimeError("runtime endpoint did not return a JSON object")
                return value
        except Exception as exc:  # readiness includes refused/reset connections
            last = exc
            time.sleep(0.25)
    raise RuntimeError(f"target did not become ready: {last}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    observed = fetch(args.url)
    Path(args.output).write_text(
        json.dumps(observed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
