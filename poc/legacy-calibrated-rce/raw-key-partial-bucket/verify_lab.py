#!/usr/bin/env python3
"""Fail-closed checks for the shared raw-key local Docker lab."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from typing import Any


class VerificationError(ValueError):
    pass


LAB_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)


def read_one(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if not isinstance(value, dict):
        raise VerificationError(f"{path}: expected one JSON object")
    return value


def lab_address(raw: str) -> bool:
    address = ipaddress.ip_address(raw)
    return any(
        address.version == network.version and address in network
        for network in LAB_NETWORKS
    )


def verify_image(data: dict[str, Any], reference: str, expected_id: str) -> None:
    if data.get("Id") != expected_id:
        raise VerificationError("image content ID mismatch")
    if data.get("Os") != "linux" or data.get("Architecture") != "amd64":
        raise VerificationError("only linux/amd64 images are allowed")
    if reference not in (data.get("RepoDigests") or []):
        raise VerificationError("pinned repository digest is absent")


def verify_network(data: dict[str, Any], name: str) -> None:
    if data.get("Name") != name or data.get("Internal") is not True:
        raise VerificationError("network is not the fresh internal network")
    if data.get("Ingress") is True or data.get("Scope") != "local":
        raise VerificationError("network must be local and non-ingress")


def verify_runtime(
    data: dict[str, Any],
    expected_php: str,
    expected_apache: str,
    expected_sapi: str,
    expected_memory: str,
) -> None:
    expected = {
        "php_version": expected_php,
        "apache_version": expected_apache,
        "sapi": expected_sapi,
        "memory_limit": expected_memory,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise VerificationError(
                f"runtime {key} mismatch: {data.get(key)!r} != {value!r}"
            )
    if data.get("upload_progress_enabled") != "1":
        raise VerificationError("session upload progress is not enabled")


def verify_worker(pid: int, expected_parent: int, output: str) -> None:
    if pid <= 1 or expected_parent <= 1:
        raise VerificationError("invalid worker or parent process ID")
    proc = Path(f"/proc/{pid}")
    comm = (proc / "comm").read_text(encoding="ascii").strip()
    fields: dict[str, str] = {}
    for line in (proc / "status").read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key] = value.strip()
    try:
        parent = int(fields["PPid"])
        uids = [int(value) for value in fields["Uid"].split()]
        gids = [int(value) for value in fields["Gid"].split()]
    except (KeyError, ValueError) as exc:
        raise VerificationError("could not parse worker identity") from exc
    if comm != "apache2" or parent != expected_parent:
        raise VerificationError("unexpected Apache worker process identity")
    if uids != [33, 33, 33, 33] or gids != [33, 33, 33, 33]:
        raise VerificationError("Apache worker is not www-data uid/gid 33")
    evidence = {
        "pid": pid,
        "parent_pid": parent,
        "comm": comm,
        "uids": uids,
        "gids": gids,
    }
    Path(output).write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def verify_container(
    data: dict[str, Any],
    name: str,
    image_reference: str,
    image_id: str,
    network: str,
    running: bool,
    user: str | None,
    hardened: bool,
    output_volume: str | None,
    output_destination: str | None,
    output_read_only: bool,
) -> None:
    if str(data.get("Name", "")).lstrip("/") != name:
        raise VerificationError("container name mismatch")
    if data.get("Image") != image_id:
        raise VerificationError("container image content ID mismatch")
    if data.get("Config", {}).get("Image") != image_reference:
        raise VerificationError("container was not created from the pinned digest")
    if user is not None and data.get("Config", {}).get("User") != user:
        raise VerificationError("container user mismatch")
    if running and data.get("State", {}).get("Running") is not True:
        raise VerificationError("container is not running")

    host = data.get("HostConfig") or {}
    if host.get("NetworkMode") != network:
        raise VerificationError("container uses an unexpected network")
    if host.get("PortBindings") not in (None, {}):
        raise VerificationError("container has published host ports")
    if host.get("Privileged") is True:
        raise VerificationError("privileged containers are forbidden")
    for key in ("PidMode", "IpcMode", "UTSMode"):
        if host.get(key) == "host":
            raise VerificationError(f"host {key} is forbidden")

    ports = (data.get("NetworkSettings") or {}).get("Ports") or {}
    if any(bindings for bindings in ports.values()):
        raise VerificationError("container has a published port")
    networks = (data.get("NetworkSettings") or {}).get("Networks") or {}
    if set(networks) != {network}:
        raise VerificationError("container has unexpected network attachments")
    if running:
        addresses = [
            networks[network].get("IPAddress"),
            networks[network].get("GlobalIPv6Address"),
        ]
        addresses = [value for value in addresses if value]
        if not addresses or not all(lab_address(value) for value in addresses):
            raise VerificationError("container address is not private")

    if hardened:
        if host.get("ReadonlyRootfs") is not True:
            raise VerificationError("attacker root filesystem is not read-only")
        if "ALL" not in (host.get("CapDrop") or []):
            raise VerificationError("attacker capabilities were not all dropped")
        security = host.get("SecurityOpt") or []
        if not any(value.startswith("no-new-privileges") for value in security):
            raise VerificationError("no-new-privileges is missing")

    volumes = [mount for mount in data.get("Mounts", []) if mount.get("Type") == "volume"]
    if output_volume is None:
        if volumes:
            raise VerificationError("unexpected named volume")
    else:
        matching = [
            mount
            for mount in volumes
            if mount.get("Name") == output_volume
            and mount.get("Destination") == output_destination
        ]
        if len(matching) != 1:
            raise VerificationError("required proof volume is missing")
        if matching[0].get("RW") is output_read_only:
            raise VerificationError("proof volume access mode mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="kind", required=True)

    image = subparsers.add_parser("image")
    image.add_argument("--inspect", required=True)
    image.add_argument("--reference", required=True)
    image.add_argument("--expected-id", required=True)

    network = subparsers.add_parser("network")
    network.add_argument("--inspect", required=True)
    network.add_argument("--name", required=True)

    runtime = subparsers.add_parser("runtime")
    runtime.add_argument("--input", required=True)
    runtime.add_argument("--expected-php", required=True)
    runtime.add_argument("--expected-apache", required=True)
    runtime.add_argument("--expected-sapi", default="apache2handler")
    runtime.add_argument("--expected-memory", default="32M")

    worker = subparsers.add_parser("worker")
    worker.add_argument("--pid", required=True, type=int)
    worker.add_argument("--expected-parent", required=True, type=int)
    worker.add_argument("--output", required=True)

    container = subparsers.add_parser("container")
    container.add_argument("--inspect", required=True)
    container.add_argument("--name", required=True)
    container.add_argument("--image-reference", required=True)
    container.add_argument("--image-id", required=True)
    container.add_argument("--network", required=True)
    container.add_argument("--running", action="store_true")
    container.add_argument("--user")
    container.add_argument("--hardened", action="store_true")
    container.add_argument("--output-volume")
    container.add_argument("--output-destination")
    container.add_argument("--output-read-only", action="store_true")

    args = parser.parse_args()
    if args.kind == "worker":
        verify_worker(args.pid, args.expected_parent, args.output)
        return 0
    if args.kind == "runtime":
        data = read_one(args.input)
    else:
        data = read_one(args.inspect)
    if args.kind == "image":
        verify_image(data, args.reference, args.expected_id)
    elif args.kind == "network":
        verify_network(data, args.name)
    elif args.kind == "runtime":
        verify_runtime(
            data,
            args.expected_php,
            args.expected_apache,
            args.expected_sapi,
            args.expected_memory,
        )
    else:
        verify_container(
            data,
            args.name,
            args.image_reference,
            args.image_id,
            args.network,
            args.running,
            args.user,
            args.hardened,
            args.output_volume,
            args.output_destination,
            args.output_read_only,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
