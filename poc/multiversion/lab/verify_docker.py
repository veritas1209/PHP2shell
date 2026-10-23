#!/usr/bin/env python3
"""Fail-closed checks for images and isolated Docker lab objects."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from typing import Any


class VerificationError(ValueError):
    pass


_LAB_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    )
)


def _is_lab_address(address: ipaddress._BaseAddress) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(address in network for network in _LAB_NETWORKS if address.version == network.version)


def _read(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if not isinstance(value, dict):
        raise VerificationError(f"{path}: expected one JSON object")
    return value


def verify_image(data: dict[str, Any], reference: str, expected_id: str | None) -> str:
    image_id = data.get("Id")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise VerificationError("image inspection has no content-addressed ID")
    if expected_id is not None and image_id != expected_id:
        raise VerificationError(f"image ID mismatch: {image_id} != {expected_id}")
    if data.get("Os") != "linux" or data.get("Architecture") != "amd64":
        raise VerificationError("only linux/amd64 images are allowed")
    digests = data.get("RepoDigests") or []
    if reference not in digests:
        raise VerificationError(f"pinned repository digest is absent: {reference}")
    return image_id


def verify_network(data: dict[str, Any], name: str) -> None:
    if data.get("Name") != name or data.get("Internal") is not True:
        raise VerificationError("network is not the fresh internal network")
    if data.get("Ingress") is True or data.get("Scope") != "local":
        raise VerificationError("network must be local and non-ingress")


def verify_container(
    data: dict[str, Any],
    name: str,
    image_id: str,
    image_reference: str,
    network: str,
    must_be_running: bool,
    volume_name: str | None = None,
    volume_destination: str | None = None,
    volume_mode: str = "none",
    expected_user: str | None = None,
) -> list[str]:
    actual_name = str(data.get("Name", "")).lstrip("/")
    if actual_name != name:
        raise VerificationError(f"unexpected container name: {actual_name!r}")
    if data.get("Image") != image_id:
        raise VerificationError("container image ID differs from the pinned image")
    if data.get("Config", {}).get("Image") != image_reference:
        raise VerificationError("container was not created from the pinned digest reference")
    if expected_user is not None and data.get("Config", {}).get("User") != expected_user:
        raise VerificationError("container does not use the required non-privileged UID/GID")
    if data.get("Platform") not in (None, "linux"):
        raise VerificationError("container platform is not Linux")
    if must_be_running and data.get("State", {}).get("Running") is not True:
        raise VerificationError("container is not running")

    host = data.get("HostConfig") or {}
    if host.get("NetworkMode") != network:
        raise VerificationError("container uses an unexpected network mode")
    if host.get("PortBindings") not in (None, {}):
        raise VerificationError("container has published port bindings")

    settings = data.get("NetworkSettings") or {}
    for bindings in (settings.get("Ports") or {}).values():
        if bindings:
            raise VerificationError("container has a published port")
    networks = settings.get("Networks") or {}
    if set(networks) != {network}:
        raise VerificationError("container is attached to an unexpected network")

    addresses: list[str] = []
    attachment = networks[network]
    for key in ("IPAddress", "GlobalIPv6Address"):
        raw = attachment.get(key)
        if raw:
            address = ipaddress.ip_address(raw)
            if not _is_lab_address(address):
                raise VerificationError(f"container received a non-private address: {address}")
            addresses.append(str(address))
    if must_be_running and not addresses:
        raise VerificationError("running target has no private network address")

    volumes = [mount for mount in data.get("Mounts", []) if mount.get("Type") == "volume"]
    if volume_mode == "none":
        if volumes:
            raise VerificationError("container has an unexpected volume mount")
    else:
        if not volume_name or not volume_destination or len(volumes) != 1:
            raise VerificationError("container does not have exactly one required volume")
        mount = volumes[0]
        if mount.get("Name") != volume_name or mount.get("Destination") != volume_destination:
            raise VerificationError("container uses an unexpected volume or destination")
        expected_rw = volume_mode == "rw"
        if mount.get("RW") is not expected_rw:
            raise VerificationError("required volume has the wrong access mode")
    return addresses


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    image = sub.add_parser("image")
    image.add_argument("--inspect", required=True)
    image.add_argument("--reference", required=True)
    image.add_argument("--expected-id")
    image.add_argument("--print-id", action="store_true")

    network = sub.add_parser("network")
    network.add_argument("--inspect", required=True)
    network.add_argument("--name", required=True)

    container = sub.add_parser("container")
    container.add_argument("--inspect", required=True)
    container.add_argument("--name", required=True)
    container.add_argument("--image-id", required=True)
    container.add_argument("--image-reference", required=True)
    container.add_argument("--network", required=True)
    container.add_argument("--running", action="store_true")
    container.add_argument("--print-addresses", action="store_true")
    container.add_argument("--volume-name")
    container.add_argument("--volume-destination")
    container.add_argument("--volume-mode", choices=("none", "ro", "rw"), default="none")
    container.add_argument("--expected-user")

    args = parser.parse_args()
    data = _read(args.inspect)
    if args.command == "image":
        result = verify_image(data, args.reference, args.expected_id)
        if args.print_id:
            print(result)
    elif args.command == "network":
        verify_network(data, args.name)
    else:
        result = verify_container(
            data,
            args.name,
            args.image_id,
            args.image_reference,
            args.network,
            args.running,
            args.volume_name,
            args.volume_destination,
            args.volume_mode,
            args.expected_user,
        )
        if args.print_addresses:
            print("\n".join(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
