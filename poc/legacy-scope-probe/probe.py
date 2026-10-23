#!/usr/bin/env python3
"""Benign pre-script session upload-progress probe for the local Docker lab.

The caller supplies only a private container address, a constrained session
identifier, and a local artifact path.  This helper carries no command or
memory-corruption payload.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import socket
import time
from pathlib import Path


BOUNDARY = b"----php2shell-legacy-bounded"
FILE_DATA = b"A" * (1024 * 1024)


def field(name: bytes, value: bytes) -> bytes:
    return (
        b"--"
        + BOUNDARY
        + b'\r\nContent-Disposition: form-data; name="'
        + name
        + b'"\r\n\r\n'
        + value
        + b"\r\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--sid", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        address = ipaddress.ip_address(args.host)
    except ValueError as exc:
        parser.error(f"host must be a literal IP address: {exc}")
    if not address.is_private:
        parser.error("host must be a private Docker address")
    if not re.fullmatch(r"[A-Za-z0-9,-]{16,48}", args.sid):
        parser.error("session ID is outside the fixed lab grammar")

    prefix = field(b"PHP_SESSION_UPLOAD_PROGRESS", b"bounded")
    prefix += (
        b"--"
        + BOUNDARY
        + b'\r\nContent-Disposition: form-data; name="f"; '
        + b'filename="benign.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'
    )
    suffix = b"\r\n--" + BOUNDARY + b"--\r\n"
    body_length = len(prefix) + len(FILE_DATA) + len(suffix)
    headers = (
        b"POST /index.php HTTP/1.1\r\n"
        + b"Host: legacy-target\r\n"
        + b"Cookie: PHPSESSID="
        + args.sid.encode("ascii")
        + b"\r\nContent-Type: multipart/form-data; boundary="
        + BOUNDARY
        + b"\r\n"
        + f"Content-Length: {body_length}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
    )

    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(15)
        sock.connect((str(address), 80))
        sock.sendall(headers + prefix + FILE_DATA[:65536])
        # Keep the upload open so the runner can observe the pre-script record.
        time.sleep(5)
        sock.sendall(FILE_DATA[65536:] + suffix)
        response = bytearray()
        while len(response) < 1024 * 1024:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response.extend(chunk)

    Path(args.output).write_bytes(response)
    if b"SCRIPT_REACHED" not in response:
        raise SystemExit("application script marker was not returned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

