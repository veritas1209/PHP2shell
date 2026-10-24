# PHP 5.4.45 HTTP-only disclosure-to-RCE validation

## Result

The exact historical PHP 5.4.45 Apache image reached the fixed local proof
command `id>/out/p` in three independent fresh-ASLR containers, followed by
an additional successful run of the final symbol-based code.  The final
runner obtains every absolute address from an HTTP response.  It does not use
`/proc`, GDB, `LD_PRELOAD`, a debugger, or an address supplied by the host.

This remains an isolated lab result.  The target is attached only to a Docker
`--internal` network, has no published ports, and the only command in the
terminal carrier is `id>/out/p`.

## Pinned environment

- PHP: `5.4.45`
- Target image:
  `mirror.gcr.io/eugenesia/php@sha256:5681afdd0e07c7cbbece3f9cde77e5b7281768f54e1a2bbba319833c1ef638a9`
- Target image ID:
  `sha256:7cb054df8a5024e6fb9b2aba29568ec588103b0a56e67eff18cf02c9e62c0ea6`
- `/usr/lib/apache2/modules/libphp5.so` SHA-256:
  `23ac7473ce973a0d4cd54a105aa404a3ae91034fab5aa165321170b38785e124`
- `/lib/x86_64-linux-gnu/libc-2.19.so` SHA-256:
  `ac8998e80f439d625cf7721478d9862176a8857c75d96ce211c3fc792c30c0ea`
- Attacker image:
  `python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704`
- MPM: prefork with one worker, `KeepAlive Off`
- Default leak-route memory limit: `108M`
- `/producer.php` and `/terminal.php` memory limit: `12M` via the mounted
  per-file Apache configuration

Each saved target inspection has `HostConfig.PortBindings = {}`.  The target
environment in all final runs contains no `LD_PRELOAD` variable.

## HTTP address source

PHP 5.4 lacks the `php_session_reset_id()` call in the upload callback path
that made the PHP 5.5 trans-SID disclosure possible.  The 5.4 chain therefore
uses a different response surface.

After the upload-progress producer aborts, a second multipart request uses:

- one warm request;
- producer pads: `32`;
- first large field: `1,048,551` bytes;
- second large field: `1,041,384` bytes;
- multipart boundary length: `78`;
- session ID length: `30`;
- upload-progress value length: `8`.

At this geometry the backing bytes of
`$_POST['PHP_SESSION_UPLOAD_PROGRESS']` are replaced before userland reads
them.  The bounded `reflect.php` endpoint returns those eight bytes as hex.
They decode directly as a 64-bit little-endian pointer to
`libphp5.so!mbfl_encoding_ascii` at fixed offset `0xbc60e0`.  Subtracting that
offset yields a page-aligned libphp base.  No pointer is read from an error
log or a local process interface.

The exact lifecycle was confirmed separately.  The POST zval retains the
eight-byte progress value's stale backing allocation after multipart cleanup
frees that allocation.  During normal module activation, mbstring allocates
its two-entry detect-order list in the same 16-byte block and writes pointers
to `mbfl_encoding_ascii` and `mbfl_encoding_utf8`.  Userland `bin2hex()` then
reflects the first qword.  The exact image's symbols are:

```text
libphp5.so + 0xbc60e0  mbfl_encoding_ascii
libphp5.so + 0xbc7380  mbfl_encoding_utf8
```

The disclosure depends on an application endpoint that reflects this POST
value (or an equivalent binary-safe response sink).  It is therefore a valid
HTTP-only lab chain, but it is not a claim that every PHP 5.4 application has
such a response surface.

## Address relations

The HTTP response first provides the module base:

```text
libphp_base = http_pointer - 0xbc60e0
```

Three calibration containers without `LD_PRELOAD` then established the
following fixed relations for this immutable image and request sequence:

```text
stale_zval = libphp_base + 0x4744380
carrier    = libphp_base + 0x4744458
system     = libphp_base + 0x39a3490
```

Equivalently, `stale_zval - system = 0xda0ef0` and the controlled fake
HashTable begins at `stale_zval + 0xd8`.
The pinned libc places `system` at `libc + 0x41490`.

Development-only calibration established the fixed relations above for this
immutable image. Raw debugger, process-map, and interposer artifacts are
deliberately omitted from this publication set. The final runner does not read
or invoke any of them.

## Terminal request

After parsing the HTTP pointer, the client sends the established 12 MiB
terminal producer and a 39-pair Cookie consumer.  Pair 27 reclaims the stale
zval and pair 28 holds a 72-byte fake ZE2 HashTable, a 72-byte Bucket, and the
fixed command.  The fake zval clears the complete `zval_gc_info.buffered`
field, has refcount 1 and type `IS_ARRAY`, and points to the carrier at
`stale_zval + 0xd8`.  The HashTable destructor is the HTTP-derived libc
`system` address.

The terminal HTTP response is empty because the worker dies after invoking
the destructor.  Proof success is the root-owned Docker volume file written
by Apache's uid 33 process.

## Fresh-ASLR evidence

| Artifact | HTTP bytes | HTTP pointer | libphp base | `system` | stale zval | proof |
|---|---:|---:|---:|---:|---:|---|
| `http-only-success1b` | `e0d0f5487b710000` | `0x717b48f5d0e0` | `0x717b48397000` | `0x717b4bd3a490` | `0x717b4cadb380` | uid 33 |
| `http-only-success2` | `e080971cc3780000` | `0x78c31c9780e0` | `0x78c31bdb2000` | `0x78c31f755490` | `0x78c3204f6380` | uid 33 |
| `http-only-success3` | `e05090d832790000` | `0x7932d89050e0` | `0x7932d7d3f000` | `0x7932db6e2490` | `0x7932dc483380` | uid 33 |
| `http-only-symbol-final` | `e0801476f8790000` | `0x79f8761480e0` | `0x79f875582000` | `0x79f878f25490` | `0x79f879cc6380` | uid 33 |

Every proof file contains:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The distinct address ranges show that the three successful runs were fresh
ASLR instances rather than a reused target process.

## Reproduction

From this directory in WSL/Linux:

```bash
./run-http-only.sh review-1
```

The runner rejects an existing result label, validates both immutable image
IDs, creates a fresh internal network and proof volume, verifies PHP 5.4.45
and empty port bindings, runs an unprivileged read-only attacker container,
and accepts success only when `/out/p` starts with the expected uid-33 line.

Main files:

- `http_only54.py`: final HTTP disclosure and terminal requests;
- `run-http-only.sh`: final isolated, non-instrumented runner;
- `reflection.py`: bounded response parser and request builder used by the
  final chain;
- `probe56_leak.py` and `terminal_sequence.py`: fixed HTTP request helpers.

## Verification performed

- Final chain: required 3/3 fresh-ASLR success, plus one extra successful
  fresh-ASLR run after expressing the same arithmetic through the exact
  `mbfl_encoding_ascii` symbol offset.
- `python3 -m py_compile` passed for all three Python programs.
- `bash -n` passed for the publication runner.
- Final target inspections show no published ports and no preload variable.
- A source scan of `http_only54.py` and `run-http-only.sh` found no `/proc`
  or GDB access.
