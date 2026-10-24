# PHP 7.0.33 HTTP-only local RCE verification

## Scope

This report records a security-research reproduction against one immutable
PHP 7.0.33 Apache image. Every request stayed inside a fresh Docker
`--internal` network. No host port was published. The only terminal command
embedded in the proof is `id>/out/p`.

This is a technical legacy-version result. It does not assert that PHP 7.0 is
within the official CVE-2026-109618 or CVE-2026-109619 CNA version range.

## Exact runtime

- image: `mirror.gcr.io/library/php@sha256:1d34b2e491a02ba7a8d26478132015e197a5ffea37f0a93b42621d11cfe042cc`
- image ID: `sha256:aa67a9c9814fb920a3aa01122b56010ddf1130710caf71a8871a0f1dbb4d78fd`
- PHP / SAPI: PHP 7.0.33 / Apache 2 handler, NTS
- `libphp7.so` SHA-256: `bebdad934a7df94fb646a3014dc784e88c13bca2a2645eee8b213ef325108447`
- `libphp7.so` build ID: `d3abf8f2994c033ec49435cebdb0434b641c499f`
- glibc 2.24 SHA-256: `b2c8bf64c2cafdce5cb263cc100749b5e6b3e4783eef2fff16ae1b4bc5633e16`
- glibc build ID: `aa889e26a70f98fa8d230d088f7cc5bf43573163`

The disclosure route uses the global 8 MiB PHP memory limit. Apache applies a
12 MiB, trans-SID-off configuration only to `/terminal.php`. The older
`/b.php` 128 MiB calibration route is not part of the final chain.

## HTTP disclosure

A1 uses eight query variables with 16-byte names and exhausts the 8 MiB
request during upload-progress handling. Calibration showed that the failed
request leaves:

- `PS(id) = main + 0x640f0`
- `PS(mod_data) = main + 0x544b0`
- `PS(send_cookie) = 1`

B1 supplies the SID through the Cookie header and moves
`PHP_SESSION_UPLOAD_PROGRESS` to the end of the multipart body. It uses five
101-page scalar carriers and no nested variables. A diagnostic offset pattern
proved that the last carrier's value offset `0x10f0` is copied over the stale
session-string header. The final request places an unpersistent PHP 7 string
header (`type_info=0x6`) there with a conservative length of 1 MiB.

The old `ps_files` object remains closeable: its `basedir` field is null and
its descriptor is `-1`. `ps_open_files`, `php_session_reset_id`, and both URL
encoding calls complete. B1 returns HTTP 200 with exactly 1 MiB in the
`Set-Cookie: PHPSESSID=` disclosure.

Two fixed qwords in that HTTP body provide all terminal addresses:

- `leak + 0x0c8f30 = main + 0x12b200`
- `leak + 0x063ee8 = libphp + 0x46c790` (`zval_ptr_dtor`)

`analyze_http70.py` applies those relations, then uses the independently
verified exact-image loader layout:

- `libc = libphp + 0x3a6f000`
- `system = libc + 0x3f480`
- therefore `system = libphp + 0x3aae480`

The final runner derives these values only from B1 HTTP bytes. It does not use
GDB, `/proc/*/maps`, ptrace, `LD_PRELOAD`, or a process-inspection address.

The 8 MiB leak-length boundary was also repeated under fresh ASLR:

- `fake_len=0x128000` returned exactly `0x128000` bytes in 3/3 runs.
- `fake_len=0x130000` ended with HTTP 500 and no disclosure in 3/3 runs.

The final chain intentionally keeps `fake_len=0x100000`, which was stable in
all full-chain runs and already contains both fixed address qwords.

## Terminal primitive

After A1/B1, the runner sends a producer and consumer to `/terminal.php` in
the same Apache worker. The 12 MiB producer leaves the session reference at
`main+0x65018`. The consumer uses 49 multipart headers with 31-byte keys to
reclassify that page into the 80-byte bin.

The controlled outer value is a PHP reference whose inner pointer is the
detached donor at `main+0x6a098`. The donor contains a complete fake
HashTable:

- `arData = donor + 0x40`
- `nNumUsed = nNumOfElements = 1`
- `pDestructor = HTTP-derived libc!system`
- `donor + 0x40 = "id>/out/p\0"`

Destruction calls `system` with that fixed string and writes the proof into a
temporary Docker volume owned by `www-data`.

## Fresh-ASLR HTTP-only results

| run | HTTP main | HTTP libphp | HTTP-derived system | A1 / B1 / terminal | proof |
| --- | --- | --- | --- | --- | --- |
| `http-rce-alt-attempt1` | `0x76df8e800000` | `0x76df97f1f000` | `0x76df9b9cd480` | 500 / 200 / 200 | uid/gid 33 |
| `http-rce-alt-attempt2` | `0x729ef1c00000` | `0x729efb31c000` | `0x729efedca480` | 500 / 200 / 200 | uid/gid 33 |
| `http-rce-alt-attempt3` | `0x77462c200000` | `0x7746359dd000` | `0x77463948b480` | 500 / 200 / 200 | uid/gid 33 |
| `http-rce-alt-postcleanup` | `0x70f2af600000` | `0x70f2b8cf8000` | `0x70f2bc7a6480` | 500 / 200 / 200 | uid/gid 33 |

In every run, `worker_before`, `worker_after_b1`, and
`worker_after_terminal` are identical. Each target inspection records
`PortBindings={}`, `Privileged=false`, no host PID namespace, and no added
capabilities.

## Reproduction

From this directory inside WSL/Linux:

```bash
./run-http-only.sh LABEL
```

The runner verifies both immutable image IDs, creates only an internal Docker
network, computes addresses from the HTTP leak, checks the fixed proof from
the host side, and removes the target, network, and proof volume on exit.

Raw calibration traces are deliberately omitted from this publication set.
They are not read by the final runner.
