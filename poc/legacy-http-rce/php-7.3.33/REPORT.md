# PHP 7.3.33 HTTP-only local RCE port

## Scope and exact runtime

All tests used only local WSL Docker, fresh `--internal` networks, no published
ports, and the fixed proof command `id>/out/p`.

- Target image: `mirror.gcr.io/library/php@sha256:b9872cd287ef72bc17d45d713aa2742f3d3bcf2503fea2506fd93aa94995219f`
- Image ID: `sha256:35da9118b3c0980fbaf84a4d410653642c9d55fb2f6c40011cc78de303837d64`
- PHP / SAPI: PHP 7.3.33 / Apache 2 handler
- `libphp7.so` build ID: `cb5f3581bd8fa554ea126c1b1b58020cfa3e8ebc`
- `libphp7.so` SHA-256: `9801b6f2e7183c858c98bec90150ce7590f69e1827bb4976725211c7ea451109`
- `zif_system`: `libphp + 0x35f640`
- `zval_ptr_dtor`: `libphp + 0x440dc0`

## Disclosure stages

The PHP 8.0 A1/B1 multipart geometry ports unchanged to PHP 7.3.33 under the
108M request profile:

- A1 returns HTTP 500 on the same prefork worker.
- B1 returns HTTP 200 with the exact 4 MiB stale disclosure.
- `/12BBBBB` is present at the expected prefix.
- the destructor pointer repeats 2,117 times and yields the exact libphp base;
  the heap pointer yields the 2 MiB-aligned Zend-MM main chunk.

The original A2/B2 terminal chain was measured but not used in the final
port. A2 leaves `PS(http_session_vars)` at `main+0x6b030`; B2 observes a second
reference at `main+0x6b018`. A 4,071-byte spray begins at `main+0x6f018`, so
the stale page at `main+0x6b000` is not reclaimed. Filler counts 0, 16, 32,
48, and 64 do not change either offset.

## Raw-key zif_system terminal stage

The existing raw-key partial-Bucket primitive was changed to call
`libphp7.so!zif_system` instead of requiring a libc leak. The fake HashTable
uses `HT.arData=E` and `HT.pDestructor=zif_system`. The compact `E` overlay is:

- `E+0x10`: qword string length `9`
- `E+0x18`: `id>/out/p\0`
- `E+0x2c`: dword argument count `1`
- `E+0x50`: qword pointer to `E`
- `E+0x58`: dword `IS_STRING` (`6`)

`zend_hash_destroy` invokes the destructor with `rdi=E`. `zif_system` reads
the overlaid first argument and completes `pclose()` before its invalid
`return_value=1` causes the expected post-proof worker exit. The client
therefore normally reports EOF after a successful proof.

A direct process-calibrated check succeeded at the original 32M raw-key
geometry (`arData=main+0x61e00`). The combined chain needs two request
profiles on the same worker:

1. `/index.php` retains the 108M trans-SID profile for A1/B1.
2. `/raw.php` applies per-file 32M, 8M post, trans-SID-off settings for the
   raw-key primitive.

After A1/B1, the first safe raw-key control is a transition round. Its donor
is weak at `main+0x32a8` (`ff=5/64`). The next raw-key sequence consistently
uses `main+0x3f40` (`ff=56/64`). The exploit client itself performs its two
warm requests before the terminal trigger, so the final minimal sequence is:

1. HTTP A1/B1 disclosure of `main` and `libphp`.
2. One safe HTTP raw-key control request.
3. HTTP terminal trigger with `arData=main+0x3f40` and
   `zif_system=libphp+0x35f640`.

No `/proc` address is read in HTTP-only mode. Host process IDs are used only
to verify that all requests stayed on the single local prefork worker.

## Fresh-ASLR results

| Run | HTTP main | HTTP libphp | Proof |
| --- | --- | --- | --- |
| `http-zif-c1-1` | `0x7ca358400000` | `0x7ca3587e3000` | uid/gid 33 |
| `http-zif-c1-2` | `0x723229a00000` | `0x723229c42000` | uid/gid 33 |
| `http-zif-c1-3` | `0x7b4534a00000` | `0x7b4534d9e000` | uid/gid 33 |

Each run has `address_source=http-b1`, no `proc-calibration.txt`, an EOF
terminal response, and a fixed `uid=33(www-data)` proof.

## Reproduction

From this directory inside WSL/Linux:

```bash
./run-http-only.sh LABEL
```

The runner verifies immutable image IDs, creates a fresh internal network and
proof volume, exposes no host ports, derives terminal addresses only from B1,
checks `/out/p` from the host side, and removes the container, network, and
volume on exit.
