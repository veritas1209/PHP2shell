# PHP 7.4.33 HTTP-only local RCE verification

## Result

The pinned PHP 7.4.33 Apache image completed the four-request chain in three
fresh containers with independent ASLR layouts. A1 returned HTTP 500, B1
returned a 4 MiB trans-SID disclosure, A2 returned HTTP 500, and the terminal
B2 request executed only the fixed `id>/out/p` proof command. Every proof was
written by uid/gid 33 (`www-data`).

The final runner obtains the Zend MM main chunk and `libphp7.so` base from the
B1 HTTP response. It does not use a debugger, ptrace, `LD_PRELOAD`, process
maps, or process memory.

## Exact runtime

- image: `mirror.gcr.io/library/php@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d`
- image ID: `sha256:20a3732f422b7b28dcf99e8597f093a8c135efca62ff0dc02a2d92d916369413`
- PHP / SAPI: PHP 7.4.33 / Apache 2 handler, NTS
- `libphp7.so` SHA-256: `5692da4ee4abb6f14b4257ca52cfdd08fc4aa9cf95fde0192445c070923a4bf0`
- `libphp7.so` build ID: `a8f9e89e11da8db14855af2dd3a0d966f8e72d86`
- `zif_system`: `libphp+0x335850`
- `zval_ptr_dtor`: `libphp+0x417d60`

The exact profile uses the 108 MiB trans-SID request geometry and stale
reference offset `main+0x7d980`. The runner pins both target and attacker image
IDs, creates a Docker-internal network, publishes no ports, and removes its
container, network, and proof volume after the run.

## Fresh-ASLR evidence

| Run | HTTP main chunk | HTTP `libphp` base | B1 leak | Proof |
|---|---:|---:|---:|---|
| `ref-7d980-1` | `0x7043b4600000` | `0x7043b4b4a000` | 4 MiB | uid/gid 33 |
| `ref-7d980-2` | `0x7c518e200000` | `0x7c518e6f9000` | 4 MiB | uid/gid 33 |
| `ref-7d980-3` | `0x72ba59800000` | `0x72ba59d06000` | 4 MiB | uid/gid 33 |

## Reproduction

From this directory in WSL/Linux:

```bash
./run-http-only.sh review-1
cat results/review-1.proof.txt
```

This is an exact-build laboratory profile. Different binaries, SAPI/MPM
settings, extensions, limits, or allocator history require independent
validation.
