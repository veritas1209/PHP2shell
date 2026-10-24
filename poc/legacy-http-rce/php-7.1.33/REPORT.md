# PHP 7.1.33 HTTP-only local RCE port

## Scope and exact runtime

All requests targeted only a fresh WSL Docker `--internal` network. No host
ports were published. The only command in the terminal payload is
`id>/out/p`.

- image: `mirror.gcr.io/library/php@sha256:70eefcf4372b279101259e905996b7733a87688d0b48625af01b55947836bb1f`
- image ID: `sha256:b9858ffdd4d259fe208b6e5e4ae08f90c815dda98a7a8a45f3bf147485afaf4c`
- PHP / SAPI: PHP 7.1.33 / Apache 2 handler, NTS
- `libphp7.so` SHA-256: `7051e920742073c398b228429e893160cd50ed549b6807bd9fd4a4582c198aee`
- `libphp7.so` build ID: `bdf8cf769f9772afd3940463da61a7ae6ddcdf62`
- glibc 2.28 SHA-256: `dedb887a5c49294ecd850d86728a0744c0e7ea780be8de2d4fc89f6948386937`
- glibc build ID: `18b9a9a8c523e5cfe5b5d946d605d09242f09798`

## HTTP disclosure

The trans-SID A1/B1 geometry uses `filename_len=208880`. A1 leaves
`PS(id)=main+0xb0ee0` while `PS(mod_data)=NULL`. B1 forges an unpersistent
PHP 7.1 string (`type_info=0x6`) at that offset and returns exactly 4 MiB.

- `leak+0x14f108` is `main+0x40`.
- the pointer `libphp+0x3d7ce0` repeats 2,117 times.
- the exact loader layout was independently checked in three fresh processes:
  `libc=libphp+0x21ec000`.
- glibc `system` is `libc+0x449c0`, hence `libphp+0x22309c0`.

`analyze_b1_71.py` derives all terminal addresses from the HTTP body. The
final runner never reads `/proc` for an address.

## Terminal geometry

`/index.php` keeps the 108 MiB trans-SID disclosure profile. Apache applies a
12 MiB, trans-SID-off profile only to `/terminal.php`. Turning trans-SID off
there is required: otherwise the prior disclosure leaves URL-rewriter state
that crashes in `php_url_scanner_reset_var_impl()` before the terminal dtor.

After A1/B1, the 12 MiB producer leaves the session reference at
`main+0x65018`. The consumer uses no seed header, 49 multipart headers with
31-byte keys, and reclassifies that page as the 80-byte bin. Carrier order is
swapped so the stale slot contains:

```
gc.refcount = 1
gc.type_info = 0x0a
inner = main + 0x6a098
zval.type_info = 0x1407
```

The inner address is a separately controlled 96-byte donor rather than an
adjacent-slot partial HashTable. It contains the complete fake HashTable:

- `arData=donor+0x40`
- `nNumUsed=nNumOfElements=1`
- `pDestructor=libc!system`
- `donor+0x40="id>/out/p\0"`

This detached layout removes the fragile requirement that a second
zend_string land immediately after the stale reference. Development tracing
confirmed the `zend_array_destroy -> zend_hash_destroy -> libc system` path;
the final package omits those calibration traces and the saved runner does not
invoke them.

## Fresh-ASLR HTTP-only results

| run | HTTP main | HTTP libphp | HTTP-derived system | proof |
| --- | --- | --- | --- | --- |
| `http-rce-final-1` | `0x7dd30e800000` | `0x7dd30f410000` | `0x7dd3116409c0` | uid/gid 33 |
| `http-rce-final-2` | `0x79df78c00000` | `0x79df79751000` | `0x79df7b9819c0` | uid/gid 33 |
| `http-rce-final-3` | `0x7680a0200000` | `0x7680a0cb8000` | `0x7680a2ee89c0` | uid/gid 33 |

All three runs returned HTTP 500 for A1, HTTP 200 with the 4 MiB B1 leak,
HTTP 200 for the terminal consumer, and
`uid=33(www-data) gid=33(www-data) groups=33(www-data)` in `proof.txt`. The
recorded worker PID stayed identical across disclosure and terminal requests.

## Reproduction

From this directory inside WSL/Linux:

```bash
./run-http-only.sh LABEL
```

The runner verifies both immutable image IDs, exposes no ports, derives
addresses only from B1, checks the proof from the host side, and removes the
target, network, and proof volume on exit.
