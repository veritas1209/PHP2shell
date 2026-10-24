# PHP 7.2.34 HTTP disclosure-to-RCE verification

## Result

The exact PHP 7.2.34 Apache image below reproduced the complete chain in three
fresh containers with independent ASLR layouts.  Every final run obtained the
main Zend MM chunk and `libphp7.so` base from the B1 HTTP response, calculated
`zif_system`, and executed only the fixed proof command `id>/out/p`.

The final runs did not read `/proc`, attach a debugger, or use a target-side
address oracle.  GDB was used earlier to calibrate fixed offsets for this exact
binary and configuration; those traces are not inputs to the final runner.

## Exact target

- Image: `php@sha256:4dc0f0115acf8c2f0df69295ae822e49f5ad5fe849725847f15aa0e5802b55f8`
- Image ID: `sha256:c61d277263e19d2ce30a6bae41115c811eb0f9274a601a5e3ee621e54c8a74f7`
- PHP: 7.2.34, Apache handler, NTS, amd64
- `libphp7.so` SHA-256: `aff83b482039f672ef675ceaa82dde09521a72a6ce569b4dcf5e1f54f5b7503c`
- GNU build ID: `9df671d4682d9e87e1bd46163c207551ac3a72cc`
- `zif_system`: `libphp_base + 0x3624e0`
- `_zval_ptr_dtor`: `libphp_base + 0x441b20`

The runner creates an internal Docker network, publishes no host ports, starts
one prefork worker, and mounts a private proof volume at `/out`.

## HTTP chain

1. A health request records the disclosure worker and checks the terminal
   virtual-host configuration.
2. A1 leaves a stale process-global session ID.  Its profiled file-name length
   is 233472 bytes; the stale string is at `main + 0x10d820`.
3. B1 replaces that string header with the PHP 7.2 `zend_string` type value
   `0x6` and returns a 4 MiB URL-rewriter disclosure.  The parser obtains the
   main chunk from leak offset `0xf27c8` and independently identifies
   `libphp7.so` from 2190 `_zval_ptr_dtor` candidates.
4. A second health request is the disclosure child's fourth connection.
   `MaxConnectionsPerChild 4` makes Apache retire that child normally.
5. The same Apache parent forks a clean terminal child.  This removes the
   retained Zend MM chunks left by the large disclosure while preserving the
   exact inherited DSO layout.  In this pinned environment the new child's
   main Zend MM mapping also repeats the disclosed address; all three final
   runs confirm that precondition through successful dispatch.
6. Terminal A creates the stale reference with a 12 MiB field under the 12 MiB
   virtual-host memory limit.
7. Terminal B uses the fixed 33-cookie and 638-value geometry to preserve the
   reference through the allocation failure.
8. Terminal C places the fake hash table at `main + 0x79038`, its carrier page
   at `main + 0x79000`, and the donor object at `main + 0x7d098`.  Its
   destructor is the `zif_system` address parsed from B1, and its execute data
   contains only `id>/out/p`.

The expected HTTP status sequence is `500, 200, 500, 500, EOF`.  EOF is
expected because the terminal child crashes after the proof process is forked.

## Final fresh-ASLR evidence

| Run | Main chunk from B1 | `libphp7.so` from B1 | B1 response | Leak | Dtor hits | Proof |
|---|---:|---:|---:|---:|---:|---|
| `full-sealed-1` | `0x7ed880000000` | `0x7ed8809a4000` | 5978081 | 4194304 | 2190 | `uid=33(www-data)` |
| `full-sealed-2` | `0x7f9305400000` | `0x7f9305de2000` | 6034499 | 4194304 | 2190 | `uid=33(www-data)` |
| `full-sealed-3` | `0x7cb988000000` | `0x7cb988822000` | 6034345 | 4194304 | 2190 | `uid=33(www-data)` |

All three proof files have SHA-256
`6d99797c5e70f1676baffdaab9979d52aef4d97cb7c457054182abe6e4075c1e`.
The summary hashes are:

- `full-sealed-1`: `f36e6a860031c637595f96624011e03583ae415af208f6e89e8e39d512f20296`
- `full-sealed-2`: `a4aa5db4ab5ab110370a83081d2d6ff56d7933cdb263c2c7f7e6c18809182dcd`
- `full-sealed-3`: `4632c1777b7a393f77d72f0985353513fdb2c985ef447fb2eb12e40932482f87`

`EVIDENCE.sha256` also fixes the runtime, client, and target-log hashes.  Each
runtime record states `network_internal=true`, `port_bindings={}`,
`address_source=http-b1-only`, `proc_or_debugger_used=false`, and
`fixed_command=id>/out/p`.

## Reproduction

From this directory in WSL/Linux:

```sh
./run-http-only.sh final-recheck
cat results/full-final-recheck/proof.txt
```

The runner rejects a different image ID, PHP version, `libphp7.so` hash,
non-internal Docker network, or any published port.  It uses unique container,
network, and volume names derived from the label.

## Scope and limitation

This is an exact-build laboratory profile, not a portable PHP 7.2 exploit.
Allocator offsets, the Apache connection lifecycle, the binary symbol offsets,
and the repeated main-chunk mapping are all profile assumptions.  A different
build, module set, MPM, request order, memory limit, or Apache lifecycle needs
independent calibration.  The runner deliberately has no arbitrary command
option and cannot target a public address through its internal-network setup.
