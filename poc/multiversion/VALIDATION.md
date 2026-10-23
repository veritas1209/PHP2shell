# Release validation

Validation was performed on 2026-10-23 in WSL with the published
`run-local-docker-lab.sh`, a local Unix Docker endpoint, a new internal network
per run, and no published ports. The fixed non-privileged validation run for
PHP 8.3.35, 8.4.26, and 8.5.11 had ID `20261023T073209Z-2879`. After adding
PHP 8.2.34, its final release-path run ID was `20261023T083245Z-3369`.
PHP 8.1.34's final `zif_system` trans-SID profile passed the packaged runner on
three fresh targets as runs `20261023T163513Z-200322`,
`20261023T163537Z-203897`, and `20261023T163602Z-207516`.
PHP 8.0.30's final HTTP-only chain passed on three fresh-ASLR targets recorded
as `b2-root-fill64-7d960-1`, `b2-root-fill64-7d960-2`, and
`b2-root-fill64-7d960-3`. After integration, packaged-runner regression
`20261023T180015Z-636870` also exited 0 with the same proof. It is recorded
separately and does not increase the profile's verification count of three.

| Exact profile | Runner exit | Proof |
|---|---:|---|
| `php-8.0.30-apache-amd64-trans-sid` | 0 in 3/3 final-chain runs; packaged regression 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| `php-8.1.34-apache-amd64-trans-sid` | 0 in 3/3 final release runs | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| `php-8.2.34-apache-amd64-pure-http-oom` | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| `php-8.3.35-apache-amd64-r0-spray` | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| `php-8.4.26-apache-amd64-fixed-carrier` | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| `php-8.5.11-apache-amd64-r0-spray` | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |

The recorded packaged release-runner runs exercised the complete release path:
pinned-image verification, live container/network/port/volume checks,
`apache2handler` runtime observation, single-prefork verification, live
`libphp.so` extraction and ELF verification, short-lived manifest creation,
isolated attacker execution, proof check, artifact checksums, and cleanup.
Helper and attacker containers ran as fixed non-privileged UID/GID
`65532:65532`; the runner inspected that setting before start. A post-run name
query found no remaining `p2s-*` containers, networks, or proof volumes created
by the release runner.

The PHP 8.2.34 tail recipe also passed the calibration matrix in 5/5 fresh
runs, including an independently executed run. The same recipe against exact
PHP 8.2.35 reached no heap pointers at B1 and produced no proof in 3/3 fresh
controls. The release-path run additionally checked the immutable image ID,
live `libphp` SHA-256/build ID/symbols, and stock `php.ini-production` values
(`memory_limit=128M`, `display_errors=Off`) before sending the four requests.

The PHP 8.1.34 chain also sent four requests. Its three B1 responses each
contained an exact `0x1c0000`-byte trans-SID value. The parser recovered three
different Zend MM main chunks and `libphp` bases, with 623 occurrences of the
exact-build `zval_ptr_dtor` candidate in every run and no second candidate
meeting the profiled 100-hit threshold. A2 streamed 167,775,191 body bytes
before the expected OOM response; B2 then called the exact-build `zif_system`
offset with the fixed proof command. All five trans-SID runtime prerequisites
matched exactly; every artifact checksum manifest verified, and cleanup left
no lab container, network, or proof volume. These runs did not read target
`/proc/<pid>/maps` or `/proc/<pid>/mem` and used neither GDB nor ptrace. Exact
addresses and lifecycle details are in
[`PHP-8.1-HTTP-RCE-VALIDATION.md`](../../docs/PHP-8.1-HTTP-RCE-VALIDATION.md).

The PHP 8.0.30 chain also sent four requests at a profiled 108 MiB memory
limit. A1 returned 500 and left the raw Session ID at main chunk `+0x126260`.
B1 returned 200 with an exact 4 MiB trans-SID leak; all three leaks recovered
different ASLR bases and contained 2,117 hits for the exact-build
`zval_ptr_dtor` candidate. A2 returned 500 after the streamed 160 MiB recipe
with 64 fillers left a stale reference at `+0x7d960`. B2 used a one-byte SID,
400 controlled 4 KiB-class values, and a fake array at `+0x7d800`. It executed
`id>/out/p` before the worker closed the connection without a normal HTTP
status. Each fresh proof file contained the expected `www-data` identity.
The success decision therefore comes from the proof volume, not a B2 response.
The exact fingerprint, addresses, and request geometry are in
[`PHP-8.0-HTTP-RCE-VALIDATION.md`](../../docs/PHP-8.0-HTTP-RCE-VALIDATION.md).

For PHP 8.1, the affected Apache worker terminated with SIGSEGV after the proof
write and Apache recorded `AH00052`. Its fourth POST therefore has no normal
access-log entry. PHP 8.0 likewise closed B2 only after the proof write and
returned no normal status. These worker crashes are part of the observed
availability impact.

Three earlier 128 MiB HTTP-only calibration runs terminated at `zif_passthru`.
They remain development history and are excluded from the final profile's
`zif_system` 3/3 proof count and published address set.

Static validation completed with:

```text
bash -n: PASS
py_compile: PASS
unittest: 55 tests run; 52 passed, 3 skipped
```

The three skipped tests require optional reference binaries/source trees that
are intentionally not bundled. Their equivalent live ELF and payload paths
were exercised by the successful Docker integration runs above.
