# Release validation

Validation was performed on 2026-10-23 in WSL with the published
`run-local-docker-lab.sh`, a local Unix Docker endpoint, a new internal network
per run, and no published ports. The fixed non-privileged validation run for
PHP 8.3.35, 8.4.26, and 8.5.11 had ID `20261023T073209Z-2879`. After adding
PHP 8.2.34, its final release-path run ID was `20261023T083245Z-3369`.

| Exact profile | Runner exit | Proof |
|---|---:|---|
| `php-8.2.34-apache-amd64-pure-http-oom` | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| `php-8.3.35-apache-amd64-r0-spray` | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| `php-8.4.26-apache-amd64-fixed-carrier` | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| `php-8.5.11-apache-amd64-r0-spray` | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |

Each run exercised the complete release path: pinned-image verification, live
container/network/port/volume checks, `apache2handler` runtime observation,
single-prefork verification, live `libphp.so` extraction and ELF verification,
short-lived manifest creation, isolated attacker execution, proof check,
artifact checksums, and cleanup. Helper and attacker containers ran as fixed
non-privileged UID/GID `65532:65532`; the runner inspected that setting before
start. A post-run name query found no remaining `p2s-*` containers, networks,
or proof volumes created by the release runner.

The PHP 8.2.34 tail recipe also passed the calibration matrix in 5/5 fresh
runs, including an independently executed run. The same recipe against exact
PHP 8.2.35 reached no heap pointers at B1 and produced no proof in 3/3 fresh
controls. The release-path run additionally checked the immutable image ID,
live `libphp` SHA-256/build ID/symbols, and stock `php.ini-production` values
(`memory_limit=128M`, `display_errors=Off`) before sending the four requests.

Static validation completed with:

```text
bash -n: PASS
py_compile: PASS
unittest: 34 tests run; 31 passed, 3 skipped
```

The three skipped tests require optional reference binaries/source trees that
are intentionally not bundled. Their equivalent live ELF and payload paths
were exercised by the successful Docker integration runs above.
