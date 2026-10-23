# Release validation

Validation was performed on 2026-10-23 in WSL with the published
`run-local-docker-lab.sh`, a local Unix Docker endpoint, a new internal network
per run, and no published ports. The final three-profile, fixed non-privileged
`all` run ID was `20261023T073209Z-2879`.

| Exact profile | Runner exit | Proof |
|---|---:|---|
| `php-8.3.35-apache-amd64-r0-spray` | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| `php-8.4.26-apache-amd64-fixed-carrier` | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| `php-8.5.11-apache-amd64-r0-spray` | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |

Each run exercised the complete release path: pinned-image verification, live
container/network/port/volume checks, `apache2handler` runtime observation,
single-prefork verification, live `libphp.so` extraction and ELF verification,
short-lived manifest creation, isolated attacker execution, proof check,
artifact checksums, and cleanup. Helper and attacker containers ran as fixed
non-privileged UID/GID `65532:65532`; the runner inspected that setting before
start. A post-run label/name query found no remaining lab containers, internal
networks, or proof volumes.

Static validation completed with:

```text
bash -n: PASS
py_compile: PASS
unittest: 28 tests run; 25 passed, 3 skipped
```

The three skipped tests require optional reference binaries/source trees that
are intentionally not bundled. Their equivalent live ELF and payload paths
were exercised by the three successful Docker integration runs above.
