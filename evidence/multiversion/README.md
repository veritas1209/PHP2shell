# Multi-version release evidence

These are sanitized records from the final WSL Docker runs
`20261023T073209Z-2879` and `20261023T083245Z-3369` on 2026-10-23. The latter
used the runner's allow-listed PHP 8.2 selector and no command-line arguments.
The complete private run artifacts were checked with their generated
`SHA256SUMS.txt` files and then excluded because Docker inspect data contains
host paths. The published runner's source and profiles are independently
hashed in `release-file-sha256.txt`.

| Exact profile | Exit | Proof |
|---|---:|---|
| PHP 8.2.34 Apache | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| PHP 8.3.35 Apache | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| PHP 8.4.26 Apache | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| PHP 8.5.11 Apache | 0 | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |

Saved inspect records confirmed a fresh Docker internal network with no
published ports for every profile. Helper and attacker containers ran as
`65532:65532`. After the run, no labelled lab containers, networks, or proof
volumes remained.

`php-8.2.34-release-run.txt` records the sanitized exact image and `libphp`
identity, live stock `php.ini-production` runtime, retry outcome, fixed proof,
and exact A1 request-body hash. The PHP 8.2.34 profile's tail variant produced
proofs in 5/5 fresh runs. Applying the same recipe to the exact PHP 8.2.35
fixed build stopped at B1 with no heap pointers and no proof in 3/3 fresh runs.

The fixed-build identities and their bounded negative results are recorded in
`patched-controls.json`. That file is deliberately non-runnable and contains
no exploit recipe. A failed current-chain control does not by itself establish
that every configuration of the fixed build is safe; patch status should be
determined from the official PHP advisory and vendor update.
