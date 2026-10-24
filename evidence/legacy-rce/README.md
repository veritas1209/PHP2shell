# Legacy locally calibrated RCE evidence

These transcripts record fresh-container runs of the exact, digest-pinned
legacy labs in `poc/legacy-calibrated-rce/`. They retain the runtime identity,
Docker isolation checks, address-calibration source, independently copied
`www-data` proof, and final result marker. Local artifact paths and full
container inspection JSON are intentionally omitted.

The legacy runners obtain ASLR-dependent addresses from the Docker host's
local `/proc/<worker>/maps` and, where required, `/proc/<worker>/mem`. The
transcripts therefore prove the terminal memory-corruption-to-command-execution
path on the listed exact builds. They do not prove a standalone remote exploit
or an HTTP-only ASLR bypass.

The only command permitted by the published runners is `id>/out/p`.

`php-7.2.34-stale-state.txt` is a negative-boundary record for an earlier route,
not RCE evidence. It records eight fresh-container observations of a dangling
session `zend_reference`, the reclaim and refcount blockers, and the final
absent-proof check for that route. A later, separate HTTP-only chain reached
the fixed proof in 3/3 fresh runs and is published under
[`poc/legacy-http-rce/php-7.2.34`](../../poc/legacy-http-rce/php-7.2.34/). The
later result does not change what this historical negative record establishes.

`release-file-sha256.txt` binds the published legacy runner source tree to this
evidence set. `SHA256SUMS.txt` covers every other file in this directory.
