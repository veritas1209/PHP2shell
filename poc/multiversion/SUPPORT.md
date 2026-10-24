# Exact-build support status

“Runnable” means the bundled profile has repeated local `uid` proofs and every
fingerprint required by the fail-closed runner. It is not a claim about every
build sharing the same PHP version.

This table describes **harness support**, not the vulnerability's complete
version range. The PHP CNA formally enumerates maintained PHP 8.2–8.5 release
lines; PHP separately published minimal source mitigations for EOL 7.4, 8.0,
and 8.1; Calif and Wiz report version/SAPI-specific attack paths reaching back
to PHP 5.4.0. PHP 5.4–7.3 are not enumerated in the CNA records and have no
official php-src backport branch. See
[Version scope](../../docs/AFFECTED-SCOPE.md) for the sources and distinctions.

| Branch/build | Status in this harness | Evidence-based reason |
|---|---|---|
| PHP 8.0.30 Apache | Verified and runnable | Three fresh HTTP-only proofs at 108M; 4 MiB trans-SID leak recovered main chunk and `libphp`, then stale reference `+0x7d960` reached the fixed `zif_system` proof without target process-memory access |
| PHP 8.1.34 Apache | Verified and runnable | Three fresh HTTP-only proofs; FILE_START/trans-SID leak recovered main chunk and `libphp`, then stale reference `+0x74160` reached fixed `zif_system` proof without target process-memory access |
| PHP 8.2.34 Apache | Verified and runnable | Five fresh tail-variant pure-HTTP/OOM proofs, including one independent run; exact stock 128M/display-errors-Off runtime |
| PHP 8.3.35 Apache | Verified and runnable | Two independent ptrace-free proofs; adaptive leak and r0 `0x74180` |
| PHP 8.4.26 Apache | Verified and runnable | Four documented proofs; fixed carrier `0x690d8` |
| PHP 8.5.11 Apache | Verified and runnable | Two independent ptrace-free proofs; r0 `0x73180`, one 19-byte pre-session field, 127 large values |
| PHP 7.2.34 Apache | Unsupported in this six-profile harness; separate legacy HTTP profile available | An earlier pre-RINIT route on the exact image left a stale `zend_reference` in 8/8 fresh containers but did not reclaim it or dispatch a destructor. A later version-specific chain, packaged separately under `poc/legacy-http-rce`, obtained its addresses from HTTP and produced 3/3 fresh fixed-command proofs. |

The unsupported PHP 7.2 row means only that the profile is not part of this
six-profile `poc/multiversion` allow-list. The earlier bounded route remains a
useful negative result for that specific producer/consumer sequence. The
separate [legacy HTTP-only profile](../legacy-http-rce/php-7.2.34/) uses a
different completed chain and is tied to its own exact image and runtime. This
harness classification must not be interpreted as “not vulnerable” or as
contradicting the separately verified exact-build result.

The earlier PHP 7.2 bounded result is documented in
[`PHP-7.2-STALE-STATE.md`](../../docs/PHP-7.2-STALE-STATE.md). PHP 7.2's source
allocates a key before incrementing `nNumUsed`, so the PHP 7.3+ raw-key
partial-`Bucket` producer is not portable to this build.

The [legacy calibrated labs](../legacy-calibrated-rce/) deliberately use a
different support class. PHP 7.3.33, 7.4.33, 8.0.30, and the historical 8 MiB
PHP 8.1.34 path have repeated terminal UID proofs there, but a local root reads
process memory to supply ASLR addresses. Those lab results do not qualify on
their own for this harness's standalone HTTP allow-list. PHP 8.0.30 and
8.1.34 now qualify through separate 108 MiB and 128 MiB trans-SID profiles,
each with 3/3 HTTP-only proofs; see the
[PHP 8.0 report](../../docs/PHP-8.0-HTTP-RCE-VALIDATION.md) and
[PHP 8.1 report](../../docs/PHP-8.1-HTTP-RCE-VALIDATION.md).

The separate [legacy scope probe](../legacy-scope-probe/) confirmed the
default-enabled pre-script upload-progress surface on one exact Apache build
from every PHP minor branch between 5.4 and 8.1. Those results are recorded in
[the legacy runtime matrix](../../docs/LEGACY-RUNTIME-MATRIX.md). They are not
runnable RCE profiles and are deliberately excluded from this allow-list.

## Patched controls

The corresponding request recipes were also run locally against exact fixed
images. These controls are evidence records, not runnable exploit profiles:

PHP 8.0 and 8.1 received EOL source mitigations rather than new official point
release images. This repository does not claim bundled patched-image controls
for those profiles; the official mitigations are linked in the version-scope
and exact-version validation documents.

| Fixed build | Image digest | Observed result |
|---|---|---|
| PHP 8.2.35 Apache | `php@sha256:fa8966fbaaa06981e549e7a33eb8a68f4cf677d6a82e1d6350adc5d85fe8f740` | B1 found no heap pointers in 3/3 fresh runs; no proof |
| PHP 8.3.36 Apache | `php@sha256:756c2884677bedea30afaa95811b42cd3ff251203291c5820c1ad209e86c9fb4` | information leak failed; no proof |
| PHP 8.4.27 Apache | `php@sha256:e6bad969f0b673ce9121c88dabb53488ab1ca139d8ebfac1d1b1ab63f245f725` | stage 1 failed; no proof |
| PHP 8.5.12 Apache | `php@sha256:e25ab14ef2cfec3bab9dd66c6cf871691146f428fbd72241b1a2c38fcacf92f5` | information leak failed; no proof |

No fixed image is marked `verified`, included in the runner allow-list, or
expected to execute the proof command.
