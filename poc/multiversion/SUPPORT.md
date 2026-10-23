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
| PHP 8.2.34 Apache | Verified and runnable | Five fresh tail-variant pure-HTTP/OOM proofs, including one independent run; exact stock 128M/display-errors-Off runtime |
| PHP 8.3.35 Apache | Verified and runnable | Two independent ptrace-free proofs; adaptive leak and r0 `0x74180` |
| PHP 8.4.26 Apache | Verified and runnable | Four documented proofs; fixed carrier `0x690d8` |
| PHP 8.5.11 Apache | Verified and runnable | Two independent ptrace-free proofs; r0 `0x73180`, one 19-byte pre-session field, 127 large values |
| PHP 8.1.34 Apache | Unsupported in this framework; separate locally calibrated RCE lab | The adaptive disclosure returned no raw leak and the older session-cookie lifecycle clears that state. The separate lab reaches `zif_passthru` after local `/proc` supplies libphp and heap bases. |
| PHP 7.2.34 Apache | Unsupported; bounded stale-state result, no RCE profile | On exact image `php@sha256:4dc0f0115acf8c2f0df69295ae822e49f5ad5fe849725847f15aa0e5802b55f8`, pre-RINIT OOM left a stale `zend_reference` at chunk `+0x6a018` in 8/8 fresh containers. Refcount 2 only fell to 1, tested inputs did not reclaim the 24-byte object, and no destructor or proof occurred. |

The unsupported rows mean only that this exact PoC recipe is not ported. They
must not be interpreted as “not vulnerable” or as contradicting the published
5.4+ research range. A safe port would need the path appropriate to that PHP
version/SAPI, a locally validated address-disclosure primitive, and a new
exact-build profile.

The PHP 7.2 bounded result is documented in
[`PHP-7.2-STALE-STATE.md`](../../docs/PHP-7.2-STALE-STATE.md). PHP 7.2's source
allocates a key before incrementing `nNumUsed`, so the PHP 7.3+ raw-key
partial-`Bucket` producer is not portable to this build.

The [legacy calibrated labs](../legacy-calibrated-rce/) deliberately use a
different support class. PHP 7.3.33, 7.4.33, 8.0.30, and 8.1.34 have repeated
terminal UID proofs there, but a local root reads process memory to supply ASLR addresses.
They therefore do not qualify for this harness's standalone HTTP allow-list.

The separate [legacy scope probe](../legacy-scope-probe/) confirmed the
default-enabled pre-script upload-progress surface on one exact Apache build
from every PHP minor branch between 5.4 and 8.1. Those results are recorded in
[the legacy runtime matrix](../../docs/LEGACY-RUNTIME-MATRIX.md). They are not
runnable RCE profiles and are deliberately excluded from this allow-list.

## Patched controls

The corresponding request recipes were also run locally against exact fixed
images. These controls are evidence records, not runnable exploit profiles:

| Fixed build | Image digest | Observed result |
|---|---|---|
| PHP 8.2.35 Apache | `php@sha256:fa8966fbaaa06981e549e7a33eb8a68f4cf677d6a82e1d6350adc5d85fe8f740` | B1 found no heap pointers in 3/3 fresh runs; no proof |
| PHP 8.3.36 Apache | `php@sha256:756c2884677bedea30afaa95811b42cd3ff251203291c5820c1ad209e86c9fb4` | information leak failed; no proof |
| PHP 8.4.27 Apache | `php@sha256:e6bad969f0b673ce9121c88dabb53488ab1ca139d8ebfac1d1b1ab63f245f725` | stage 1 failed; no proof |
| PHP 8.5.12 Apache | `php@sha256:e25ab14ef2cfec3bab9dd66c6cf871691146f428fbd72241b1a2c38fcacf92f5` | information leak failed; no proof |

No fixed image is marked `verified`, included in the runner allow-list, or
expected to execute the proof command.
