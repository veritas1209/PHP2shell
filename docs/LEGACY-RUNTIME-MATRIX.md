# PHP 5.4–8.1 legacy runtime matrix

Date: 2026-10-23 (Asia/Seoul)

This matrix separates a historical attack surface from a verified exploit.
The PHP CNA formally enumerates maintained 8.2–8.5 branches, while the
original researchers traced applicable exploitation paths back to PHP 5.4.0.
PHP also published minimal source mitigations for the EOL 7.4, 8.0, and 8.1
branches.

## Local result

One final Apache build from every minor branch between 5.4 and 8.1 was run in
the WSL Docker lab. A fixed 1 MiB upload was paused after its first 64 KiB so
the session file could be inspected while request parsing was still in
progress. All ten builds created the `upload_progress_bounded` value before
`index.php` responded, had the setting enabled by default, reached the script
after the upload resumed, and removed the progress value on normal completion.

| Exact build | Image source | Enabled by default | Pre-script record | Cleanup and script |
|---|---|---:|---:|---:|
| PHP 5.4.45 Apache | archived eugenesia open-source image | yes | confirmed | confirmed |
| PHP 5.5.38 Apache | historical Docker Official Image mirror | yes | confirmed | confirmed |
| PHP 5.6.40 Apache | historical Docker Official Image mirror | yes | confirmed | confirmed |
| PHP 7.0.33 Apache | historical Docker Official Image mirror | yes | confirmed | confirmed |
| PHP 7.1.33 Apache | historical Docker Official Image mirror | yes | confirmed | confirmed |
| PHP 7.2.34 Apache | historical Docker Official Image mirror | yes | confirmed | confirmed |
| PHP 7.3.33 Apache | historical Docker Official Image mirror | yes | confirmed | confirmed |
| PHP 7.4.33 Apache | historical Docker Official Image mirror | yes | confirmed | confirmed |
| PHP 8.0.30 Apache | historical Docker Official Image mirror | yes | confirmed | confirmed |
| PHP 8.1.34 Apache | historical Docker Official Image mirror | yes | confirmed | confirmed |

Every run used a Docker network created with `--internal`; the containers had
no published host ports. The runner and image identities are in
[`poc/legacy-scope-probe`](../poc/legacy-scope-probe/), and the compact local
record is [`evidence/legacy-runtime-matrix.txt`](../evidence/legacy-runtime-matrix.txt).

## What this establishes

The experiment confirms one prerequisite surface behind the researchers'
lower bound: all tested 5.4–8.1 exact builds have the default-enabled RFC1867
callback and can update Session state before application code runs. PHP 5.4.0
was the first release with this feature; PHP 5.3 lacks this callback.

This observation alone does not demonstrate either CVE end to end. A complete
proof would also need a useful interruption/OOM producer, stale state that
survives request-heap teardown, a later consumer, a memory disclosure, and a
controlled terminal primitive on the exact build.

Separate later experiments completed HTTP-only fixed-command chains on all ten
exact PHP 5.4.45–8.1.34 builds in this matrix. The PHP 5.4–7.4 profiles and
fresh run counts are published in
[`../poc/legacy-http-rce/`](../poc/legacy-http-rce/); PHP 8.0 and PHP 8.1 are
part of the main multi-version runner. PHP 5.4–5.6 require an application
endpoint that reflects the affected POST value, including embedded bytes,
before the worker exits. These later results do not change what the benign
probe itself establishes.

PHP 7.2.34 also had an earlier bounded investigation that reproduced a
pre-RINIT OOM dangling `zend_reference` in 8/8 fresh containers but stopped
before a terminal primitive. It remains useful development evidence in
[`PHP-7.2-STALE-STATE.md`](PHP-7.2-STALE-STATE.md); the final PHP 7.2 HTTP-only
profile uses a different completed chain.

## Why one disclosure recipe does not generalize across legacy builds

The public PHP 8.3–8.5 chains and this repository's PHP 8.2 port obtain their
first address disclosure by making stale Session ID storage reach
`Set-Cookie`. Direct tests showed that this exact recipe did not produce a
usable disclosure on PHP 8.1.34 or PHP 7.2.34. Their older
`php_session_reset_id()` logic clears `PS(send_cookie)` unconditionally, while
the newer path used by the public chain returns early on cookie-send failure
and preserves it. Changing offsets or filler counts cannot replace a missing
consumer.

PHP 8.1.34 was later ported with a different consumer. A FILE_START OOM leaves
`PS(id)` before ordinary session initialization, and the next request exposes a
profiled 1.75 MiB stale value through trans-SID URL rewriting. That response
supplies the Zend MM main chunk and `libphp` base without process-memory
access; a second OOM producer and reclaim request then create the fixed proof
in 3/3 fresh runs. See
[`PHP-8.1-HTTP-RCE-VALIDATION.md`](PHP-8.1-HTTP-RCE-VALIDATION.md).

The earlier PHP 7.2 bounded route found a different pre-RINIT OOM producer and
confirmed that the next request consumes stale session state. That route still
stops before a terminal primitive: `zval_ptr_dtor()` changes the reference's
refcount from 2 to 1 without dispatching a destructor, and the tested inputs do
not reclaim its 24-byte allocation. The final PHP 7.2 profile therefore uses
the version-specific HTTP chain packaged under `poc/legacy-http-rce` rather
than presenting that failed route as completed.

The completed profiles cross several ABI families:

- The locally calibrated PHP 8.0 raw-key lab and historical PHP 8.1 8 MiB
  stale-session lab prove their terminal primitives but do not supply
  addresses through HTTP. The separate PHP 8.1 128 MiB trans-SID profile does.
- PHP 7 needs version-aware type flags, reference sizes, and HashTable
  semantics. Exact PHP 7.0.33–7.4.33 profiles have separate validated heap
  geometries and HTTP disclosure paths.
- PHP 5 uses Zend Engine 2 zvals, pointer-based HashTables, a different
  allocator, and a different internal-function ABI. The published 5.4–5.6
  chain uses an mbstring symbol pointer recovered through an application
  reflection response.

The Calif and Wiz teams report successful paths reaching PHP 5.4. The public
full-core implementations initially reviewed for this repository centered on
PHP 8.3–8.5; the legacy profiles here are additional exact-build technical
research. A benign callback probe alone still adds no build to an RCE
allow-list. Only the separate end-to-end runners, fixed proof, fingerprints and
fresh-run records support the exact builds listed above. These results do not
expand the PHP CNA's formal 8.2–8.5 CVE range.

## Source and image caveat for PHP 5.4

Docker Hub retains the original `php:5.4.45-apache` only in the obsolete
schema-v1 format, which Docker 29 rejects. The runtime check therefore uses
the digest-pinned `eugenesia/php:5.4.45-apache` image, whose Dockerfile is
derived from the historical official image and published at
[`eugenesia/docker-library-php`](https://github.com/eugenesia/docker-library-php).
It is evidence for that exact third-party build and is not represented as an
official PHP or Docker build.

## Interpretation

- **Formal PHP CNA matrix:** PHP 8.2–8.5, with the fixed point releases listed
  in [`AFFECTED-SCOPE.md`](AFFECTED-SCOPE.md).
- **Official EOL source mitigations:** PHP 7.4, 8.0, and 8.1.
- **Research-confirmed technical history:** version- and SAPI-dependent paths
  reach PHP 5.4.0.
- **This repository's standalone HTTP RCE profiles:** exact PHP 5.4.45,
  5.5.38, 5.6.40, 7.0.33–7.4.33, and 8.0.30–8.5.11 Apache images. PHP 5.x
  requires the documented application reflection sink.
- **This repository's historical locally calibrated RCE labs:** exact PHP
  7.3.33, 7.4.33, 8.0.30, and 8.1.34 Apache images; retained as independent
  evidence and not used by the HTTP-only profiles.
- **This repository's early PHP 7.2 bounded route:** cross-request stale
  `zend_reference` confirmed 8/8, with destructor and command proof absent;
  later superseded for runnable support by a different 3/3 HTTP-only chain.
- **This legacy experiment:** the pre-script upload-progress surface on ten
  exact PHP 5.4–8.1 Apache images, without an RCE claim.
