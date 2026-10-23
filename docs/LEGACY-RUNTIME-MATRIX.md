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

Separate later experiments did reach locally calibrated terminal RCE on exact
PHP 7.3.33, 7.4.33, 8.0.30, and 8.1.34 images. Those results are documented in
[`LEGACY-RCE-VALIDATION.md`](LEGACY-RCE-VALIDATION.md) and do not change what
this benign matrix itself establishes.

PHP 7.2.34 also received a separate bounded investigation. It reproduced a
pre-RINIT OOM dangling `zend_reference` across requests in 8/8 fresh
containers at Zend MM chunk `+0x6a018`, but refcount 2 fell only to 1 and the
tested HTTP inputs did not reclaim the 24-byte reference. No destructor or
command proof occurred. See
[`PHP-7.2-STALE-STATE.md`](PHP-7.2-STALE-STATE.md).

## Why Set-Cookie stops on legacy builds, and the PHP 8.1 exception

The public PHP 8.3–8.5 chains and this repository's PHP 8.2 port obtain their
first address disclosure by making stale Session ID storage reach
`Set-Cookie`. PHP 8.1.34 and PHP 7.2.34 were tested directly with that recipe:
neither returned a usable disclosure. Their older `php_session_reset_id()`
logic clears `PS(send_cookie)` unconditionally, while the newer path used by
the public chain returns early on cookie-send failure and preserves it.
Changing symbol offsets or filler counts cannot replace that missing consumer.

PHP 8.1.34 was later ported with a different consumer. A FILE_START OOM leaves
`PS(id)` before ordinary session initialization, and the next request exposes a
profiled 1.75 MiB stale value through trans-SID URL rewriting. That response
supplies the Zend MM main chunk and `libphp` base without process-memory
access; a second OOM producer and reclaim request then create the fixed proof
in 3/3 fresh runs. See
[`PHP-8.1-HTTP-RCE-VALIDATION.md`](PHP-8.1-HTTP-RCE-VALIDATION.md). The PHP 7.2
blockers below remain unresolved.

The PHP 7.2 bounded investigation found a different pre-RINIT OOM producer and
confirmed that the next request consumes stale session state. It still stops
before a terminal primitive: `zval_ptr_dtor()` changes the stale reference's
refcount from 2 to 1 without dispatching a destructor, and tested inputs do not
reclaim its 24-byte allocation. Source inspection also shows that PHP 7.2
allocates the key before incrementing `nNumUsed`; the partial-`Bucket` producer
used on PHP 7.3+ is therefore absent.

Porting a standalone HTTP chain still crosses ABI families:

- The locally calibrated PHP 8.0 raw-key lab and historical PHP 8.1 8 MiB
  stale-session lab prove their terminal primitives but do not supply
  addresses through HTTP. The separate PHP 8.1 128 MiB trans-SID profile does.
- PHP 7 needs version-aware type flags, reference sizes, and HashTable
  semantics. The raw-key partial-`Bucket` geometry was validated on exact PHP
  7.3.33 and 7.4.33 images. PHP 7.2 has a confirmed stale-state primitive but
  remains unverified for end-to-end RCE.
- PHP 5 uses Zend Engine 2 zvals, pointer-based HashTables, a different
  allocator, and a different internal-function ABI. It requires a separate
  payload encoder and exploit strategy.

The Calif and Wiz teams report successful paths reaching PHP 5.4 but did not
publish those legacy full-chain implementations. The public full-core RCE
implementations reviewed for this repository are centered on PHP 8.3–8.5.
The benign probe alone adds no build to an RCE allow-list. The four successful
legacy labs required their own OOM/stale-session path, heap geometry, terminal
payload and local `/proc` address calibration. PHP 5.4–7.2 remain unverified
for end-to-end RCE in this repository; within that range, PHP 7.2 has the
stronger stale-state result while PHP 5.4–7.1 remain benign-surface-only.

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
- **This repository's standalone HTTP RCE profiles:** exact PHP 8.1.34,
  8.2.34, 8.3.35, 8.4.26, and 8.5.11 Apache images.
- **This repository's locally calibrated RCE labs:** exact PHP 7.3.33,
  7.4.33, 8.0.30, and 8.1.34 Apache images; addresses supplied from local
  `/proc`, with no remote ASLR-bypass claim.
- **This repository's PHP 7.2 bounded result:** cross-request stale
  `zend_reference` confirmed 8/8, with destructor and command proof absent.
- **This legacy experiment:** the pre-script upload-progress surface on ten
  exact PHP 5.4–8.1 Apache images, without an RCE claim.
