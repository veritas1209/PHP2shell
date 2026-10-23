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

## Why the current RCE profile stops on legacy builds

The public PHP 8.3–8.5 chains and this repository's PHP 8.2 port obtain their
first address disclosure by making stale Session ID storage reach
`Set-Cookie`. PHP 8.1.34 and PHP 7.2.34 were tested directly with that recipe:
neither returned a usable disclosure. Their older `php_session_reset_id()`
logic clears `PS(send_cookie)` unconditionally, while the newer path used by
the public chain returns early on cookie-send failure and preserves it.
Changing symbol offsets or filler counts cannot replace that missing consumer.

The remaining work also crosses ABI families:

- PHP 8.0/8.1 can reuse much of the PHP 8 fake-object layout after a new
  disclosure and fresh heap calibration are found.
- PHP 7 needs version-aware type flags, reference sizes, and HashTable
  semantics. For example, the measured PHP 7.2 `IS_ARRAY_EX` is `0x1407` and
  its `zend_reference` is 24 bytes, versus `0x307` and 32 bytes on PHP 8.
- PHP 5 uses Zend Engine 2 zvals, pointer-based HashTables, a different
  allocator, and a different internal-function ABI. It requires a separate
  payload encoder and exploit strategy.

The Calif and Wiz teams report successful paths reaching PHP 5.4 but did not
publish those legacy full-chain implementations. The public full-core RCE
implementations reviewed for this repository are centered on PHP 8.3–8.5.
Accordingly, no legacy build is added to the RCE allow-list on the strength of
this surface probe.

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
- **This repository's verified RCE profiles:** four exact PHP 8.2–8.5 Apache
  images only.
- **This legacy experiment:** the pre-script upload-progress surface on ten
  exact PHP 5.4–8.1 Apache images, without an RCE claim.

