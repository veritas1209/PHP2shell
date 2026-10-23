# Official affected scope and EOL backports

The PHP CNA records are the authority for the formal CVE version range. Their
product-level `defaultStatus` is `unaffected`, and they list four affected
stable branches rather than one unbounded “less than 8.2.35” range.

| Stable branch | Formally affected releases | First fixed release | Signed release fix |
|---|---|---|---|
| PHP 8.2 | 8.2.0–8.2.34 | 8.2.35 | [`01a40e89`](https://github.com/php/php-src/commit/01a40e89fbfc499936e3b05888d8f00bfde886df) |
| PHP 8.3 | 8.3.0–8.3.35 | 8.3.36 | [`3c832b52`](https://github.com/php/php-src/commit/3c832b523ee13b1a010177d2ff84aea18be0015e) |
| PHP 8.4 | 8.4.0–8.4.26 | 8.4.27 | [`506e87fa`](https://github.com/php/php-src/commit/506e87fa7dcdd306975e5b8f8265ee03527aacbf) |
| PHP 8.5 | 8.5.0–8.5.11 | 8.5.12 | [`31c0ea7d`](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065) |

The source records are
[`CVE-2026-109618.json`](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/109xxx/CVE-2026-109618.json)
and
[`CVE-2026-109619.json`](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/109xxx/CVE-2026-109619.json).
Both were assigned by PHP and agree with the two php-src security advisories.

PHP 8.1, 8.0, and 7.4 are end-of-life branches. They are outside that formal
CNA affected matrix and received no new point releases. Because of the
severity, the PHP project nevertheless published signed **minimal source
backports** for the same two CVEs:

| EOL branch | Last point release | Minimal source mitigation |
|---|---|---|
| PHP 8.1 | 8.1.34 | [`1d7dec17`](https://github.com/php/php-src/commit/1d7dec178a094e6e75b229ce22754045f8c6070a) |
| PHP 8.0 | 8.0.30 | [`82f8f31b`](https://github.com/php/php-src/commit/82f8f31b16a035c1b67cc253e79f7cc288f4cc20) |
| PHP 7.4 | 7.4.33 | [`712e60f9`](https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2) |

These minimal mitigations are intentionally different from the supported
branch patch. They fail closed on OOM and disable the upload-progress callback
in code instead of backporting the complete delayed-OOM and safe session
lifecycle. Their existence is strong evidence of a technical concern in those
EOL branches, but it is not a basis for claiming that this repository has a
working RCE profile for them.

PHP 7.3 and older have neither a corresponding official php-src mitigation
branch nor an affected entry in the PHP CNA records. The official material
does not prove that every older implementation is technically immune; it also
does not support labelling all older PHP versions as affected by these CVEs.

PHP 8.6 was prerelease software at disclosure. The PHP announcement says the
fix was included in 8.6.0 RC4 and advises users of earlier 8.6 development
builds to update. It is tracked separately from the stable CVE matrix.

Runnable support in this repository remains **exact-build support**. A proof
on one image establishes the chain only for the fingerprinted image, runtime,
and heap recipe recorded in that profile. It must not be generalized to every
patch release in the same branch without separate evidence.
