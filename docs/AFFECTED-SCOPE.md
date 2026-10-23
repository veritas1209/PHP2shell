# Version scope: CNA matrix, EOL mitigations, and research evidence

There are three different version questions in this case: which releases the
PHP CNA formally enumerated in the CVE records, which end-of-life branches
received official source mitigations, and how far independent exploit research
traced the underlying attack paths. Those scopes are related, but they are not
interchangeable.

## 1. Formal PHP CNA stable-branch matrix

The PHP CNA records use product-level `defaultStatus: unaffected` and enumerate
four maintained stable branches. This is the formal CVE version matrix:

| Stable branch | Formally affected releases | First fixed release | Signed release fix |
|---|---|---|---|
| PHP 8.2 | 8.2.0–8.2.34 | 8.2.35 | [`01a40e89`](https://github.com/php/php-src/commit/01a40e89fbfc499936e3b05888d8f00bfde886df) |
| PHP 8.3 | 8.3.0–8.3.35 | 8.3.36 | [`3c832b52`](https://github.com/php/php-src/commit/3c832b523ee13b1a010177d2ff84aea18be0015e) |
| PHP 8.4 | 8.4.0–8.4.26 | 8.4.27 | [`506e87fa`](https://github.com/php/php-src/commit/506e87fa7dcdd306975e5b8f8265ee03527aacbf) |
| PHP 8.5 | 8.5.0–8.5.11 | 8.5.12 | [`31c0ea7d`](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065) |

Primary records:

- [CVE-2026-109618 CNA JSON](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/109xxx/CVE-2026-109618.json) and [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 CNA JSON](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/109xxx/CVE-2026-109619.json) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

The CNA matrix is an administrative statement about the listed products and
supported release lines. Its `defaultStatus` must not be read as experimental
proof that every omitted historical implementation is technically immune.

## 2. Official source mitigations for EOL branches

PHP 8.1, 8.0, and 7.4 were already end of life and received no new point
release. The [PHP security announcement](https://www.php.net/archive/2026.php#2026-10-21-1)
nevertheless supplies signed **minimal source mitigations** for vendors and
users maintaining those branches:

| EOL branch | Last point release | Minimal source mitigation |
|---|---|---|
| PHP 8.1 | 8.1.34 | [`1d7dec17`](https://github.com/php/php-src/commit/1d7dec178a094e6e75b229ce22754045f8c6070a) |
| PHP 8.0 | 8.0.30 | [`82f8f31b`](https://github.com/php/php-src/commit/82f8f31b16a035c1b67cc253e79f7cc288f4cc20) |
| PHP 7.4 | 7.4.33 | [`712e60f9`](https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2) |

These mitigations intentionally differ from the maintained-branch patch. They
fail closed on OOM and disable the upload-progress callback rather than
backporting the complete delayed-OOM and safe session lifecycle. Their
existence is strong evidence that the technical issue also matters on those
EOL lines, but it does not add them to the CNA matrix or establish a runnable
profile in this repository.

## 3. Research-confirmed lineage reaches PHP 5.4

The primary researcher write-ups describe a wider technical lineage than the
CNA stable-branch matrix:

- [Calif's php2shell analysis](https://calif.io/php2shell/) reports that the
  earliest affected path they found dates to PHP 5.4.0. It distinguishes
  multiple paths by PHP version and SAPI: the mod_php session upload-progress
  path reaches 5.4.0, while another partial-HashTable/OOM path applies from
  PHP 7.3.
- [Wiz's PHP2Shell analysis](https://www.wiz.io/blog/php2shell-php-rce) likewise
  reports that at least one issue/path affects releases back to PHP 5.4 and
  stresses that exploit portability changes with version, configuration, SAPI,
  and application behavior.

Accordingly, “PHP 8.2–8.5” is the **formal maintained-branch CNA matrix**, not
the complete research-confirmed history of the vulnerability family. A careful
technical statement is that researchers demonstrated applicable attack paths
across PHP 5.4.0 and later pre-fix code, with the usable primitive and required
environment varying by release and SAPI. This evidence does not prove that
both CVE conditions are reachable on every historical patch release or under
every configuration.

## 4. PHP 5.4–7.3 status

PHP 5.4 through 7.3 have neither an affected entry in the PHP CNA records nor a
corresponding official php-src backport branch in the PHP announcement. The
research reports are evidence of technical exposure, while the lack of CNA
enumeration or an upstream backport means these versions have no supported PHP
project fix path. Users must move to a maintained fixed release or obtain a
verified distribution/LTS-vendor backport.

PHP 8.6 was prerelease software at disclosure. The PHP announcement says the
fix was included in 8.6.0 RC4 and advises users of earlier 8.6 development
builds to update. It is tracked separately from the stable CVE matrix.

## 5. Scope of this repository's PoC

Runnable support here remains **exact-build support**. The four verified
profiles cover PHP 8.2.34, 8.3.35, 8.4.26, and 8.5.11 on fingerprinted Apache
images and runtimes. A proof on one image establishes the chain only for that
image, SAPI, configuration, and heap recipe; it must not be generalized to all
releases in the branch.

Conversely, the absence of a runnable profile is not an “unaffected” result.
For example, the current disclosure recipe did not port directly to the tested
PHP 8.1.34 and 7.2.34 images, even though the official EOL mitigations and the
research record show that the broader technical scope extends beyond the four
runnable profiles.
