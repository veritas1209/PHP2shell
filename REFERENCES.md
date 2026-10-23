# References and source identity

## Official PHP sources

- [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [CVE-2026-109618 CNA JSON](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/109xxx/CVE-2026-109618.json)
- [CVE-2026-109619 CNA JSON](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/109xxx/CVE-2026-109619.json)
- [PHP security announcement and EOL source mitigations](https://www.php.net/archive/2026.php#2026-10-21-1)
- [PHP 8.4 combined fix, `506e87fa`](https://github.com/php/php-src/commit/506e87fa7dcdd306975e5b8f8265ee03527aacbf)
- [PHP 8.2 fix, `01a40e89`](https://github.com/php/php-src/commit/01a40e89fbfc499936e3b05888d8f00bfde886df)
- [PHP 8.2.35 release](https://www.php.net/releases/8_2_35.php)
- [PHP 8.3.36 release](https://www.php.net/releases/8_3_36.php)
- [PHP 8.4.27 release](https://www.php.net/releases/8_4_27.php)
- [PHP 8.5.12 release](https://www.php.net/releases/8_5_12.php)
- [Official OOM regression test](https://github.com/php/php-src/blob/php-8.4.27/Zend/tests/oom_after_main_script.phpt)
- [Official RFC1867 regression test](https://github.com/php/php-src/blob/php-8.4.27/ext/session/tests/rfc1867_no_user_code.phpt)

## Primary vulnerability research

- [Calif: PHP2Shell](https://calif.io/php2shell/) — reports distinct
  version/SAPI-dependent paths reaching PHP 5.4.0
- [Wiz: PHP2Shell PHP RCE](https://www.wiz.io/blog/php2shell-php-rce) — reports
  that at least one relevant path affects PHP releases back to 5.4

These research findings describe technical lineage and exploit paths. They are
broader than the maintained PHP 8.2–8.5 branches enumerated by the PHP CNA and
broader than this repository's four exact-build runnable profiles. See
[`docs/AFFECTED-SCOPE.md`](docs/AFFECTED-SCOPE.md).

## Historical PHP 5.4 lab image

- [`eugenesia/docker-library-php`](https://github.com/eugenesia/docker-library-php)
  supplies the source for the digest-pinned PHP 5.4.45 Apache image used only
  by the benign legacy scope probe. It is derived from the historical official
  image but is not represented here as a PHP or Docker official build.

## Licensed source adapted by the multi-version framework

- [`78ResearchLab/PHP2Shell-Full-Chain-Exploit`](https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit), commit `167085410a9342fafbd1bd64f5006920dbc83b8e`
- Reviewed upstream `exploit.py` SHA-256: `6aadf7bc93b3f4f93b755fed727d3f017e806419c96853290cf2250e567c1323`
- License: MIT, `Copyright (c) 2026 78ResearchLab`

The request lifecycle, leak sequence, and packed `r0` spray in the bundled
multi-version framework are adapted in part from this commit. The copyright
notice and complete MIT text are preserved under `poc/multiversion/`.

## Other public PoC repositories reviewed

- [`cozybear-dev/cve-2026-109619`](https://github.com/cozybear-dev/cve-2026-109619), commit `7a73bb50fbc9d0f5aafce9c135bf4cbf4575601b`
- [`9bie/php2shell-bypass-aslr-exp`](https://github.com/9bie/php2shell-bypass-aslr-exp), commit `17e98ee81025cccfd94b4f9c9a17bf269c65ff75`
- [`Bulletdev/php2shell-poc`](https://github.com/Bulletdev/php2shell-poc), commit `2d80235ccdf62bd01c1ef6ce36ae4a93b31c88cd`

These three repositories reported no detected license in GitHub's repository
metadata when checked on 2026-10-23. Their complete source trees are referenced
rather than redistributed here.

## Exact Docker image identity

The runnable profiles cover only the following official PHP Apache
`linux/amd64` images. A PHP version string alone is not sufficient.

| Role | Version | Repo/index digest | Image/config ID |
|---|---|---|---|
| Verified proof | 8.2.34 | `sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86` | `sha256:f380b054d6364b80f0952a9198e5dc1e1ab4d809aad24d3f3174f059e863f48a` |
| Fixed control | 8.2.35 | `sha256:fa8966fbaaa06981e549e7a33eb8a68f4cf677d6a82e1d6350adc5d85fe8f740` | `sha256:745174152c4e5ddc9854adea24a2c408129c27384010e29b31303e1b50e3caae` |
| Verified proof | 8.3.35 | `sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184` | `sha256:90620e863c15e608cfebd058554d82d2c7fd816bdd690adc69027409cbb7a369` |
| Fixed control | 8.3.36 | `sha256:756c2884677bedea30afaa95811b42cd3ff251203291c5820c1ad209e86c9fb4` | `sha256:7ee673f08963aa38fcbd9732a209b20bc74a9fe264feeed8252ec4594734ccea` |
| Verified proof | 8.4.26 | `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` | `sha256:46b195b6378e712d1a65cd3f853242bebd7f3cb4cafe137fd592b365909d2c17` |
| Fixed control | 8.4.27 | `sha256:e6bad969f0b673ce9121c88dabb53488ab1ca139d8ebfac1d1b1ab63f245f725` | `sha256:675af91f3349cf6dba7bd50ce967eb38732c5aa23b9e5b021dc15e2b1a2d1e5e` |
| Verified proof | 8.5.11 | `sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b` | `sha256:b384c1b31d2008af2160a735bb856317926f893553293f526024019a31d0fd6b` |
| Fixed control | 8.5.12 | `sha256:e25ab14ef2cfec3bab9dd66c6cf871691146f428fbd72241b1a2c38fcacf92f5` | `sha256:3aaf6c3363d21d928e512092ef5af8a3528cbde3bd001401e389242d94796cae` |

The digest-pinned attacker image used by the runner is:

```text
python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
```

## `libphp` identity for runnable profiles

| PHP | `libphp.so` SHA-256 | GNU build ID |
|---|---|---|
| 8.2.34 | `42ae9f69550e036ff5ad3d25d7ebf6b40bf2dd6531e8f891de53bea0d1663e9b` | `432b9cdfc44ab0205ee9f81d234d14e474e9aeb6` |
| 8.3.35 | `ea069762fa225a2d61ebf613db5686d7c29823acf641424d596f78fcaa1cdccb` | `6750eb9dbdf140fb6f76592d078784272ec1c7ca` |
| 8.4.26 | `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` | `a534a5c4a890b378ef6c227590627d531eafa8ce` |
| 8.5.11 | `2c80ca2a245ca1ccca9946f30ebeca210b9689bc24f2bd07eda717d70108ee5d` | `13ba090198423880ce5847c4e3f92c48f2385a72` |

## Publication policy

- [GitHub Active Malware or Exploits policy](https://docs.github.com/en/site-policy/acceptable-use-policies/github-active-malware-or-exploits)
- [GitHub Acceptable Use Policies](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies)

