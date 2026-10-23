# References and source identity

## Official PHP sources

- [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP 8.4 combined fix, `506e87fa`](https://github.com/php/php-src/commit/506e87fa7dcdd306975e5b8f8265ee03527aacbf)
- [PHP 8.4.27 release](https://www.php.net/releases/8_4_27.php)
- [Official OOM regression test](https://github.com/php/php-src/blob/php-8.4.27/Zend/tests/oom_after_main_script.phpt)
- [Official RFC1867 regression test](https://github.com/php/php-src/blob/php-8.4.27/ext/session/tests/rfc1867_no_user_code.phpt)

## Public PoC repositories reviewed

- [`cozybear-dev/cve-2026-109619`](https://github.com/cozybear-dev/cve-2026-109619), commit `7a73bb50fbc9d0f5aafce9c135bf4cbf4575601b`
- [`9bie/php2shell-bypass-aslr-exp`](https://github.com/9bie/php2shell-bypass-aslr-exp), commit `17e98ee81025cccfd94b4f9c9a17bf269c65ff75`
- [`Bulletdev/php2shell-poc`](https://github.com/Bulletdev/php2shell-poc), commit `2d80235ccdf62bd01c1ef6ce36ae4a93b31c88cd`

The three public PoC repositories reported no detected license in GitHub's
repository metadata when checked on 2026-10-23. Their complete source trees are
therefore referenced rather than redistributed here.

## Docker image identity

```text
PHP 8.4.26 index:  sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a
PHP 8.4.26 config: sha256:46b195b6378e712d1a65cd3f853242bebd7f3cb4cafe137fd592b365909d2c17
PHP 8.4.27 index:  sha256:e6bad969f0b673ce9121c88dabb53488ab1ca139d8ebfac1d1b1ab63f245f725
PHP 8.4.27 config: sha256:675af91f3349cf6dba7bd50ce967eb38732c5aa23b9e5b021dc15e2b1a2d1e5e
```

## Publication policy

- [GitHub Active Malware or Exploits policy](https://docs.github.com/en/site-policy/acceptable-use-policies/github-active-malware-or-exploits)
- [GitHub Acceptable Use Policies](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies)

