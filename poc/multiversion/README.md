# Exact-profile multi-version local lab

> **Security research use only.** This harness is for an isolated Docker lab
> that you own or are explicitly authorised to test. The runner accepts no
> target address or command, creates an internal network with no published
> ports, and can execute only `id>/out/p`. Do not adapt it to third-party
> systems or public wargame services.

This directory contains a profile-driven reproduction of CVE-2026-109619 for
five exact official `linux/amd64` PHP Apache images. A PHP version string is
not enough: the image digest, image ID, `libphp` hash/build ID and symbols,
runtime settings, request geometry, and heap calibration must all match.

The five images are this harness's exact-build support set, not the full
affected-version range. The PHP CNA matrix enumerates maintained PHP 8.2–8.5
lines, PHP published minimal mitigations for EOL 7.4/8.0/8.1, and Calif/Wiz
report version- and SAPI-dependent paths back to PHP 5.4.0. PHP 5.4–7.3 have
neither CNA enumeration nor an official php-src backport branch. See
[Version scope](../../docs/AFFECTED-SCOPE.md).

## Verified profiles

| Profile | Stage 2 | Stage 3 | Local proof |
|---|---|---|---|
| PHP 8.1.34 | FILE_START OOM then trans-SID leak, raw SID offset `0x1fa120` | streamed 160 MiB A2 then fake reference at main chunk `+0x74160` | 3/3 fresh HTTP-only runs |
| PHP 8.2.34 | pure-HTTP/OOM B1, raw SID offset `0xe2968` | fake array at main chunk `+0xf9398` | 5/5 fresh runs, including one independent run |
| PHP 8.3.35 | adaptive window `0x20000`, 150 arrays | r0 `0x74180`, 400 spray fields | 2/2 independent runs |
| PHP 8.4.26 | fixed array | fixed carrier at `0x690d8` | 4/4 documented runs |
| PHP 8.5.11 | adaptive window `0x20000`, 150 arrays | r0 `0x73180`, one 19-byte pre-session field, 128 total spray fields | 2/2 independent runs |

The PHP 8.5 consumer has 127 large forged values: its one ordinary 19-byte
field is included in the profiled total of 128. All proofs contained
`uid=33(www-data)` and came from ptrace-free runs on fresh internal Docker
networks.

PHP 8.2.34 uses the profile-interpreted `pure-http-oom-v1` path with the stock
`php.ini-production` 128M, `display_errors=Off` runtime. Its tail A1 request preserves the stale
session ID, B1 discloses the exact-build main chunk and `libphp`, and A2/B2
reclaims the stale session value with the fixed proof payload. PHP 8.2.35
stopped at B1 with no heap pointers and no proof in 3/3 fresh controls.

PHP 8.1.34 uses the profile-interpreted `php81-trans-sid-v1` path. Its A1
request leaves a stale Session ID before session initialization, B1 recovers
the Zend MM main chunk and `libphp` base from a 1.75 MiB trans-SID response,
A2 closes the files handler before a streamed OOM leaves a stale
`zend_reference`, and B2 invokes the fixed proof command. The fresh 3/3 runs
read neither target `/proc/<pid>/maps` nor `/proc/<pid>/mem` and used neither
GDB nor ptrace. See the
[PHP 8.1 validation report](../../docs/PHP-8.1-HTTP-RCE-VALIDATION.md).
Those three proofs came from the final `zif_system` runner. Three earlier
128 MiB HTTP-only calibration runs used `zif_passthru` and are excluded from
the final profile's proof count and published address set.
For this profile only, the runner mounts `lab/index-trans-sid.php`, which emits
one fixed local `/next` link for PHP's URL rewriter. The remaining profiles
continue to use `lab/index.php`.

PHP 7.2.34 remains deliberately non-runnable. The historical PHP 8.1.34 lab
under [`../legacy-calibrated-rce/`](../legacy-calibrated-rce/) is retained as
independent terminal-primitive evidence; it uses a different 8 MiB geometry
and local `/proc` calibration. The unsupported PHP 7.2 row does not mean that
branch is unaffected or narrow the published PHP 5.4+ research range; see
[SUPPORT.md](SUPPORT.md).

## Run in WSL or Linux

The no-argument runner uses the current Docker context only after confirming
that it points to a local Unix socket. By default it runs every bundled
verified profile:

```sh
./run-local-docker-lab.sh
```

To run one exact profile, set the allow-listed selector. It never accepts a
URL, image, numeric offset, or command from the environment:

```sh
PHP2SHELL_PROFILE_ID=php-8.1.34-apache-amd64-trans-sid \
  ./run-local-docker-lab.sh
```

The script will pull an image only by its immutable digest when that image is
not already present. For each profile it then:

1. creates a new `--internal` bridge network and a new `/out` volume;
2. creates the target without host port bindings and verifies its exact image,
   platform, network attachment, output volume, and live private address; the
   selected profile file must also match its release-pinned SHA-256;
3. observes the runtime through `apache2handler`, checks one prefork worker,
   copies `libphp.so` from that live container, and verifies its hash, build ID,
   and symbols;
4. creates a ten-minute manifest binding those observations to the profile;
5. creates and inspects a read-only, capability-free attacker container from a
   digest-pinned Python image under fixed non-privileged UID/GID
   `65532:65532`, then runs the standard-library-only harness;
6. accepts success only when `/out/p` contains a `uid=<number>` proof, records
   checksummed artifacts, and removes the containers, network, and volume.

Artifacts are written below `artifacts/multiversion/<UTC-run-id>/`. The runner
does not retain the extracted `libphp.so`; it records the inspection metadata.

## Checks

```sh
bash -n run-local-docker-lab.sh
python3 -m py_compile \
  exploit.py php81_trans_sid.py profile.py elf.py profile_tool.py lab/*.py tests/*.py
python3 -m unittest -v tests/test_framework.py tests/test_release.py
```

The exploit framework and profile format are documented in
[FRAMEWORK.md](FRAMEWORK.md). The adaptive request lifecycle is derived in
part from `78ResearchLab/PHP2Shell-Full-Chain-Exploit` at commit
`167085410a9342fafbd1bd64f5006920dbc83b8e`; the MIT notice is preserved in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt](THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt).
The PHP 8.2 request bytes and heap geometry were calibrated and byte-hash
checked in the local lab. The 9bie work is cited transparently as prior art;
its source files are not redistributed here.
