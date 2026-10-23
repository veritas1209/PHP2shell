# Exact-profile multi-version local lab

> **Security research use only.** This harness is for an isolated Docker lab
> that you own or are explicitly authorised to test. The runner accepts no
> target address or command, creates an internal network with no published
> ports, and can execute only `id>/out/p`. Do not adapt it to third-party
> systems or public wargame services.

This directory contains a profile-driven reproduction of CVE-2026-109619 for
three exact official `linux/amd64` PHP Apache images. A PHP version string is
not enough: the image digest, image ID, `libphp` hash/build ID and symbols,
runtime settings, request geometry, and heap calibration must all match.

## Verified profiles

| Profile | Stage 2 | Stage 3 | Local proof |
|---|---|---|---|
| PHP 8.3.35 | adaptive window `0x20000`, 150 arrays | r0 `0x74180`, 400 spray fields | 2/2 independent runs |
| PHP 8.4.26 | fixed array | fixed carrier at `0x690d8` | 4/4 documented runs |
| PHP 8.5.11 | adaptive window `0x20000`, 150 arrays | r0 `0x73180`, one 19-byte pre-session field, 128 total spray fields | 2/2 independent runs |

The PHP 8.5 consumer has 127 large forged values: its one ordinary 19-byte
field is included in the profiled total of 128. All proofs contained
`uid=33(www-data)` and came from ptrace-free runs on fresh internal Docker
networks.

PHP 8.2.34, 8.1.34, and 7.2.34 are deliberately **non-runnable** here. This
does not mean those branches are unaffected. The current chain cannot obtain
its required session-cookie disclosure on those runtimes; changing offsets or
filler counts is insufficient. See [SUPPORT.md](SUPPORT.md).

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
PHP2SHELL_PROFILE_ID=php-8.5.11-apache-amd64-r0-spray \
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
  exploit.py profile.py elf.py profile_tool.py lab/*.py tests/*.py
python3 -m unittest -v tests/test_framework.py tests/test_release.py
```

The exploit framework and profile format are documented in
[FRAMEWORK.md](FRAMEWORK.md). The adaptive request lifecycle is derived in
part from `78ResearchLab/PHP2Shell-Full-Chain-Exploit` at commit
`167085410a9342fafbd1bd64f5006920dbc83b8e`; the MIT notice is preserved in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt](THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt).
