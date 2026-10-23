# Profile-driven php2shell local research harness

This directory is a fail-closed refactor of the CVE-2026-109619 PoC. It is
intended only for an isolated Docker/WSL lab that you own or are explicitly
authorised to test.

Framework support must not be confused with affected-version scope. The PHP
CNA formally enumerates maintained PHP 8.2–8.5 branches; PHP supplied minimal
source mitigations for EOL 7.4/8.0/8.1; and Calif/Wiz report distinct attack
paths reaching PHP 5.4.0. PHP 5.4–7.3 lack both CNA enumeration and an official
php-src backport. See [Version scope](../../docs/AFFECTED-SCOPE.md).

The normal runner enforces all of these conditions before opening a socket:

- the target resolves only to loopback, RFC1918, or IPv6 ULA addresses;
- every DNS answer exactly matches a fresh target manifest;
- the profile is `verified`, not `candidate` or `retired`;
- the manifest binds the exact profile file hash, image ID/repository digest,
  `libphp` SHA-256, runtime settings, and target addresses;
- the platform is non-ZTS `apache2handler` on Linux/AMD64 with one prefork
  worker;
- the only command is `id>/out/<simple-name>`. There is no arbitrary command,
  symbol-offset, heap-offset, timing-oracle, or public-target override.

## Files

- `exploit.py`: guarded dispatcher plus profile-driven fixed-carrier and
  `r0-spray-v1` execution, including fixed or adaptive stage-2 leak recipes.
- `pure_http_oom.py`: declarative `pure-http-oom-v1` A1/B1/A2/B2 recipe
  interpreter for the exact PHP 8.2.34 `php.ini-production` runtime.
- `php81_trans_sid.py`: declarative `php81-trans-sid-v1` A1/B1/A2/B2 recipe
  interpreter for the exact PHP 8.1.34 128 MiB trans-SID runtime. It validates
  and consumes only addresses recovered from the target's HTTP response.
- `profile.py`: strict profile/manifest loader, ABI geometry checks, and local
  address policy.
- `elf.py`: bounds-checked ELF64 reader that hashes `libphp`, reads its GNU
  build ID, and resolves `zif_system` and `zval_ptr_dtor` as executable
  `STT_FUNC` symbols.
- `profile_tool.py`: offline ELF inspection, candidate-only calibration, and
  short-lived target-manifest creation.
- `profile-v1.schema.json`: the profile interchange schema.
- `profiles/`: five runnable exact-build profiles. PHP 8.1.34 uses the
  FILE_START/trans-SID path; PHP 8.2.34 uses the pure-HTTP/OOM path; PHP 8.3.35
  and 8.5.11 use adaptive stage 2 plus `r0-spray-v1`; PHP 8.4.26 uses the
  fixed-array/fixed-carrier recipe.
- `run-local-docker-lab.sh` and `lab/`: the no-argument digest-pinned runner
  and its live Docker/image/runtime verification helpers.
  `lab/index-trans-sid.php` emits one fixed local link for PHP 8.1 B1 so the
  session URL rewriter places the disclosed SID in the HTTP response; the
  other four profiles continue to mount `lab/index.php`.

PHP 8.1.34, 8.2.34, 8.3.35, 8.4.26, and 8.5.11 are runnable only for the exact
fingerprints recorded in their profiles, after repeated local UID proofs. The
maintained 8.2–8.5 profiles also have patched negative controls. PHP 7.2.34
remains non-runnable **in this standalone HTTP framework**; see `SUPPORT.md`.
A historical locally `/proc`-calibrated PHP 8.1.34 terminal RCE lab lives
under `../legacy-calibrated-rce/`, but its 8 MiB geometry is separate from the
new verified 128 MiB HTTP-only profile. Known ELF symbols alone never qualify
a new profile.

## Offline profile workflow

Inspect the module copied from the exact local image:

```bash
python3 profile_tool.py inspect-libphp ./libphp.so -o libphp-inspection.json
python3 profile_tool.py verify-libphp ./libphp.so \
  --profile profiles/php-8.4.26-apache-amd64-fixed.json
```

Record measured heap values into an existing **candidate** profile. This
command deliberately keeps the result non-runnable:

```bash
python3 profile_tool.py calibrate-candidate \
  --profile profiles/php-8.3.35-candidate.json \
  --stage1-fillers 892 \
  --r0-page-lo 0x50000 --r0-page-hi 0xc0000 \
  --r0-lowbits 0x160,0x100,0x130,0x190 \
  --output profiles/php-8.3.35-calibrated-candidate.json
```

Promotion to `verified` is intentionally manual. Do it only after the exact
image/configuration has passed the vulnerable, patched, cross-profile, and
configuration-mismatch matrix. Record the run count and evidence in the
profile.

Create a short-lived target manifest from fresh local inspection data. The
runtime JSON must be the exact object described by `profile.runtime`, measured
from the running lab rather than copied from a tag:

```bash
python3 profile_tool.py make-target-manifest \
  --profile profiles/php-8.4.26-apache-amd64-fixed.json \
  --libphp ./libphp.so \
  --runtime-json ./observed-runtime.json \
  --image-id sha256:46b195b6378e712d1a65cd3f853242bebd7f3cb4cafe137fd592b365909d2c17 \
  --repo-digest php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a \
  --address 172.20.0.2 \
  --output target-manifest.json
```

Run only inside the isolated lab, with `/out` shared between the target and
attacker:

```bash
python3 exploit.py \
  --profile profiles/php-8.4.26-apache-amd64-fixed.json \
  --target-manifest target-manifest.json \
  --url http://172.20.0.2/index.php \
  --proof-target /out/p \
  --proof /proof/p
```

The local proof path must not already exist. Exit status is `0` only when it
contains `uid=<number>`; validation and exploit failures return `2`.

## Current limits

- Profiles are exact-build artefacts; a PHP version alone is never enough.
- `pure-http-oom-v1` is a separate recipe shape. It records the PHP 8.2 A1
  tail geometry, raw stale-SID offset, B1 disclosure size/page order, A2
  nested-field geometry, and B2 fake-reference/fake-array placement. Its
  large B1 request uses chunked transfer so the stock `post_max_size=8M`
  runtime follows the measured request path.
- `php81-trans-sid-v1` records the PHP 8.1 FILE_START producer, raw stale-SID
  offset, fixed 1.75 MiB trans-SID disclosure, HTTP leak invariants, streamed
  A2 size, and B2 fake-reference placement. Its leak parser requires the
  expected prefix, exact length, a 2 MiB-aligned main chunk, and one strongly
  repeated page-aligned `zval_ptr_dtor` candidate before deriving either base.
- The pure HTTP engine accepts only the fixed `id>/out/<simple-name>` proof
  command supplied by the guarded entry point. It cannot be selected with a
  public target, command, offset, or image override.
- The ABI builder supports the profiled PHP 8 Zend layout on Linux/AMD64.
- Schema v1's `zend_execute_data.call_info` key is a compatibility name for
  the pointer at offset `0x40`; the real PHP 8 member is
  `zend_execute_data.run_time_cache`. The payload writes a full null pointer
  there. Renaming the serialized key would invalidate every v1 profile, so the
  accurate mapping is documented and used internally until a future schema
  version can rename it.
- The single-worker requirement is part of the current exploit chain.
- `stage2.strategy` records whether a build uses the legacy
  `fixed-array-v1` leak or the upstream-compatible `adaptive-window-v1`
  request. Adaptive stage 2 intentionally preserves the successful stage-1
  worker state and rotates only between failed retries.
- `r0-spray-v1.pre_session_fields` records allocation grooming that must occur
  before `PHPSESSID` and the upload-progress field. Its count is included in
  `spray.count`; the remaining carriers keep the same numeric field sequence.
- `r0-spray-v1` reports the successful page and the packed low-bit set. A
  packed success does not identify which low bit hit; keep that calibration a
  candidate until isolated reruns establish it.
- `make-target-manifest` validates supplied local evidence. The surrounding
  lab script remains responsible for collecting image/runtime facts from the
  intended container and for keeping the Docker network internal.

See `THIRD_PARTY_NOTICES.md` for the upstream MIT attribution.

