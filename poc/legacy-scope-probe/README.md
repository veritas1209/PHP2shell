# PHP 5.4–8.1 legacy scope probe

This is a **benign attack-surface probe**, not an RCE exploit. It records that
the default-enabled `session.upload_progress` callback creates a session
progress record while a multipart upload is paused and before `index.php`
runs. The same record is removed when the upload completes normally.

The runner covers one end-of-branch Apache build for each historical minor
line from PHP 5.4 through 8.1. Every image is pinned by registry digest and
local image ID. PHP 5.5 and later use historical Docker Official Images from
Google's registry mirror. The PHP 5.4.45 image is the archived, open-source
[`eugenesia/docker-library-php`](https://github.com/eugenesia/docker-library-php)
build because the original Docker Official Image is available only as a
schema-v1 manifest that current Docker rejects.

Run from Linux or WSL with a local Docker socket:

```bash
./run-local-docker-lab.sh
```

To run one fixed profile, select it through the allow-listed environment
variable:

```bash
PHP2SHELL_LEGACY_SCOPE_ID=php-7.4.33-apache-surface \
  ./run-local-docker-lab.sh
```

The lab creates an internal Docker network, publishes no host ports, accepts
no URL or command argument, and sends only a 1 MiB inert file body. Artifacts
are written below `artifacts/` and include image/container/network inspection,
runtime settings, the observed session record, the final HTTP response, and a
SHA-256 manifest.

## What a success means

`SURFACE_CONFIRMED` establishes these facts on the exact image:

- `session.upload_progress.enabled=1` and cleanup are active;
- the fixed progress record exists before the application script responds;
- normal upload completion reaches `index.php` and cleans the record;
- the target ran on an internal network with no published port.

It does not establish OOM corruption, cross-request stale state, information
disclosure, ASLR bypass, or code execution. The full RCE runner remains under
[`../multiversion`](../multiversion/) and currently has verified profiles only
for exact PHP 8.2.34, 8.3.35, 8.4.26, and 8.5.11 images.

