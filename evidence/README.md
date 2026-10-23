# Evidence index

| File | Meaning |
|---|---|
| `cozybear-compose-final-exact.log` | Clean PHP 8.4.26/8.4.27 Docker A/B run; `RESULT: CONFIRMED` |
| `rce-proof.txt` | Vulnerable target's independently copied `www-data` proof |
| `fixed-proof-check.txt` | Patched target proof path was absent |
| `9bie-b1-leak-diagnosis.txt` | Independent pointer-filter and `/proc/maps` cross-check |
| `official-oom-*.log` | Official OOM regression differential |
| `official-rfc1867-*.log` | Official session/RFC1867 regression differential |
| `multiversion/` | Sanitized final-run proofs, patched-control identities, and release-source hashes for PHP 8.1.34/8.2.34/8.3.35/8.4.26/8.5.11 |
| `legacy-runtime-matrix.txt` | Compact, digest-pinned PHP 5.4.45–8.1.34 benign pre-script upload-progress observations; explicitly not RCE evidence |
| `legacy-rce/` | Sanitized exact-build terminal RCE transcripts for locally calibrated PHP 7.3.33/7.4.33/8.0.30/8.1.34 labs |
| `SHA256SUMS.txt` | SHA-256 hashes for every evidence file except the manifest itself |

ANSI terminal control bytes were removed from the public Compose log. The raw
container inspect JSON and the original private bundle were excluded because
they contained local host paths and unrelated Docker metadata.

