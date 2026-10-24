#!/usr/bin/env bash
set -Eeuo pipefail

readonly HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SELECTION="${PHP2SHELL_LEGACY_VERSION:-all}"
readonly RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"

case "$SELECTION" in
  5.4) versions=(php-5.4.45) ;;
  5.5) versions=(php-5.5.38) ;;
  5.6) versions=(php-5.6.40) ;;
  7.0) versions=(php-7.0.33) ;;
  7.1) versions=(php-7.1.33) ;;
  7.2) versions=(php-7.2.34) ;;
  7.3) versions=(php-7.3.33) ;;
  7.4) versions=(php-7.4.33) ;;
  all)
    versions=(
      php-7.4.33 php-7.3.33 php-7.2.34 php-7.1.33
      php-7.0.33 php-5.6.40 php-5.5.38 php-5.4.45
    )
    ;;
  *)
    echo "unsupported PHP2SHELL_LEGACY_VERSION: $SELECTION" >&2
    exit 64
    ;;
esac

for version in "${versions[@]}"; do
  label="release-${RUN_ID}-${version#php-}"
  printf '\n=== %s (%s) ===\n' "$version" "$label"
  "$HERE/$version/run-http-only.sh" "$label"
done
