#!/usr/bin/env bash
# Research-use only: run the fixed legacy profiles in a local Docker lab.
set -Eeuo pipefail

if (( $# != 0 )); then
    echo "this runner accepts no arguments or external targets" >&2
    exit 64
fi
if (( EUID != 0 )); then
    echo "local /proc calibration requires root; rerun with sudo" >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly SELECTION="${PHP2SHELL_LEGACY_PROFILE_ID:-all}"

case "$SELECTION" in
    all)
        profiles=(raw-key-partial-bucket php-8.1.34)
        ;;
    raw-key-partial-bucket|php-8.1.34)
        profiles=("$SELECTION")
        ;;
    *)
        echo "refusing unknown legacy profile: $SELECTION" >&2
        exit 64
        ;;
esac

for profile in "${profiles[@]}"; do
    printf '\n=== %s locally calibrated RCE lab ===\n' "$profile"
    "$SCRIPT_DIR/$profile/run-local-docker-lab.sh"
done
