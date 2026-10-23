#!/usr/bin/env bash
# Research-use only. This runner is intentionally limited to its local,
# digest-pinned Docker Compose lab and accepts no external target.
set -Eeuo pipefail

UPSTREAM_URL="https://github.com/cozybear-dev/cve-2026-109619.git"
UPSTREAM_COMMIT="7a73bb50fbc9d0f5aafce9c135bf4cbf4575601b"
VULN_DIGEST="60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a"
FIXED_DIGEST="e6bad969f0b673ce9121c88dabb53488ab1ca139d8ebfac1d1b1ab63f245f725"
ATTACKER_BASE_DIGEST="a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704"

if (( $# != 0 )); then
    echo "this runner accepts no arguments or external targets" >&2
    exit 2
fi

# Prevent Compose environment variables from selecting another file, project,
# or profile. The exact lab files and project are supplied on every invocation.
unset COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_PATH_SEPARATOR
unset COMPOSE_ENV_FILES

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
DOCKER_BIN="${DOCKER_BIN:-docker}"
ARTIFACTS_ROOT="${ARTIFACTS_DIR:-$REPO_ROOT/artifacts}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$ARTIFACTS_ROOT/$RUN_ID"
SCRATCH_PARENT="$REPO_ROOT/.work"
mkdir -p "$SCRATCH_PARENT"
SCRATCH_ROOT="$(mktemp -d "$SCRATCH_PARENT/php2shell-lab.XXXXXX")"
LAB_DIR="$SCRATCH_ROOT/upstream"
COMPOSE_PROJECT="cve-2026-109619"

compose_lab() {
    "$DOCKER_BIN" compose \
        -f "$LAB_DIR/compose.yaml" \
        -f "$LAB_DIR/research-only.override.yaml" \
        -p "$COMPOSE_PROJECT" "$@"
}

cleanup() {
    local exit_code=$?
    set +e
    if [[ -d "$LAB_DIR" ]]; then
        (cd "$LAB_DIR" && compose_lab down -v --remove-orphans >/dev/null 2>&1)
    fi
    rm -rf -- "$SCRATCH_ROOT"
    return "$exit_code"
}
trap cleanup EXIT

for dependency in git tee grep python3; do
    command -v "$dependency" >/dev/null || {
        echo "missing dependency: $dependency" >&2
        exit 1
    }
done
[[ -x "$DOCKER_BIN" ]] || command -v "$DOCKER_BIN" >/dev/null || {
    echo "docker executable not found: $DOCKER_BIN" >&2
    exit 1
}

if [[ -n "${DOCKER_CONTEXT:-}" ]]; then
    CONTEXT_NAME="$DOCKER_CONTEXT"
    CONTEXT_ENDPOINT="$(
        "$DOCKER_BIN" context inspect "$CONTEXT_NAME" \
            --format '{{.Endpoints.docker.Host}}' 2>/dev/null
    )" || {
        echo "cannot inspect Docker context: $CONTEXT_NAME" >&2
        exit 1
    }
    EFFECTIVE_ENDPOINT="$CONTEXT_ENDPOINT"
else
    CONTEXT_NAME="$("$DOCKER_BIN" context show 2>/dev/null)" || {
        echo "cannot determine the Docker context" >&2
        exit 1
    }
    CONTEXT_ENDPOINT="$(
        "$DOCKER_BIN" context inspect "$CONTEXT_NAME" \
            --format '{{.Endpoints.docker.Host}}' 2>/dev/null
    )" || {
        echo "cannot inspect Docker context: $CONTEXT_NAME" >&2
        exit 1
    }
    EFFECTIVE_ENDPOINT="${DOCKER_HOST:-$CONTEXT_ENDPOINT}"
fi
case "$EFFECTIVE_ENDPOINT" in
    unix://*) ;;
    *)
        echo "refusing non-local Docker endpoint: $EFFECTIVE_ENDPOINT" >&2
        exit 1
        ;;
esac
DOCKER_SOCKET="${EFFECTIVE_ENDPOINT#unix://}"
[[ -S "$DOCKER_SOCKET" ]] || {
    echo "local Docker socket is unavailable: $DOCKER_SOCKET" >&2
    exit 1
}
"$DOCKER_BIN" info >/dev/null 2>&1 || {
    echo "cannot access the Docker daemon with $DOCKER_BIN" >&2
    echo "run with Docker-group access or use sudo as documented" >&2
    exit 1
}

mkdir -p "$RUN_DIR"

git init -q "$LAB_DIR"
git_lab() {
    git -c safe.directory="$LAB_DIR" -C "$LAB_DIR" "$@"
}
git_lab remote add origin "$UPSTREAM_URL"
git_lab fetch -q --depth 1 origin "$UPSTREAM_COMMIT"
git_lab checkout -q --detach FETCH_HEAD

ACTUAL_COMMIT="$(git_lab rev-parse HEAD)"
[[ "$ACTUAL_COMMIT" == "$UPSTREAM_COMMIT" ]] || {
    echo "unexpected upstream commit: $ACTUAL_COMMIT" >&2
    exit 1
}

grep -Fq "php@sha256:$VULN_DIGEST" "$LAB_DIR/compose.yaml"
grep -Fq "php@sha256:$FIXED_DIGEST" "$LAB_DIR/compose.yaml"
grep -Fq '127.0.0.1:8088:80' "$LAB_DIR/compose.yaml"
grep -Fq '127.0.0.1:8089:80' "$LAB_DIR/compose.yaml"

python3 - \
    "$LAB_DIR/attacker/exploit.py" \
    "$LAB_DIR/attacker/Dockerfile" \
    "$ATTACKER_BASE_DIGEST" <<'PY'
from pathlib import Path
import sys

exploit_path = Path(sys.argv[1])
dockerfile_path = Path(sys.argv[2])
attacker_digest = sys.argv[3]

source = exploit_path.read_text(encoding="utf-8")
old = "return 0x7F0000000000 <= v < 0x0001000000000000"
new = "return 0x700000000000 <= v < 0x0001000000000000"
if source.count(old) != 1:
    raise SystemExit("upstream pointer predicate did not match exactly once")
exploit_path.write_text(source.replace(old, new), encoding="utf-8")

dockerfile = dockerfile_path.read_text(encoding="utf-8")
old_base = "FROM python:3.12-slim"
new_base = f"{old_base}@sha256:{attacker_digest}"
if dockerfile.count(old_base) != 1:
    raise SystemExit("upstream attacker base did not match exactly once")
dockerfile_path.write_text(
    dockerfile.replace(old_base, new_base), encoding="utf-8"
)
PY
git_lab diff --check
git_lab diff -- attacker/exploit.py attacker/Dockerfile > "$RUN_DIR/applied.patch"

cat > "$LAB_DIR/research-only.override.yaml" <<'YAML'
services:
  vuln:
    security_opt:
      - no-new-privileges:true
    mem_limit: 512m
    pids_limit: 64
  fixed:
    security_opt:
      - no-new-privileges:true
    mem_limit: 512m
    pids_limit: 64
  attacker:
    security_opt:
      - no-new-privileges:true
    mem_limit: 256m
    pids_limit: 64
networks:
  default:
    internal: true
YAML

set +e
(
    cd "$LAB_DIR"
    COMPOSE_PROGRESS=plain compose_lab up --build \
        --abort-on-container-exit --exit-code-from attacker 2>&1
) | tee "$RUN_DIR/compose.log"
COMPOSE_RC=${PIPESTATUS[0]}
set -e
echo "COMPOSE_EXIT_CODE=$COMPOSE_RC" | tee -a "$RUN_DIR/compose.log"

"$DOCKER_BIN" cp \
    cve-2026-109619-attacker-1:/proof/vuln/p \
    "$RUN_DIR/rce-proof.txt"

if "$DOCKER_BIN" cp \
    cve-2026-109619-attacker-1:/proof/fixed/p \
    "$RUN_DIR/unexpected-fixed-proof.txt" >/dev/null 2>&1; then
    echo "UNEXPECTED_FIXED_PROOF_PRESENT" | tee "$RUN_DIR/fixed-proof-check.txt"
    exit 1
else
    echo "EXPECTED_NO_FIXED_PROOF" | tee "$RUN_DIR/fixed-proof-check.txt"
fi

grep -Fq 'uid=33(www-data)' "$RUN_DIR/rce-proof.txt"
grep -Fq 'RESULT: CONFIRMED' "$RUN_DIR/compose.log"
[[ "$COMPOSE_RC" -eq 0 ]]

(
    cd "$RUN_DIR"
    sha256sum applied.patch compose.log fixed-proof-check.txt rce-proof.txt \
        > SHA256SUMS.txt
)

echo "RCE proof: $(cat "$RUN_DIR/rce-proof.txt")"
echo "Artifacts: $RUN_DIR"

