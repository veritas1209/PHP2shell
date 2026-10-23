#!/usr/bin/env bash
# Research-use only: exact, verified profiles in a local Docker isolation lab.
set -Eeuo pipefail

if (( $# != 0 )); then
    echo "this runner accepts no arguments or external targets" >&2
    exit 64
fi

readonly ATTACKER_IMAGE="python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704"
readonly -a VERIFIED_PROFILE_IDS=(
    "php-8.1.34-apache-amd64-trans-sid"
    "php-8.2.34-apache-amd64-pure-http-oom"
    "php-8.3.35-apache-amd64-r0-spray"
    "php-8.4.26-apache-amd64-fixed-carrier"
    "php-8.5.11-apache-amd64-r0-spray"
)

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly VERIFY_DOCKER="$SCRIPT_DIR/lab/verify_docker.py"
readonly PROFILE_SELECTION="${PHP2SHELL_PROFILE_ID:-all}"
readonly RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
readonly ARTIFACTS_ROOT="$SCRIPT_DIR/artifacts/multiversion"
readonly RUN_ROOT="$ARTIFACTS_ROOT/$RUN_ID"
readonly WORK_PARENT="$SCRIPT_DIR/.work"

for dependency in python3 sha256sum grep mktemp uname; do
    command -v "$dependency" >/dev/null || {
        echo "missing dependency: $dependency" >&2
        exit 1
    }
done

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "run this script inside Linux or WSL with a local Unix Docker socket" >&2
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

if [[ -n "${DOCKER_CONTEXT:-}" ]]; then
    context_name="$DOCKER_CONTEXT"
    context_endpoint="$(
        "$DOCKER_BIN" context inspect "$context_name" \
            --format '{{.Endpoints.docker.Host}}' 2>/dev/null
    )" || {
        echo "cannot inspect Docker context: $context_name" >&2
        exit 1
    }
    effective_endpoint="$context_endpoint"
else
    context_name="$("$DOCKER_BIN" context show 2>/dev/null)" || {
        echo "cannot determine the Docker context" >&2
        exit 1
    }
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
docker_socket="${effective_endpoint#unix://}"
if [[ ! -S "$docker_socket" ]]; then
    echo "local Docker socket is unavailable: $docker_socket" >&2
    exit 1
fi
"$DOCKER_BIN" info >/dev/null 2>&1 || {
    echo "cannot access the local Docker daemon" >&2
    exit 1
}

case "$PROFILE_SELECTION" in
    all)
        SELECTED_PROFILE_IDS=("${VERIFIED_PROFILE_IDS[@]}")
        ;;
    php-8.1.34-apache-amd64-trans-sid|php-8.2.34-apache-amd64-pure-http-oom|php-8.3.35-apache-amd64-r0-spray|php-8.4.26-apache-amd64-fixed-carrier|php-8.5.11-apache-amd64-r0-spray)
        SELECTED_PROFILE_IDS=("$PROFILE_SELECTION")
        ;;
    *)
        echo "refusing unknown or unverified profile ID: $PROFILE_SELECTION" >&2
        exit 64
        ;;
esac
readonly -a SELECTED_PROFILE_IDS

mkdir --parents -- "$ARTIFACTS_ROOT" "$WORK_PARENT"
mkdir -- "$RUN_ROOT"

ensure_image() {
    local reference=$1 expected_id=${2:-} inspect_path=$3
    if ! "$DOCKER_BIN" image inspect "$reference" >"$inspect_path" 2>/dev/null; then
        "$DOCKER_BIN" pull --quiet --platform linux/amd64 "$reference" >/dev/null
        "$DOCKER_BIN" image inspect "$reference" >"$inspect_path"
    fi
    local -a verify=(
        python3 "$VERIFY_DOCKER" image
        --inspect "$inspect_path"
        --reference "$reference"
        --print-id
    )
    if [[ -n "$expected_id" ]]; then
        verify+=(--expected-id "$expected_id")
    fi
    "${verify[@]}"
}

ATTACKER_IMAGE_ID="$(
    ensure_image "$ATTACKER_IMAGE" "" "$RUN_ROOT/attacker-image-inspect.json"
)"
readonly ATTACKER_IMAGE_ID

profile_spec() {
    case "$1" in
        php-8.1.34-apache-amd64-trans-sid)
            PROFILE_FILE="php-8.1.34-apache-amd64-trans-sid.json"
            PROFILE_SHA256="bb52e592c1bdc81b32413604f804ccdefcc4f255ca8132a2355c66dc51c5564c"
            TARGET_IMAGE="mirror.gcr.io/library/php@sha256:72f0c0134922985022d55a39b0390d35dc7a10e961aa6c44fa35b4c3102f4268"
            TARGET_IMAGE_ID="sha256:e6c924c6e862e6c74e01be964f88cb0c7ccbd673925e9a648cbbf77ff53b7ca1"
            PHP_INI_FILE="php81-trans.ini"
            INDEX_FILE="index-trans-sid.php"
            PRODUCTION_INI=0
            ;;
        php-8.3.35-apache-amd64-r0-spray)
            PROFILE_FILE="php-8.3.35-apache-amd64-r0-spray.json"
            PROFILE_SHA256="98047f64453c5fbcf88ce57fc42494d13083ab206a21357db8a438240c9d04cf"
            TARGET_IMAGE="php@sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184"
            TARGET_IMAGE_ID="sha256:90620e863c15e608cfebd058554d82d2c7fd816bdd690adc69027409cbb7a369"
            PHP_INI_FILE="php.ini"
            INDEX_FILE="index.php"
            PRODUCTION_INI=0
            ;;
        php-8.4.26-apache-amd64-fixed-carrier)
            PROFILE_FILE="php-8.4.26-apache-amd64-fixed.json"
            PROFILE_SHA256="28a0145a06b703ba612e36543e1cfe6acba5728b151dbd370d3260ee3cdd2a4a"
            TARGET_IMAGE="php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a"
            TARGET_IMAGE_ID="sha256:46b195b6378e712d1a65cd3f853242bebd7f3cb4cafe137fd592b365909d2c17"
            PHP_INI_FILE="php.ini"
            INDEX_FILE="index.php"
            PRODUCTION_INI=0
            ;;
        php-8.5.11-apache-amd64-r0-spray)
            PROFILE_FILE="php-8.5.11-apache-amd64-r0-spray.json"
            PROFILE_SHA256="6339a0fa94d2eaf7e00a8dfa8769be3c98d708ce1f40e735b107caa1aa2f3127"
            TARGET_IMAGE="php@sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b"
            TARGET_IMAGE_ID="sha256:b384c1b31d2008af2160a735bb856317926f893553293f526024019a31d0fd6b"
            PHP_INI_FILE="php.ini"
            INDEX_FILE="index.php"
            PRODUCTION_INI=0
            ;;
        php-8.2.34-apache-amd64-pure-http-oom)
            PROFILE_FILE="php-8.2.34-apache-amd64-pure-http-oom.json"
            PROFILE_SHA256="a0d1d55152445385885230a384f859001193afad08604b407e987dc9ba34aec6"
            TARGET_IMAGE="php@sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86"
            TARGET_IMAGE_ID="sha256:f380b054d6364b80f0952a9198e5dc1e1ab4d809aad24d3f3174f059e863f48a"
            # The measured target uses the image's stock php.ini-production.
            PHP_INI_FILE=""
            INDEX_FILE="index.php"
            PRODUCTION_INI=1
            ;;
        *)
            echo "internal error: profile escaped the allow-list: $1" >&2
            return 1
            ;;
    esac
    readonly PROFILE_FILE PROFILE_SHA256 TARGET_IMAGE TARGET_IMAGE_ID PHP_INI_FILE INDEX_FILE PRODUCTION_INI
}

run_profile() (
    set -Eeuo pipefail
    local profile_id=$1
    profile_spec "$profile_id"

    local profile_path="$SCRIPT_DIR/profiles/$PROFILE_FILE"
    local artifact_dir="$RUN_ROOT/$profile_id"
    local scratch_dir
    scratch_dir="$(mktemp -d "$WORK_PARENT/${profile_id}.XXXXXX")"
    chmod 0755 "$scratch_dir"
    mkdir -- "$scratch_dir/in" "$scratch_dir/out"
    chmod 0755 "$scratch_dir/in"
    chmod 0733 "$scratch_dir/out"
    mkdir -- "$artifact_dir"

    local suffix="${RUN_ID//[^A-Za-z0-9_.-]/-}-${RANDOM}"
    local network_name="p2s-net-$suffix"
    local volume_name="p2s-out-$suffix"
    local target_name="p2s-target-$suffix"
    local -a created_containers=()
    local network_created=0 volume_created=0

    cleanup_profile() {
        local rc=$?
        set +e
        local name
        for name in "${created_containers[@]}"; do
            "$DOCKER_BIN" rm -f "$name" >/dev/null 2>&1 || true
        done
        if (( network_created )); then
            "$DOCKER_BIN" network rm "$network_name" >/dev/null 2>&1 || true
        fi
        if (( volume_created )); then
            "$DOCKER_BIN" volume rm "$volume_name" >/dev/null 2>&1 || true
        fi
        rm -rf -- "$scratch_dir"
        return "$rc"
    }
    trap cleanup_profile EXIT

    if [[ ! -f "$profile_path" ]]; then
        echo "bundled profile is missing: $profile_path" >&2
        exit 1
    fi
    cp -- "$profile_path" "$scratch_dir/in/profile.json"
    local actual_profile_sha
    read -r actual_profile_sha _ < <(sha256sum -- "$scratch_dir/in/profile.json")
    if [[ "$actual_profile_sha" != "$PROFILE_SHA256" ]]; then
        echo "refusing modified profile file: $PROFILE_FILE" >&2
        exit 1
    fi
    chmod 0444 "$scratch_dir/in/profile.json"

    local target_image_inspect="$artifact_dir/target-image-inspect.json"
    local actual_target_id
    actual_target_id="$(ensure_image "$TARGET_IMAGE" "$TARGET_IMAGE_ID" "$target_image_inspect")"
    [[ "$actual_target_id" == "$TARGET_IMAGE_ID" ]]

    "$DOCKER_BIN" network create --internal \
        --label org.php2shell.purpose=isolated-research "$network_name" \
        >"$artifact_dir/network-create.txt"
    network_created=1
    "$DOCKER_BIN" network inspect "$network_name" >"$artifact_dir/network-inspect.json"
    python3 "$VERIFY_DOCKER" network \
        --inspect "$artifact_dir/network-inspect.json" --name "$network_name"

    "$DOCKER_BIN" volume create \
        --label org.php2shell.purpose=proof-output "$volume_name" \
        >"$artifact_dir/volume-create.txt"
    volume_created=1

    local -a php_ini_mount=()
    if [[ -n "$PHP_INI_FILE" ]]; then
        php_ini_mount=(
            --mount "type=bind,src=$SCRIPT_DIR/lab/$PHP_INI_FILE,dst=/usr/local/etc/php/conf.d/zz-php2shell.ini,readonly"
        )
    fi

    "$DOCKER_BIN" create \
        --name "$target_name" \
        --network "$network_name" \
        --network-alias target \
        --security-opt no-new-privileges:true \
        --pids-limit 64 \
        --memory 512m \
        --env "PHP2SHELL_PRODUCTION_INI=$PRODUCTION_INI" \
        --tmpfs /tmp:rw,nosuid,nodev,size=128m \
        "${php_ini_mount[@]}" \
        --mount "type=bind,src=$SCRIPT_DIR/lab/apache.conf,dst=/etc/apache2/conf-enabled/zz-php2shell.conf,readonly" \
        --mount "type=bind,src=$SCRIPT_DIR/lab/$INDEX_FILE,dst=/var/www/html/index.php,readonly" \
        --mount "type=bind,src=$SCRIPT_DIR/lab/runtime.php,dst=/var/www/html/runtime.php,readonly" \
        --mount "type=volume,src=$volume_name,dst=/out" \
        "$TARGET_IMAGE" \
        sh -eu -c 'if [ "$PHP2SHELL_PRODUCTION_INI" = 1 ]; then cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini; fi; chown www-data:www-data /out; rm -f /out/p; exec apache2-foreground' \
        >"$artifact_dir/target-container-id.txt"
    created_containers+=("$target_name")
    "$DOCKER_BIN" start "$target_name" >/dev/null

    run_helper() {
        local role=$1 log_path=$2
        shift 2
        local helper_name="p2s-${role}-$suffix"
        local inspect_path="$artifact_dir/${role}-container-inspect.json"
        "$DOCKER_BIN" create \
            --name "$helper_name" \
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
            --mount "type=bind,src=$scratch_dir,dst=/scratch" \
            "$ATTACKER_IMAGE" "$@" >/dev/null
        created_containers+=("$helper_name")
        "$DOCKER_BIN" inspect "$helper_name" >"$inspect_path"
        python3 "$VERIFY_DOCKER" container \
            --inspect "$inspect_path" \
            --name "$helper_name" \
            --image-id "$ATTACKER_IMAGE_ID" \
            --image-reference "$ATTACKER_IMAGE" \
            --network "$network_name" \
            --expected-user 65532:65532 \
            --require-read-only \
            --require-cap-drop-all \
            --require-no-new-privileges
        set +e
        "$DOCKER_BIN" start --attach "$helper_name" >"$log_path" 2>&1
        local rc=$?
        set -e
        "$DOCKER_BIN" inspect "$helper_name" >"$artifact_dir/${role}-container-exit-inspect.json"
        if (( rc != 0 )); then
            cat "$log_path" >&2
            return "$rc"
        fi
    }

    run_helper runtime-probe "$artifact_dir/runtime-probe.log" \
        python3 /harness/lab/runtime_probe.py \
        --url http://target/runtime.php \
        --output /scratch/out/observed-runtime-full.json

    "$DOCKER_BIN" exec "$target_name" sh -eu -c \
        'apache2ctl -M 2>/dev/null | grep -q mpm_prefork_module; n=0; for f in /proc/[0-9]*/comm; do if [ "$(cat "$f")" = apache2 ]; then n=$((n+1)); fi; done; [ "$n" -eq 2 ]'

    "$DOCKER_BIN" inspect "$target_name" >"$artifact_dir/target-container-inspect.json"
    python3 "$VERIFY_DOCKER" container \
        --inspect "$artifact_dir/target-container-inspect.json" \
        --name "$target_name" \
        --image-id "$TARGET_IMAGE_ID" \
        --image-reference "$TARGET_IMAGE" \
        --network "$network_name" \
        --running \
        --volume-name "$volume_name" \
        --volume-destination /out \
        --volume-mode rw \
        --require-no-new-privileges \
        --print-addresses >"$scratch_dir/out/target-addresses.txt"
    mapfile -t target_addresses <"$scratch_dir/out/target-addresses.txt"
    if (( ${#target_addresses[@]} == 0 )); then
        echo "target has no verified private address" >&2
        exit 1
    fi

    "$DOCKER_BIN" cp \
        "$target_name:/usr/lib/apache2/modules/libphp.so" \
        "$scratch_dir/in/libphp.so"

    run_helper observation-check "$artifact_dir/observation-check.log" \
        python3 /harness/lab/verify_observation.py \
        --profile /scratch/in/profile.json \
        --observation /scratch/out/observed-runtime-full.json \
        --expected-profile-id "$profile_id" \
        --expected-repo-digest "$TARGET_IMAGE" \
        --expected-image-id "$TARGET_IMAGE_ID" \
        --runtime-output /scratch/out/observed-runtime.json

    cp -- "$scratch_dir/out/observed-runtime-full.json" "$artifact_dir/observed-runtime-full.json"
    cp -- "$scratch_dir/out/observed-runtime.json" "$artifact_dir/observed-runtime.json"

    run_helper libphp-inspect "$artifact_dir/libphp-inspect.log" \
        python3 /harness/profile_tool.py inspect-libphp /scratch/in/libphp.so \
        --output /scratch/out/libphp-inspection.json
    cp -- "$scratch_dir/out/libphp-inspection.json" "$artifact_dir/libphp-inspection.json"

    run_helper libphp-verify "$artifact_dir/libphp-verify.log" \
        python3 /harness/profile_tool.py verify-libphp /scratch/in/libphp.so \
        --profile /scratch/in/profile.json

    local -a manifest_command=(
        python3 /harness/profile_tool.py make-target-manifest
        --profile /scratch/in/profile.json
        --libphp /scratch/in/libphp.so
        --runtime-json /scratch/out/observed-runtime.json
        --image-id "$TARGET_IMAGE_ID"
        --repo-digest "$TARGET_IMAGE"
        --minutes 10
        --output /scratch/out/target-manifest.json
    )
    local address
    for address in "${target_addresses[@]}"; do
        manifest_command+=(--address "$address")
    done
    run_helper manifest "$artifact_dir/manifest.log" "${manifest_command[@]}"
    cp -- "$scratch_dir/out/target-manifest.json" "$artifact_dir/target-manifest.json"

    "$DOCKER_BIN" exec "$target_name" test ! -e /out/p

    local attacker_name="p2s-attacker-$suffix"
    "$DOCKER_BIN" create \
        --name "$attacker_name" \
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
        --mount "type=bind,src=$scratch_dir,dst=/scratch,readonly" \
        --mount "type=volume,src=$volume_name,dst=/proof,readonly" \
        "$ATTACKER_IMAGE" \
        python3 /harness/exploit.py \
        --profile /scratch/in/profile.json \
        --target-manifest /scratch/out/target-manifest.json \
        --url http://target/index.php \
        --proof-target /out/p \
        --proof /proof/p \
        --retries 3 \
        --timeout 30 \
        >"$artifact_dir/attacker-container-id.txt"
    created_containers+=("$attacker_name")
    "$DOCKER_BIN" inspect "$attacker_name" >"$artifact_dir/attacker-container-inspect.json"
    python3 "$VERIFY_DOCKER" container \
        --inspect "$artifact_dir/attacker-container-inspect.json" \
        --name "$attacker_name" \
        --image-id "$ATTACKER_IMAGE_ID" \
        --image-reference "$ATTACKER_IMAGE" \
        --network "$network_name" \
        --expected-user 65532:65532 \
        --volume-name "$volume_name" \
        --volume-destination /proof \
        --volume-mode ro \
        --require-read-only \
        --require-cap-drop-all \
        --require-no-new-privileges

    set +e
    "$DOCKER_BIN" start --attach "$attacker_name" >"$artifact_dir/exploit.log" 2>&1
    local exploit_rc=$?
    set -e
    echo "$exploit_rc" >"$artifact_dir/exploit.exit"
    "$DOCKER_BIN" inspect "$attacker_name" >"$artifact_dir/attacker-container-exit-inspect.json"
    "$DOCKER_BIN" logs "$target_name" >"$artifact_dir/target.log" 2>&1 || true
    "$DOCKER_BIN" exec "$target_name" sh -c \
        'if test -r /out/p; then cat /out/p; else printf "%s\n" NO_PROOF; fi' \
        >"$artifact_dir/proof.txt"

    if (( exploit_rc != 0 )); then
        cat "$artifact_dir/exploit.log" >&2
        echo "exploit exited with status $exploit_rc" >&2
        exit "$exploit_rc"
    fi
    grep -Eq '^uid=[0-9]+' "$artifact_dir/proof.txt"

    (
        cd -- "$artifact_dir"
        sha256sum \
            attacker-container-inspect.json \
            exploit.exit exploit.log \
            libphp-inspection.json libphp-verify.log \
            network-inspect.json observed-runtime-full.json \
            proof.txt target-container-inspect.json \
            target-image-inspect.json target-manifest.json target.log \
            >SHA256SUMS.txt
    )

    printf '%s: %s\n' "$profile_id" "$(cat "$artifact_dir/proof.txt")"
)

for profile_id in "${SELECTED_PROFILE_IDS[@]}"; do
    run_profile "$profile_id"
done

echo "artifacts: $RUN_ROOT"
