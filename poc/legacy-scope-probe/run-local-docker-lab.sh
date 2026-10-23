#!/usr/bin/env bash
# Research-use only: benign version-scope probe on pinned local Docker images.
set -Eeuo pipefail

if (( $# != 0 )); then
    echo "this runner accepts no arguments or external targets" >&2
    exit 64
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly SELECTION="${PHP2SHELL_LEGACY_SCOPE_ID:-all}"
readonly RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
readonly RUN_ROOT="$SCRIPT_DIR/artifacts/$RUN_ID"
readonly WORK_ROOT="$SCRIPT_DIR/.work"
readonly -a PROFILE_IDS=(
    php-5.4.45-apache-surface
    php-5.5.38-apache-surface
    php-5.6.40-apache-surface
    php-7.0.33-apache-surface
    php-7.1.33-apache-surface
    php-7.2.34-apache-surface
    php-7.3.33-apache-surface
    php-7.4.33-apache-surface
    php-8.0.30-apache-surface
    php-8.1.34-apache-surface
)

for dependency in python3 sha256sum grep mktemp uname; do
    command -v "$dependency" >/dev/null || {
        echo "missing dependency: $dependency" >&2
        exit 1
    }
done
if [[ "$(uname -s)" != Linux ]]; then
    echo "run inside Linux or WSL with a local Unix Docker socket" >&2
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

context_name="$($DOCKER_BIN context show 2>/dev/null)"
context_endpoint="$($DOCKER_BIN context inspect "$context_name" --format '{{.Endpoints.docker.Host}}')"
effective_endpoint="${DOCKER_HOST:-$context_endpoint}"
case "$effective_endpoint" in
    unix://*) ;;
    *) echo "refusing non-Unix Docker endpoint: $effective_endpoint" >&2; exit 1 ;;
esac
docker_socket="${effective_endpoint#unix://}"
[[ -S "$docker_socket" ]] || {
    echo "local Docker socket is unavailable: $docker_socket" >&2
    exit 1
}
$DOCKER_BIN info >/dev/null

if [[ "$SELECTION" == all ]]; then
    SELECTED_IDS=("${PROFILE_IDS[@]}")
else
    SELECTED_IDS=()
    for candidate in "${PROFILE_IDS[@]}"; do
        [[ "$candidate" == "$SELECTION" ]] && SELECTED_IDS+=("$candidate")
    done
    (( ${#SELECTED_IDS[@]} == 1 )) || {
        echo "refusing unknown legacy scope profile: $SELECTION" >&2
        exit 64
    }
fi
readonly -a SELECTED_IDS
mkdir -p -- "$RUN_ROOT" "$WORK_ROOT"

profile_spec() {
    case "$1" in
        php-5.4.45-apache-surface)
            VERSION=5.4.45
            IMAGE='mirror.gcr.io/eugenesia/php@sha256:5681afdd0e07c7cbbece3f9cde77e5b7281768f54e1a2bbba319833c1ef638a9'
            IMAGE_ID='sha256:7cb054df8a5024e6fb9b2aba29568ec588103b0a56e67eff18cf02c9e62c0ea6'
            ;;
        php-5.5.38-apache-surface)
            VERSION=5.5.38
            IMAGE='mirror.gcr.io/library/php@sha256:be7f9332d3bea49084d74a0718a5400f7b5d128c1937575e76f72df3a41e8eac'
            IMAGE_ID='sha256:ea0a3d41ce6c99e1b96c335f3a9e616ecae62f1fabfdfdede51bb66b506d14ee'
            ;;
        php-5.6.40-apache-surface)
            VERSION=5.6.40
            IMAGE='mirror.gcr.io/library/php@sha256:0a40fd273961b99d8afe69a61a68c73c04bc0caa9de384d3b2dd9e7986eec86d'
            IMAGE_ID='sha256:24c791995c1e498255393db857040793a7a040fa0f8ddd4bbe8fb230648e37d7'
            ;;
        php-7.0.33-apache-surface)
            VERSION=7.0.33
            IMAGE='mirror.gcr.io/library/php@sha256:1d34b2e491a02ba7a8d26478132015e197a5ffea37f0a93b42621d11cfe042cc'
            IMAGE_ID='sha256:aa67a9c9814fb920a3aa01122b56010ddf1130710caf71a8871a0f1dbb4d78fd'
            ;;
        php-7.1.33-apache-surface)
            VERSION=7.1.33
            IMAGE='mirror.gcr.io/library/php@sha256:70eefcf4372b279101259e905996b7733a87688d0b48625af01b55947836bb1f'
            IMAGE_ID='sha256:b9858ffdd4d259fe208b6e5e4ae08f90c815dda98a7a8a45f3bf147485afaf4c'
            ;;
        php-7.2.34-apache-surface)
            VERSION=7.2.34
            IMAGE='mirror.gcr.io/library/php@sha256:4dc0f0115acf8c2f0df69295ae822e49f5ad5fe849725847f15aa0e5802b55f8'
            IMAGE_ID='sha256:c61d277263e19d2ce30a6bae41115c811eb0f9274a601a5e3ee621e54c8a74f7'
            ;;
        php-7.3.33-apache-surface)
            VERSION=7.3.33
            IMAGE='mirror.gcr.io/library/php@sha256:b9872cd287ef72bc17d45d713aa2742f3d3bcf2503fea2506fd93aa94995219f'
            IMAGE_ID='sha256:35da9118b3c0980fbaf84a4d410653642c9d55fb2f6c40011cc78de303837d64'
            ;;
        php-7.4.33-apache-surface)
            VERSION=7.4.33
            IMAGE='mirror.gcr.io/library/php@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d'
            IMAGE_ID='sha256:20a3732f422b7b28dcf99e8597f093a8c135efca62ff0dc02a2d92d916369413'
            ;;
        php-8.0.30-apache-surface)
            VERSION=8.0.30
            IMAGE='mirror.gcr.io/library/php@sha256:c87b4c94d53b35520467b6d026f38656ab9a6d446fa3a0fbba1bc633125f9ad2'
            IMAGE_ID='sha256:3357132d6ece3a509ce6f8abf6e7cf9886b343c504cb58428a7302cbe7abe446'
            ;;
        php-8.1.34-apache-surface)
            VERSION=8.1.34
            IMAGE='mirror.gcr.io/library/php@sha256:72f0c0134922985022d55a39b0390d35dc7a10e961aa6c44fa35b4c3102f4268'
            IMAGE_ID='sha256:e6c924c6e862e6c74e01be964f88cb0c7ccbd673925e9a648cbbf77ff53b7ca1'
            ;;
        *) echo "internal profile error: $1" >&2; return 1 ;;
    esac
    readonly VERSION IMAGE IMAGE_ID
}

ensure_image() {
    local reference=$1 expected_id=$2 inspect_path=$3
    if ! $DOCKER_BIN image inspect "$reference" >"$inspect_path" 2>/dev/null; then
        $DOCKER_BIN pull --quiet --platform linux/amd64 "$reference" >/dev/null
        $DOCKER_BIN image inspect "$reference" >"$inspect_path"
    fi
    local actual_id architecture os
    actual_id="$($DOCKER_BIN image inspect "$reference" --format '{{.Id}}')"
    architecture="$($DOCKER_BIN image inspect "$reference" --format '{{.Architecture}}')"
    os="$($DOCKER_BIN image inspect "$reference" --format '{{.Os}}')"
    [[ "$actual_id" == "$expected_id" ]] || {
        echo "image ID mismatch for $reference" >&2
        return 1
    }
    [[ "$architecture/$os" == amd64/linux ]] || {
        echo "image platform mismatch for $reference: $architecture/$os" >&2
        return 1
    }
}

run_profile() (
    set -Eeuo pipefail
    local profile_id=$1
    profile_spec "$profile_id"
    local artifact_dir="$RUN_ROOT/$profile_id"
    local scratch_dir
    scratch_dir="$(mktemp -d "$WORK_ROOT/${profile_id}.XXXXXX")"
    mkdir -p -- "$artifact_dir"

    local suffix="${RUN_ID//[^A-Za-z0-9_.-]/-}-${RANDOM}"
    local network_name="p2s-legacy-net-$suffix"
    local target_name="p2s-legacy-target-$suffix"
    local network_created=0 container_created=0
    cleanup_profile() {
        local rc=$?
        set +e
        (( container_created )) && $DOCKER_BIN rm -f "$target_name" >/dev/null 2>&1
        (( network_created )) && $DOCKER_BIN network rm "$network_name" >/dev/null 2>&1
        rm -rf -- "$scratch_dir"
        return "$rc"
    }
    trap cleanup_profile EXIT

    ensure_image "$IMAGE" "$IMAGE_ID" "$artifact_dir/image-inspect.json"
    $DOCKER_BIN network create --internal \
        --label org.php2shell.purpose=benign-legacy-scope-probe \
        "$network_name" >"$artifact_dir/network-id.txt"
    network_created=1
    $DOCKER_BIN network inspect "$network_name" >"$artifact_dir/network-inspect.json"
    [[ "$($DOCKER_BIN network inspect "$network_name" --format '{{.Internal}}')" == true ]]

    $DOCKER_BIN create --name "$target_name" --network "$network_name" \
        --pids-limit 128 --memory 384m --security-opt no-new-privileges \
        "$IMAGE" >"$artifact_dir/container-id.txt"
    container_created=1
    $DOCKER_BIN cp "$SCRIPT_DIR/index.php" "$target_name:/var/www/html/index.php"
    $DOCKER_BIN start "$target_name" >/dev/null
    $DOCKER_BIN inspect "$target_name" >"$artifact_dir/container-inspect.json"
    case "$($DOCKER_BIN inspect "$target_name" --format '{{json .HostConfig.PortBindings}}')" in
        null|'{}') ;;
        *) echo "target unexpectedly publishes a port" >&2; exit 1 ;;
    esac

    local target_ip
    target_ip="$($DOCKER_BIN inspect "$target_name" \
        --format "{{(index .NetworkSettings.Networks \"$network_name\").IPAddress}}")"
    python3 - "$target_ip" <<'PY'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
if not address.is_private:
    raise SystemExit("target did not receive a private Docker address")
PY

    $DOCKER_BIN exec "$target_name" php -r '
        printf("php_version=%s\n", PHP_VERSION);
        foreach (array("session.upload_progress.enabled", "session.upload_progress.cleanup", "session.upload_progress.freq", "session.upload_progress.min_freq", "session.save_path") as $key) {
            printf("%s=%s\n", $key, ini_get($key));
        }
    ' >"$artifact_dir/runtime.txt"
    grep -Fx "php_version=$VERSION" "$artifact_dir/runtime.txt" >/dev/null
    grep -Fx 'session.upload_progress.enabled=1' "$artifact_dir/runtime.txt" >/dev/null
    grep -Fx 'session.upload_progress.cleanup=1' "$artifact_dir/runtime.txt" >/dev/null

    local ready=0
    for _attempt in $(seq 1 50); do
        if timeout 1 bash -c "exec 3<>/dev/tcp/$target_ip/80" 2>/dev/null; then
            ready=1
            break
        fi
        sleep 0.1
    done
    (( ready )) || { echo "Apache did not become ready" >&2; exit 1; }

    local sid="${profile_id//[^A-Za-z0-9,-]/}"
    sid="${sid:0:40}"
    python3 "$SCRIPT_DIR/probe.py" \
        --host "$target_ip" --sid "$sid" --output "$artifact_dir/response.bin" &
    local client_pid=$!
    : >"$artifact_dir/session-during-upload.txt"
    local observed=0
    for attempt in $(seq 1 20); do
        if $DOCKER_BIN exec "$target_name" sh -c "test -f /tmp/sess_$sid"; then
            printf 'attempt=%s\n' "$attempt" >>"$artifact_dir/session-during-upload.txt"
            $DOCKER_BIN exec "$target_name" sh -c "cat /tmp/sess_$sid" \
                >>"$artifact_dir/session-during-upload.txt"
            printf '\n' >>"$artifact_dir/session-during-upload.txt"
            observed=1
            break
        fi
        sleep 0.2
    done
    wait "$client_pid"
    (( observed )) || { echo "pre-script progress record was not observed" >&2; exit 1; }

    $DOCKER_BIN exec "$target_name" sh -c \
        "if test -f /tmp/sess_$sid; then wc -c /tmp/sess_$sid; else echo SESSION_FILE_ABSENT; fi" \
        >"$artifact_dir/session-after-upload.txt"
    $DOCKER_BIN logs "$target_name" >"$artifact_dir/apache.log" 2>&1
    grep -q 'upload_progress_bounded' "$artifact_dir/session-during-upload.txt"
    grep -a -q 'SCRIPT_REACHED' "$artifact_dir/response.bin"
    grep -Eq '^(0 /tmp/sess_|SESSION_FILE_ABSENT$)' "$artifact_dir/session-after-upload.txt"

    cat >"$artifact_dir/result.txt" <<EOF
profile=$profile_id
php_version=$VERSION
image=$IMAGE
image_id=$IMAGE_ID
network_internal=true
published_ports=false
upload_progress_enabled=1
pre_script_progress_observed=true
script_reached=true
cleanup_observed=true
rce_tested=false
EOF
    (
        cd -- "$artifact_dir"
        sha256sum -- apache.log container-inspect.json image-inspect.json \
            network-inspect.json response.bin result.txt runtime.txt \
            session-after-upload.txt session-during-upload.txt >SHA256SUMS.txt
    )
    echo "$profile_id: SURFACE_CONFIRMED"
)

for profile_id in "${SELECTED_IDS[@]}"; do
    run_profile "$profile_id"
done
echo "artifacts: $RUN_ROOT"

