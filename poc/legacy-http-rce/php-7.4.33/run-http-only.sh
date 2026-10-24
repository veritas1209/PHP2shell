#!/usr/bin/env bash
set -Eeuo pipefail

if (( $# != 1 )) || [[ ! $1 =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo 'usage: run-http-only.sh LABEL' >&2
  exit 64
fi

readonly LABEL=$1
readonly HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HARNESS="$(cd -- "$HERE/../../multiversion" && pwd)"
readonly RESULTS="$HERE/results"
readonly IMAGE='mirror.gcr.io/library/php@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d'
readonly IMAGE_ID='sha256:20a3732f422b7b28dcf99e8597f093a8c135efca62ff0dc02a2d92d916369413'
readonly ATTACKER='python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704'
readonly ATTACKER_ID='sha256:a33c10a97f11005523814c6eee013986119fe41f3122f444518117536675c8e1'
readonly TARGET="p74-http-$LABEL-target"
readonly NETWORK="p74-http-$LABEL-net"
readonly VOLUME="p74-http-$LABEL-out"

if command -v docker >/dev/null 2>&1; then
  DOCKER="$(command -v docker)"
elif [[ -x /snap/bin/docker ]]; then
  DOCKER=/snap/bin/docker
else
  echo 'docker CLI was not found' >&2
  exit 69
fi
readonly DOCKER

test "$($DOCKER image inspect "$IMAGE" --format '{{.Id}}')" = "$IMAGE_ID"
test "$($DOCKER image inspect "$ATTACKER" --format '{{.Id}}')" = "$ATTACKER_ID"
test ! -e "$RESULTS/$LABEL"
mkdir -p "$RESULTS"
chmod 0777 "$RESULTS"

cleanup() {
  set +e
  $DOCKER logs "$TARGET" >"$RESULTS/$LABEL.target.log" 2>&1
  $DOCKER inspect "$TARGET" >"$RESULTS/$LABEL.target.inspect.json" 2>/dev/null
  $DOCKER network inspect "$NETWORK" >"$RESULTS/$LABEL.network.inspect.json" 2>/dev/null
  $DOCKER rm -f "$TARGET" >/dev/null 2>&1
  $DOCKER network rm "$NETWORK" >/dev/null 2>&1
  $DOCKER volume rm "$VOLUME" >/dev/null 2>&1
}
trap cleanup EXIT

$DOCKER network create --internal --label org.php2shell.purpose=isolated-research "$NETWORK" >/dev/null
$DOCKER volume create --label org.php2shell.purpose=fixed-proof "$VOLUME" >/dev/null
$DOCKER create \
  --name "$TARGET" --network "$NETWORK" --network-alias target \
  --security-opt no-new-privileges:true --pids-limit 64 --memory 512m \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --mount "type=bind,src=$HERE/php108.ini,dst=/usr/local/etc/php/conf.d/zz-php74-http.ini,readonly" \
  --mount "type=bind,src=$HERE/apache.conf,dst=/etc/apache2/conf-enabled/zz-php74-http.conf,readonly" \
  --mount "type=bind,src=$HERE/index.php,dst=/var/www/html/index.php,readonly" \
  --mount "type=volume,src=$VOLUME,dst=/out" \
  "$IMAGE" sh -eu -c 'chown www-data:www-data /out; rm -f /out/p; exec apache2-foreground' >/dev/null
$DOCKER start "$TARGET" >/dev/null
sleep 1
test "$($DOCKER exec "$TARGET" php -r 'echo PHP_VERSION;')" = 7.4.33
test "$($DOCKER inspect "$TARGET" --format '{{json .HostConfig.PortBindings}}')" = '{}'
test "$($DOCKER network inspect "$NETWORK" --format '{{.Internal}}')" = true

set +e
$DOCKER run --rm \
  --network "$NETWORK" --user 65532:65532 --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 64 --memory 512m --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --mount "type=bind,src=$HARNESS,dst=/harness,readonly" \
  --mount "type=bind,src=$HERE,dst=/research,readonly" \
  --mount "type=bind,src=$RESULTS,dst=/results" \
  --mount "type=volume,src=$VOLUME,dst=/proof,readonly" \
  --workdir /research "$ATTACKER" \
  python3 /research/full_chain.py "$LABEL" \
  | tee "$RESULTS/$LABEL.stdout"
client_status=${PIPESTATUS[0]}
set -e
sleep 1
$DOCKER run --rm --read-only --mount "type=volume,src=$VOLUME,dst=/proof,readonly" \
  --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges:true \
  "$ATTACKER" sh -eu -c 'if test -r /proof/p; then cat /proof/p; else echo NO_PROOF; fi' \
  >"$RESULTS/$LABEL.proof.txt"
printf '%s\n' "$client_status" >"$RESULTS/$LABEL.exit"
cat "$RESULTS/$LABEL.proof.txt"
grep -Eq '^uid=33\(www-data\) gid=33\(www-data\)' "$RESULTS/$LABEL.proof.txt"
exit "$client_status"
