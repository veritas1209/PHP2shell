#!/usr/bin/env bash
set -Eeuo pipefail

if (( $# != 1 )) || [[ ! $1 =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo 'usage: run-http-only.sh LABEL' >&2
  exit 64
fi

readonly LABEL=$1
readonly IMAGE='mirror.gcr.io/library/php@sha256:0a40fd273961b99d8afe69a61a68c73c04bc0caa9de384d3b2dd9e7986eec86d'
readonly IMAGE_ID='sha256:24c791995c1e498255393db857040793a7a040fa0f8ddd4bbe8fb230648e37d7'
readonly ATTACKER='python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704'
readonly ATTACKER_ID='sha256:a33c10a97f11005523814c6eee013986119fe41f3122f444518117536675c8e1'
readonly HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly OUT="$HERE/results/$LABEL"
readonly TARGET="p56-mb-$LABEL-target"
readonly NETWORK="p56-mb-$LABEL-net"
readonly VOLUME="p56-mb-$LABEL-out"

if command -v docker >/dev/null 2>&1; then DOCKER="$(command -v docker)";
elif [[ -x /snap/bin/docker ]]; then DOCKER=/snap/bin/docker;
else echo 'docker CLI was not found' >&2; exit 69; fi
readonly DOCKER

test "$($DOCKER image inspect "$IMAGE" --format '{{.Id}}')" = "$IMAGE_ID"
test "$($DOCKER image inspect "$ATTACKER" --format '{{.Id}}')" = "$ATTACKER_ID"
test ! -e "$OUT"
mkdir -p "$OUT/client"
chmod 0777 "$OUT/client"

cleanup() {
  set +e
  $DOCKER logs "$TARGET" >"$OUT/target.log" 2>&1
  $DOCKER inspect "$TARGET" >"$OUT/target.inspect.json" 2>/dev/null
  $DOCKER network inspect "$NETWORK" >"$OUT/network.inspect.json" 2>/dev/null
  $DOCKER image inspect "$IMAGE" >"$OUT/target-image.inspect.json" 2>/dev/null
  $DOCKER image inspect "$ATTACKER" >"$OUT/attacker-image.inspect.json" 2>/dev/null
  $DOCKER rm -f "$TARGET" >/dev/null 2>&1
  $DOCKER network rm "$NETWORK" >/dev/null 2>&1
  $DOCKER volume rm "$VOLUME" >/dev/null 2>&1
}
trap cleanup EXIT

$DOCKER network create --internal \
  --label org.php2shell.purpose=isolated-research "$NETWORK" >/dev/null
$DOCKER volume create \
  --label org.php2shell.purpose=isolated-proof "$VOLUME" >/dev/null
$DOCKER create --name "$TARGET" --network "$NETWORK" \
  --network-alias php2shell-56-target --memory 512m --pids-limit 64 \
  --mount "type=bind,src=$HERE/producer.php,dst=/var/www/html/producer.php,readonly" \
  --mount "type=bind,src=$HERE/warm.php,dst=/var/www/html/warm.php,readonly" \
  --mount "type=bind,src=$HERE/leak.php,dst=/var/www/html/leak.php,readonly" \
  --mount "type=bind,src=$HERE/terminal.php,dst=/var/www/html/terminal.php,readonly" \
  --mount "type=bind,src=$HERE/php108-trans.ini,dst=/usr/local/etc/php/conf.d/zz-ze2-http.ini,readonly" \
  --mount "type=bind,src=$HERE/apache.conf,dst=/etc/apache2/conf-enabled/zz-ze2-lab.conf,readonly" \
  --mount "type=bind,src=$HERE/route56.conf,dst=/etc/apache2/conf-enabled/zz-ze2-routes.conf,readonly" \
  --mount "type=volume,src=$VOLUME,dst=/out" \
  "$IMAGE" sh -eu -c \
    'mkdir -p /out; chown 33:33 /out; chmod 0770 /out; rm -f /out/p; exec apache2-foreground' \
  >/dev/null
$DOCKER start "$TARGET" >/dev/null

for _ in {1..50}; do
  $DOCKER exec "$TARGET" php -r 'echo PHP_VERSION;' >/dev/null 2>&1 && break
  sleep 0.1
done
test "$($DOCKER exec "$TARGET" php -r 'echo PHP_VERSION;')" = 5.6.40
test "$($DOCKER inspect "$TARGET" --format '{{json .HostConfig.PortBindings}}')" = '{}'
test "$($DOCKER network inspect "$NETWORK" --format '{{.Internal}}')" = true
test -z "$($DOCKER inspect "$TARGET" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^LD_PRELOAD=' || true)"

set +e
$DOCKER run --rm --network "$NETWORK" --read-only --user 65532:65532 \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --pids-limit 64 --memory 512m \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --mount "type=bind,src=$HERE,dst=/lab,readonly" \
  --mount "type=bind,src=$OUT/client,dst=/results" \
  "$ATTACKER" python3 /lab/http_only56_mbstring.py --out /results \
  --rollover-delay 1.0 --terminal-target-index 25 \
  >"$OUT/client.log" 2>&1
client_rc=$?
set -e
printf '%s\n' "$client_rc" >"$OUT/client.exit"
sleep 0.5
$DOCKER cp "$TARGET:/out/p" "$OUT/proof.txt" >/dev/null 2>&1 || \
  echo NO_PROOF >"$OUT/proof.txt"
cat "$OUT/client.log"
cat "$OUT/client/address-source.json" 2>/dev/null || true
cat "$OUT/proof.txt"
grep -Eq '^uid=33\(www-data\) gid=33\(www-data\)' "$OUT/proof.txt"
