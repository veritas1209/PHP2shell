#!/usr/bin/env bash
set -Eeuo pipefail

if (( $# != 1 )) || [[ ! $1 =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo 'usage: run-http-only.sh LABEL' >&2
  exit 64
fi

readonly LABEL=$1
readonly HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly OUT="$HERE/results/$LABEL"
readonly IMAGE='mirror.gcr.io/eugenesia/php@sha256:5681afdd0e07c7cbbece3f9cde77e5b7281768f54e1a2bbba319833c1ef638a9'
readonly IMAGE_ID='sha256:7cb054df8a5024e6fb9b2aba29568ec588103b0a56e67eff18cf02c9e62c0ea6'
readonly ATTACKER='python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704'
readonly ATTACKER_ID='sha256:a33c10a97f11005523814c6eee013986119fe41f3122f444518117536675c8e1'
readonly TARGET="p54-http-$LABEL-target"
readonly NETWORK="p54-http-$LABEL-net"
readonly VOLUME="p54-http-$LABEL-out"

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
  $DOCKER top "$TARGET" -eo pid,ppid,user,args >"$OUT/docker-top.txt" 2>&1
  $DOCKER network inspect "$NETWORK" >"$OUT/network.inspect.json" 2>/dev/null
  $DOCKER logs "$TARGET" >"$OUT/target.log" 2>&1
  $DOCKER inspect "$TARGET" >"$OUT/target.inspect.json" 2>/dev/null
  $DOCKER rm -f "$TARGET" >/dev/null 2>&1
  $DOCKER network rm "$NETWORK" >/dev/null 2>&1
  $DOCKER volume rm "$VOLUME" >/dev/null 2>&1
}
trap cleanup EXIT

$DOCKER network create --internal --label org.php2shell.purpose=isolated-research "$NETWORK" >/dev/null
$DOCKER volume create --label org.php2shell.purpose=isolated-proof "$VOLUME" >/dev/null
$DOCKER create --name "$TARGET" --network "$NETWORK" \
  --network-alias php2shell-56-target --network-alias php2shell-72-target \
  --memory 512m --pids-limit 64 \
  --mount "type=bind,src=$HERE/producer.php,dst=/var/www/html/producer.php,readonly" \
  --mount "type=bind,src=$HERE/warm.php,dst=/var/www/html/warm.php,readonly" \
  --mount "type=bind,src=$HERE/reflect.php,dst=/var/www/html/reflect.php,readonly" \
  --mount "type=bind,src=$HERE/terminal.php,dst=/var/www/html/terminal.php,readonly" \
  --mount "type=bind,src=$HERE/php.ini,dst=/usr/local/etc/php/conf.d/zz-ze2-http.ini,readonly" \
  --mount "type=bind,src=$HERE/apache.conf,dst=/etc/apache2/conf-enabled/zz-ze2-lab.conf,readonly" \
  --mount "type=bind,src=$HERE/route.conf,dst=/etc/apache2/conf-enabled/zz-ze2-routes.conf,readonly" \
  --mount "type=volume,src=$VOLUME,dst=/out" \
  "$IMAGE" sh -eu -c 'mkdir -p /out; chown 33:33 /out; chmod 0770 /out; rm -f /out/p; exec apache2-foreground' >/dev/null
$DOCKER start "$TARGET" >/dev/null
for _ in {1..50}; do
  $DOCKER exec "$TARGET" php -r 'echo PHP_VERSION;' >/dev/null 2>&1 && break
  sleep 0.1
done
test "$($DOCKER exec "$TARGET" php -r 'echo PHP_VERSION;')" = 5.4.45
test "$($DOCKER inspect "$TARGET" --format '{{json .HostConfig.PortBindings}}')" = '{}'
test "$($DOCKER network inspect "$NETWORK" --format '{{.Internal}}')" = true

set +e
$DOCKER run --rm --network "$NETWORK" --read-only --user 65532:65532 \
  --security-opt no-new-privileges:true --cap-drop ALL --pids-limit 64 --memory 512m \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --mount "type=bind,src=$HERE,dst=/chain,readonly" \
  --mount "type=bind,src=$OUT/client,dst=/results" \
  "$ATTACKER" sh -c 'PYTHONPATH=/chain exec python3 /chain/http_only54.py --out /results' \
  >"$OUT/client.log" 2>&1
client_rc=$?
set -e
printf '%s\n' "$client_rc" >"$OUT/client.exit"
sleep 0.5
$DOCKER cp "$TARGET:/out/p" "$OUT/proof.txt" >/dev/null 2>&1 || echo NO_PROOF >"$OUT/proof.txt"
cat "$OUT/client.log"
cat "$OUT/proof.txt"
grep -Eq '^uid=33\(www-data\) gid=33\(www-data\)' "$OUT/proof.txt"
