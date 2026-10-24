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
readonly OUT="$RESULTS/full-$LABEL"
readonly IMAGE='php@sha256:4dc0f0115acf8c2f0df69295ae822e49f5ad5fe849725847f15aa0e5802b55f8'
readonly IMAGE_ID='sha256:c61d277263e19d2ce30a6bae41115c811eb0f9274a601a5e3ee621e54c8a74f7'
readonly ATTACKER='python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704'
readonly ATTACKER_ID='sha256:a33c10a97f11005523814c6eee013986119fe41f3122f444518117536675c8e1'
readonly TARGET="p72-http-$LABEL-target"
readonly NETWORK="p72-http-$LABEL-net"
readonly VOLUME="p72-http-$LABEL-out"

if command -v docker >/dev/null 2>&1; then DOCKER="$(command -v docker)";
elif [[ -x /snap/bin/docker ]]; then DOCKER=/snap/bin/docker;
else echo 'docker CLI was not found' >&2; exit 69; fi
readonly DOCKER

test "$($DOCKER image inspect "$IMAGE" --format '{{.Id}}')" = "$IMAGE_ID"
test "$($DOCKER image inspect "$ATTACKER" --format '{{.Id}}')" = "$ATTACKER_ID"
test ! -e "$OUT"
mkdir -p "$RESULTS"
chmod 0777 "$RESULTS"

cleanup() {
  set +e
  mkdir -p "$OUT"
  if $DOCKER exec "$TARGET" test -r /out/p >/dev/null 2>&1; then
    $DOCKER exec "$TARGET" cat /out/p >"$OUT/proof.txt" 2>/dev/null
  else
    echo NO_PROOF >"$OUT/proof.txt"
  fi
  $DOCKER top "$TARGET" -eo pid,ppid,user,comm >"$OUT/workers.after.txt" 2>/dev/null
  $DOCKER logs "$TARGET" >"$OUT/target.log" 2>&1
  $DOCKER inspect "$TARGET" >"$OUT/target.inspect.json" 2>/dev/null
  $DOCKER network inspect "$NETWORK" >"$OUT/network.inspect.json" 2>/dev/null
  $DOCKER rm -f "$TARGET" >/dev/null 2>&1
  $DOCKER network rm "$NETWORK" >/dev/null 2>&1
  $DOCKER volume rm "$VOLUME" >/dev/null 2>&1
}
trap cleanup EXIT

$DOCKER network create --internal --label org.php2shell.purpose=isolated-research "$NETWORK" >/dev/null
$DOCKER volume create --label org.php2shell.purpose=fixed-proof "$VOLUME" >/dev/null
$DOCKER run -d --name "$TARGET" --network "$NETWORK" \
  --network-alias target --network-alias php2shell-72-target \
  --security-opt no-new-privileges:true --pids-limit 64 --memory 512m \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --mount "type=bind,src=$HERE/php108.ini,dst=/usr/local/etc/php/conf.d/zz-php72-http.ini,readonly" \
  --mount "type=bind,src=$HERE/apache.conf,dst=/etc/apache2/conf-enabled/zz-php72-http.conf,readonly" \
  --mount "type=bind,src=$HERE/index.php,dst=/var/www/html/index.php,readonly" \
  --mount "type=bind,src=$HERE/terminal.php,dst=/var/www/html/terminal.php,readonly" \
  --mount "type=volume,src=$VOLUME,dst=/out" \
  "$IMAGE" sh -eu -c 'chown www-data:www-data /out; rm -f /out/p; exec apache2-foreground' >/dev/null

for _ in {1..100}; do
  $DOCKER exec "$TARGET" php -r 'echo PHP_VERSION;' >/dev/null 2>&1 && break
  sleep 0.1
done
test "$($DOCKER exec "$TARGET" php -r 'echo PHP_VERSION;')" = 7.2.34
test "$($DOCKER inspect "$TARGET" --format '{{.Image}}')" = "$IMAGE_ID"
test "$($DOCKER inspect "$TARGET" --format '{{json .HostConfig.PortBindings}}')" = '{}'
test "$($DOCKER network inspect "$NETWORK" --format '{{.Internal}}')" = true
test "$($DOCKER exec "$TARGET" sha256sum /usr/lib/apache2/modules/libphp7.so | awk '{print $1}')" = \
  aff83b482039f672ef675ceaa82dde09521a72a6ce569b4dcf5e1f54f5b7503c

$DOCKER top "$TARGET" -eo pid,ppid,user,comm >"$RESULTS/full-$LABEL.workers.before.tmp"
set +e
$DOCKER run --rm --network "$NETWORK" --user 65532:65532 --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 64 --memory 512m --read-only --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --mount "type=bind,src=$HARNESS,dst=/harness,readonly" \
  --mount "type=bind,src=$HERE,dst=/lab,readonly" \
  --mount "type=bind,src=$RESULTS,dst=/results" \
  --workdir /lab "$ATTACKER" python3 /lab/full_chain72.py --label "$LABEL" \
  >"$RESULTS/full-$LABEL.client.tmp" 2>&1
client_rc=$?
set -e

mkdir -p "$OUT"
mv "$RESULTS/full-$LABEL.client.tmp" "$OUT/client.log"
mv "$RESULTS/full-$LABEL.workers.before.tmp" "$OUT/workers.before.txt"
cat >"$OUT/runtime.txt" <<EOF
image=$IMAGE
image_id=$IMAGE_ID
php=7.2.34
libphp_sha256=aff83b482039f672ef675ceaa82dde09521a72a6ce569b4dcf5e1f54f5b7503c
network_internal=true
port_bindings={}
address_source=http-b1-only
proc_or_debugger_used=false
fixed_command=id>/out/p
max_connections_per_child=4
client_rc=$client_rc
EOF

proof_verified=false
for _ in {1..40}; do
  if $DOCKER exec "$TARGET" test -s /out/p >/dev/null 2>&1; then
    proof_verified=true
    break
  fi
  sleep 0.1
done
if [[ $proof_verified == true ]]; then
  proof_text="$($DOCKER exec "$TARGET" cat /out/p 2>/dev/null || true)"
  [[ $proof_text =~ ^uid=[0-9]+\(.+\)[[:space:]]gid=[0-9]+\(.+\) ]] || proof_verified=false
fi
printf 'proof_verified=%s\n' "$proof_verified" >>"$OUT/runtime.txt"
cat "$OUT/client.log"
(( client_rc == 0 )) || exit "$client_rc"
[[ $proof_verified == true ]] || { echo 'fixed proof command did not produce a uid record' >&2; exit 70; }
