# PHP 8.0.30 HTTP-only RCE validation

작성일: 2026-10-24 (Asia/Seoul)

> [!CAUTION]
> 이 문서와 재현 코드는 보안 연구, 교육 및 방어 검증 전용입니다. 본인이
> 소유하거나 명시적으로 허가받은 격리 환경에서만 사용하세요. 게시용 runner는
> 외부 target과 임의 명령을 받지 않으며 proof 명령을 `id>/out/p`로 고정합니다.
> 공개 워게임 서버, 운영 서비스 또는 제3자 시스템에 적용하지 마세요.

## 결론

PHP 8.0.30의 아래 exact official Apache image에서 ASLR 주소 누출부터 고정 명령
실행까지 네 HTTP 요청으로 연결했다. 서로 다른 fresh target 세 개에서 HTTP
응답만으로 서로 다른 Zend MM main chunk와 `libphp` base를 복원했고, 모두
`zif_system`으로 다음 proof를 생성했다.

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

최종 성공 경로는 target의 `/proc/<pid>/maps`, `/proc/<pid>/mem`, GDB 또는 ptrace를
사용하지 않았다. 로컬 Docker host는 exact image와 격리 조건을 검사하며, 공통
runner가 `/proc/*/comm`을 읽는 목적은 single-worker 조건 확인뿐이다. 성공 여부는
매 실행 새로 만든 target container의 `/out` volume에 고정 proof가 생겼는지로
판정한다.

이 결과는 아래 fingerprint와 runtime이 모두 일치하는 exact build에 한정한다.
PHP 8.0 branch 전체, 다른 SAPI, 배포판 build 또는 다른 설정으로 일반화하지
않는다.

| 항목 | 검증 값 |
|---|---|
| Image | `mirror.gcr.io/library/php@sha256:c87b4c94d53b35520467b6d026f38656ab9a6d446fa3a0fbba1bc633125f9ad2` |
| Image ID | `sha256:3357132d6ece3a509ce6f8abf6e7cf9886b343c504cb58428a7302cbe7abe446` |
| Platform / SAPI | `linux/amd64`, Apache 2.4.56 prefork/mod_php, worker 1개 |
| PHP | `8.0.30`, non-ZTS |
| `libphp` SHA-256 | `0f2d31b76eb19814dc88e2a0cc7d57fe7f116168df8f8857fa9150fb5b5f7949` |
| `libphp` build ID | `22ea5e392e39c122039896feb5c9c52b75846581` |
| Symbols | `zif_system=0x3495d0`, `zval_ptr_dtor=0x4319a0` |
| Runtime | `memory_limit=108M`, `post_max_size=192M`, `upload_max_filesize=192M`, `max_input_vars=1000`, `display_errors=Off` |
| trans-SID prerequisites | `session.use_trans_sid=1`, `session.use_cookies=0`, `session.use_only_cookies=0`, `session.upload_progress.cleanup=1`, `url_rewriter.tags=a=href,area=href,frame=src,form=` |
| Proof command | `id>/out/p` |

## 네 요청의 상태 전이

### A1: `PS(id)`를 남기는 FILE_START OOM

첫 요청은 query field 5개, nested part 860개와 depth 64, 103/231-byte
content-type, 103-byte name의 small filler 14개를 먼저 배치한다. 이어
8,000-byte value의 large field 65개, 4,000-byte burner 20개, 1,216-byte pad,
4×3,000-byte·1×850-byte·12×128-byte pre-file scalar와 170/400-byte mix를
사용한다. 마지막 file part는 3,064-byte field name과 245,760-byte filename을
사용한다. 이 exact geometry가 `FILE_START` callback에서 Session ID를 복사한 뒤
OOM을 일으켜 raw `PS(id)` allocation을 Zend MM main chunk `+0x126260`에 남긴다.
A1은 HTTP 500을 반환한다.

이 offset은 위 exact runtime의 fresh runs에서 반복 확인했다. 다른 memory limit,
Apache worker 수 또는 allocator warm state에는 그대로 적용할 수 없다.

### B1: 4 MiB trans-SID leak으로 두 ASLR base 복원

두 번째 요청은 stale Session ID allocation을 회수해 길이를 `0x400000`으로
바꾼다. 294개의 forged page, head 13, partial flood 400 page, tail 2와 nested
field 900개를 사용하는 profile geometry다. PHP의 URL rewriter는 고정 local
`/next` link에 Session ID를 붙이고, parser는 index 12의 고정 prefix `/12BBBBB`와
정확한 4 MiB decoded length를 확인한다.

- leak `+0xd9d88`의 qword에서 2 MiB-aligned Zend MM main chunk를 복원한다.
- exact image의 `zval_ptr_dtor` offset `0x4319a0`을 사용해 반복되는 executable
  pointer 후보에서 `libphp` base를 구한다. 세 성공 실행 모두 같은 후보가 2,117회
  나타났고 profiled 최소값 100을 넘었다.

prefix, 길이, canonical address, main-chunk alignment와 반복 조건이 하나라도 맞지
않으면 중단한다. B1은 HTTP 200을 반환하며 target process memory를 읽지 않는다.

### A2: files state를 닫고 stale `zend_reference` 생성

세 번째 요청은 Session ID와 `pwn` upload-progress field, 64-byte file part를
먼저 보내 files handler를 정상적으로 닫은 다음 167,772,160-byte scalar body를
스트리밍한다. 108 MiB
memory limit에서 multipart END cleanup 전에 OOM이 발생한다. 이 PHP 8.0 exact
geometry는 64개의 filler를 사용하며 stale `zend_reference`를 main chunk
`+0x7d960`에 남긴다. A2는 HTTP 500을 반환한다.

32개 filler에서 관찰한 다른 offset은 실제 B2에서 small field-name allocation에
소비됐으므로 최종 profile에 사용하지 않는다. 64개 결과만 게시 proof set에
포함한다.

### B2: 짧은 Session ID와 고정 terminal reclaim

마지막 요청은 Session ID를 한 byte인 `a`로 고정한다. 더 긴 값은 PHP 8.0의
`PS_ID`/files-handler 48-byte allocation class와 충돌하므로 이 profile에 사용할
수 없다. B2는 4-byte field name과 4,071-byte value를 가진 controlled field
400개를 spray한다. 각 value는 main chunk `+0x7d960`의 fake
`zend_reference`, 같은 page `+0x7d800`의 fake `HashTable`, HTTP에서 얻은
`libphp` base에 `0x3495d0`을 더한 `zif_system`을 포함한다.

```text
php_session_track_init
  -> zend_reference_destroy
  -> zend_array_destroy
  -> zend_hash_destroy
  -> zif_system("id>/out/p")
```

B2는 고정 명령을 실행해 proof를 쓴 뒤 worker가 crash하며 connection이 닫혀
정상 HTTP status를 반환하지 않는다. 따라서 HTTP 응답의 부재를 성공으로 취급하지
않는다. 새 `/out` volume의 `/out/p`가 존재하고 `uid=<number>` 형식을 만족할 때만
성공으로 판정한다. 세 실행 모두 정확한 `www-data` proof를 만들었다.

## 최종 세 fresh-ASLR 실행

| Artifact | HTTP-derived main chunk | HTTP-derived `libphp` base | dtor hits | HTTP 상태 | 결과 |
|---|---:|---:|---:|---|---|
| `b2-root-fill64-7d960-1` | `0x7b34f1200000` | `0x7b34f1678000` | 2,117 | A1 500, B1 200, A2 500, B2 no status | proof 생성 |
| `b2-root-fill64-7d960-2` | `0x70e9f8800000` | `0x70e9f8bce000` | 2,117 | A1 500, B1 200, A2 500, B2 no status | proof 생성 |
| `b2-root-fill64-7d960-3` | `0x74260e200000` | `0x74260e62b000` | 2,117 | A1 500, B1 200, A2 500, B2 no status | proof 생성 |

서로 다른 세 ASLR base에서 같은 profile-relative offsets로 proof를 만든 결과는
주소를 HTTP leak에서 동적으로 복원했음을 확인한다. 원시 leak와 response는 host
경로 등 불필요한 실행 정보를 포함하므로 저장소에는 sanitized proof record만
게시한다.

세 fresh-ASLR 검증 세트와 별도로, 공개용 표준 runner에 profile을 통합한 뒤
`20261023T180015Z-636870` 회귀 실행도 exit 0과 같은 `www-data` proof로
통과했다. 이 회귀 실행은 profile의 검증 횟수 3에 추가하지 않는다.

## 기존 locally calibrated lab과의 관계

기존 [`legacy-calibrated-rce/raw-key-partial-bucket`](../poc/legacy-calibrated-rce/raw-key-partial-bucket/)
lab은 partial `Bucket`과 fake `HashTable`을 이용해 terminal primitive를 먼저
확인한 historical 재현기다. 로컬 root가 `/proc`에서 heap과 libc base를 공급하므로
remote ASLR bypass를 입증하지 않는다. 새 HTTP-only chain은 별도 108 MiB
FILE_START/trans-SID geometry로 Zend MM main chunk와 `libphp` base를 HTTP에서
얻는다.

두 경로의 terminal symbol, heap layout과 runtime은 서로 호환되지 않는다. 기존
lab은 개발 이력과 독립 primitive 증거로 보존하고, standalone 재현에는 exact
HTTP-only profile을 사용한다.

## 공개 범위와 한계

- target은 위 immutable image digest와 image ID로 고정한다.
- target과 attacker는 새 Docker `--internal` network에서만 실행하고 host port를
  공개하지 않는다.
- 외부 URL, 임의 image, address override 또는 command option을 제공하지 않는다.
- payload 명령은 `id>/out/p`로 고정하며 interactive shell이나 persistence를
  제공하지 않는다.
- 성공은 새 proof volume의 파일로만 판정한다. B2의 connection close나 worker
  crash 자체는 성공 증거가 아니다.
- B2 이후 worker crash는 관찰된 가용성 영향이며 운영 서비스에서 시험하면 안 된다.
- exact profile이 없는 다른 PHP 8.0 build, branch, SAPI 또는 설정에 대한 동작을
  주장하지 않는다.

PHP 8.0은 EOL이며 PHP 프로젝트가 별도의 최소 source mitigation을 제공했다.
운영 환경은 이 exact PoC의 성공 여부와 관계없이 유지보수되는 수정 릴리스로
업그레이드하거나 배포판/LTS 공급자의 검증된 backport를 적용해야 한다.
