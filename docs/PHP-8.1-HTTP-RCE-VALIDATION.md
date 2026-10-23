# PHP 8.1.34 HTTP-only RCE validation

작성일: 2026-10-24 (Asia/Seoul)

> [!CAUTION]
> 이 문서와 재현 코드는 보안 연구, 교육 및 방어 검증 전용입니다. 본인이
> 소유하거나 명시적으로 허가받은 격리 환경에서만 사용하세요. 게시용 runner는
> 외부 target과 임의 명령을 받지 않으며 proof 명령을 `id>/out/p`로 고정합니다.

## 결론

PHP 8.1.34의 exact official Apache image에서 ASLR 주소 누출부터 고정 명령
실행까지 네 HTTP 요청으로 연결했다. 강화된 최종 allow-listed runner를 서로 다른
fresh target 세 개에서 실행해 각각 다른 heap과 `libphp` 주소를 얻었고, 모두
`zif_system`으로 다음 proof를 생성했다.

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

이 검증의 주소는 target의 HTTP 응답에서만 복원했다. 성공 경로는
`/proc/<pid>/maps`, `/proc/<pid>/mem`, GDB 또는 ptrace를 사용하지 않았다. 로컬
Docker host는 exact image와 격리 조건을 검사하고, common runner는 single-worker
조건 확인에만 `/proc/*/comm`을 읽는다. target container의 새 `/out` volume에서는
고정 proof 파일만 읽는다.

이 결과는 아래 fingerprint와 runtime이 일치하는 exact build의 재현 결과다. PHP
8.1 branch 전체, 다른 SAPI, 배포판 build 또는 다른 설정으로 일반화하지 않는다.

| 항목 | 검증 값 |
|---|---|
| Image | `mirror.gcr.io/library/php@sha256:72f0c0134922985022d55a39b0390d35dc7a10e961aa6c44fa35b4c3102f4268` |
| Image ID | `sha256:e6c924c6e862e6c74e01be964f88cb0c7ccbd673925e9a648cbbf77ff53b7ca1` |
| Platform / SAPI | `linux/amd64`, Apache prefork/mod_php, worker 1개 |
| PHP | `8.1.34`, non-ZTS |
| Runtime | `memory_limit=128M`, `post_max_size=192M`, `upload_max_filesize=192M`, `max_input_vars=1000`, `display_errors=Off` |
| trans-SID prerequisites | `session.use_trans_sid=1`, `session.use_cookies=0`, `session.use_only_cookies=0`, `session.upload_progress.cleanup=1`, `url_rewriter.tags=a=href,area=href,frame=src,form=` |
| Proof command | `id>/out/p` |

## 네 요청의 상태 전이

### A1: `PS(id)`를 남기는 FILE_START OOM

첫 multipart 요청은 마지막 file part의 `FILE_START` callback에서 Session ID를
복사한 뒤, upload-progress용 `current_file` 문자열을 만들다가 OOM을 일으킨다.
ordinary session initialization보다 먼저 중단되므로 `PS(id)`는 남고
`PS(mod_data)`는 `NULL`이다. 이 조건은 다음 요청에서 stale files handler를
닫다가 먼저 충돌하는 경로를 제거한다.

남은 Session ID의 주소는 Zend MM 2 MiB chunk 안에서 `+0x1fa120`이다. 이 offset은
fresh-ASLR trace 세 번에서 같았다. GDB trace는 생산자 geometry를 개발하는 동안
상태 전이를 확인하는 데 사용했지만, 아래 end-to-end 성공 실행과 게시용 runner에는
포함되지 않는다.

### B1: trans-SID로 heap과 `libphp` 주소 누출

두 번째 multipart 요청은 stale Session ID allocation을 회수하고 길이 필드를
`0x1c0000`으로 바꾼다. PHP의 trans-SID URL rewrite가 이 값을 HTTP 응답에
percent-encoding해 넣는다. 이 profile에서만 target은 고정 local link
`<a href="/next">LOCAL-LINK</a>`를 출력하는 `lab/index-trans-sid.php`를 mount한다.
PHP의 URL rewriter가 해당 link에 Session ID를 붙이며, 외부 URL이나 사용자 입력은
포함되지 않는다. 파서는 고정 prefix `/14BBBBB`와 정확한 누출 길이를 확인한 뒤 두
독립 표식을 사용한다.

- 누출 `+0x5ec8`의 qword는 Zend MM main chunk `+0x40`을 가리킨다. 2 MiB
  alignment를 확인한 뒤 `0x40`을 빼 main chunk base를 얻는다.
- exact image의 `zval_ptr_dtor` offset은 `libphp+0x457150`이다. 누출에서 같은
  page-aligned 후보가 623회 나타났고, 각 실행의 runner-up 후보는 1회뿐이었다.
  이 주소에서 `0x457150`을 빼 `libphp` base를 얻는다.

파서는 prefix, 길이, canonical userspace 범위, main-chunk alignment, 최소 반복
횟수와 후보 유일성을 모두 만족하지 않으면 중단한다. HTTP framing도 중복되거나
지원하지 않는 `Transfer-Encoding`, 잘못된 `Content-Length`, 불완전한 zero chunk와
허용된 trailer 뒤 후행 데이터를 거부한다.

### A2: files state를 닫고 stale `zend_reference` 생성

세 번째 요청은 Session ID와 upload-progress field를 먼저 보내고 file part를
시작한다. 첫 update가 `php_session_flush(1)`을 거쳐 files handler를 정상적으로
닫아 `PS(mod_data)=NULL`로 만든다. 이어지는 160 MiB scalar body를 스트리밍하다
PHP의 128 MiB memory limit에서 OOM이 발생한다. multipart END cleanup 전 bailout이
일어나면서 `PS(http_session_vars)`의 `zend_reference`가 main chunk
`+0x74160`에 남는다.

client는 큰 body를 한 번 더 메모리에 복사하지 않고 socket으로 스트리밍한다.
요청은 `post_max_size`보다 작고 `memory_limit`보다 충분히 커야 하므로 이 geometry는
위 runtime fingerprint에 묶인다.

### B2: 고정 명령 terminal reclaim

마지막 요청은 4 KiB allocation 400개로 stale reference page를 회수한다. 각
controlled value에는 `main+0x74160`의 fake `zend_reference`와 같은 page
`+0x74800`의 fake `HashTable`이 들어 있다. fake destructor는 HTTP에서 얻은
`libphp` base에 exact image offset `0x36f470`을 더한 `zif_system`이다.

```text
php_session_track_init
  -> zend_reference_destroy
  -> zend_array_destroy
  -> zend_hash_destroy
  -> zif_system("id>/out/p")
```

payload는 고정 문자열 `id>/out/p`만 포함하며 URL, host, image, address 또는 command
입력을 받지 않는다.

B2는 proof 파일을 쓴 뒤 해당 Apache worker가 SIGSEGV로 종료되며 Apache error
log에 `AH00052`가 남는다. 요청이 정상 종료되지 않으므로 네 번째 POST의 access-log
행도 남지 않는다. proof 생성은 명령 실행을 입증하지만 worker crash라는 가용성
영향을 동반한다.

## 최종 `zif_system` runner 결과

| Run ID | HTTP-derived main chunk | HTTP-derived `libphp` base | dtor hits | 결과 |
|---|---:|---:|---:|---|
| `20261023T163513Z-200322` | `0x7b3636200000` | `0x7b3637d91000` | 623 | `zif_system` proof 생성 |
| `20261023T163537Z-203897` | `0x75d685400000` | `0x75d687057000` | 623 | `zif_system` proof 생성 |
| `20261023T163602Z-207516` | `0x7fa812400000` | `0x7fa81402f000` | 623 | `zif_system` proof 생성 |

세 실행에서 B1 leak 길이는 모두 `0x1c0000`이었고, A2는 167,775,191-byte body를
끝까지 스트리밍했다. HTTP 상태는 모두 A1 500, B1 200, A2 500이었다. B2가 계산한
`zif_system`과 stale reference 주소는 각 실행의 서로 다른 ASLR base에서
일관되게 바뀌었다. 다섯 trans-SID prerequisite가 profile과 정확히 일치했고,
각 실행의 artifact `SHA256SUMS.txt` 검증과 container, network, volume cleanup도
통과했다.

## 개발 실행과 최종 proof의 구분

최종 profile을 만들기 전 같은 128 MiB producer/disclosure geometry를 조정한 세
HTTP-only 개발 실행은 terminal 함수를 `zif_passthru`(`libphp+0x36f480`)로 두었다.
그 결과는 주소 복구와 terminal primitive의 개발 이력일 뿐이며 위 최종
`zif_system` 3/3 proof 수와 주소에는 포함하지 않았다. 게시 profile의 terminal
offset `0x36f470`과 검증 횟수는 위 세 allow-listed runner 실행만 근거로 한다.

## 기존 locally calibrated lab과의 관계

기존 [`legacy-calibrated-rce/php-8.1.34`](../poc/legacy-calibrated-rce/php-8.1.34/)
lab은 8 MiB runtime에서 같은 terminal primitive를 먼저 검증한 역사적 재현기다.
그 runner는 로컬 root가 `/proc`에서 heap과 `libphp` base를 공급하므로 remote ASLR
bypass를 입증하지 않는다. 새 HTTP-only chain은 128 MiB runtime의 별도 producer와
trans-SID disclosure를 사용해 두 주소를 HTTP 응답에서 얻는다.

두 경로의 heap geometry와 runtime은 호환되지 않는다. 기존 lab을 삭제하거나 그
결과를 새 chain의 증거로 재해석하지 않는다. 새 재현에는 HTTP-only runner를
사용하고, 기존 runner는 terminal primitive의 개발 이력과 독립 증거로 보존한다.

## 공개 범위와 한계

- target은 immutable image digest로 고정한다.
- target과 attacker는 새 Docker `--internal` network에서만 실행하고 host port를
  공개하지 않는다.
- attacker는 non-root, read-only, capability-free container로 실행한다.
- 성공 여부는 매 실행 새로 만든 `/out` volume의 `/out/p`만으로 판정한다.
- 외부 URL, 임의 image, address override 또는 command option을 제공하지 않는다.
- 이 실험은 서비스 가용성, persistence, interactive shell 또는 다른 권한 상승을
  시험하지 않는다.
- 고정 proof 명령 뒤 해당 Apache worker가 crash하므로 재현 자체가 target worker의
  가용성에 영향을 준다.

PHP 8.1은 EOL이며 PHP 프로젝트가 별도의 최소 source mitigation을 제공했다.
운영 환경은 이 exact PoC의 성공 여부와 관계없이 유지보수되는 수정 릴리스로
업그레이드하거나 배포판/LTS 공급자의 검증된 backport를 적용해야 한다.
