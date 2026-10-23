# PHP2Shell PoC 멀티버전 및 공식 패치 차등 검증 보고서

작성일: 2026-10-23 (Asia/Seoul)

> 이 문서는 공개된 보안 권고와 수정 릴리스에 대한 사후 보안 연구 기록이다.
> 본인이 소유하거나 명시적으로 허가받은 격리 환경에서만 재현해야 한다.

이 문서는 초기 PHP 8.4.26/8.4.27의 공식 회귀 테스트와 full-chain A/B 분석을
보존하면서, 그 뒤에 수행한 PHP 8.2.34, 8.3.35 및 8.5.11 exact-build 포팅 결과를 함께
정리한다. 멀티버전 PoC는 버전 문자열만으로 실행하지 않고 image digest,
`libphp` identity, runtime과 heap calibration을 모두 검증한다.

## 종합 결론

후속 포팅에서 다음 네 exact official PHP Apache `linux/amd64` build에 대해
ptrace 없는 fresh-container 실행으로 `zif_system("id>/out/p")` proof를 확인했다.

| 취약 빌드 | full-chain 결과 | 수정 빌드 대조군 | 같은 재현 절차의 결과 |
|---|---|---|---|
| PHP 8.2.34 | tail variant 5/5 fresh 실행 성공 | PHP 8.2.35 | 3/3 B1 heap pointer 없음, `PROOF_ABSENT` |
| PHP 8.3.35 | 2/2 독립 실행 성공 | PHP 8.3.36 | disclosure 실패, `NO_PROOF` |
| PHP 8.4.26 | 4/4 기록된 실행 성공 | PHP 8.4.27 | stage-1 leak 실패, proof 없음 |
| PHP 8.5.11 | 2/2 독립 실행 성공 | PHP 8.5.12 | disclosure 실패, `NO_PROOF` |

성공한 모든 proof는
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`였다. 이 결과는 PHP
8.2, 8.3, 8.4, 8.5 계열 전체를 일반적으로 지원한다는 뜻이 아니다. 검증한 image와
runtime이 정확히 일치하는 네 build만 runnable profile로 제공한다.

PHP 8.2.34는 기존 8M/`display_errors=On` recipe 대신 stock
`php.ini-production`의 128M/`display_errors=Off` 환경에 맞춘
`pure-http-oom-v1` A1/B1/A2/B2 chain을 사용한다. 이 standalone HTTP framework에는
PHP 8.1.34와 7.2.34 profile이 없다. 그러나 별도 실험에서 PHP 7.3.33, 7.4.33,
8.0.30과 8.1.34의 terminal RCE primitive를 확인했다. 네 구버전 lab은 주소를
로컬 `/proc`에서 보정하므로 standalone remote ASLR bypass와 구분한다.

권장 재현 경로는 `poc/multiversion/run-local-docker-lab.sh`다. 이 runner는 외부
target이나 임의 명령을 받지 않고, allow-list된 exact profile과 digest-pinned
image만 사용한다. 새 internal Docker network와 proof volume을 만들고 host port를
공개하지 않으며, live target의 runtime과 `libphp` fingerprint를 검증한 뒤 고정
명령 `id>/out/p`만 실행한다.

### 버전 범위를 읽는 기준

이 보고서에서는 다음 세 범위를 분리한다.

| 구분 | 확인된 범위 | 의미 |
|---|---|---|
| PHP CNA의 공식 stable matrix | PHP 8.2.0–8.2.34, 8.3.0–8.3.35, 8.4.0–8.4.26, 8.5.0–8.5.11 | 두 CVE 레코드에 PHP CNA가 열거한 유지보수 branch와 첫 수정 릴리스 |
| PHP 프로젝트의 EOL 최소 완화 | PHP 7.4, 8.0, 8.1 | 새 point release 없이 제공된 source-level fail-closed/업로드 진행 callback 비활성화 backport |
| 연구진이 확인한 기술적 계보 | PHP 5.4.0 이상 pre-fix 코드 | Calif/Wiz가 버전·SAPI별로 서로 다른 공격 경로를 확인한 범위 |

따라서 `8.2–8.5`는 공식 CNA stable matrix이고, PHP2Shell 계열의 기술적 영향
하한은 아니다. Calif는 mod_php의 session upload-progress 경로가 PHP 5.4.0까지,
별도의 partial-HashTable/OOM 경로가 PHP 7.3까지 거슬러 올라간다고 보고했다.
Wiz도 적어도 하나의 관련 경로가 PHP 5.4부터 존재한다고 보고한다. 다만 이
연구 결과는 모든 historical patch와 설정에서 두 CVE가 동시에 같은 방법으로
재현된다는 뜻이 아니다. 실제 primitive는 PHP 버전, SAPI, 설정과 애플리케이션
동작에 따라 달라진다.

PHP 5.4–7.3은 PHP CNA 레코드에 열거되지 않았고 PHP 프로젝트가 제공한 공식
php-src backport branch도 없다. EOL 버전은 PoC 성공 여부와 관계없이 유지보수
릴리스로 업그레이드하거나 배포판/LTS 공급자의 검증된 backport를 적용해야 한다.
근거와 commit 표는 [버전 범위 문서](AFFECTED-SCOPE.md)에 별도로 정리했다.

### 초기 PHP 8.4 A/B 조사

공식 패치가 겨냥한 취약 상태와 패치 효과는 WSL2 Docker에서 재현됐다.
PHP 8.4.26과 8.4.27을 같은 입력으로 비교했을 때 다음 두 차이가 결정적으로
확인됐다.

1. CVE-2026-109618 관련 공식 OOM 회귀 시나리오에서 8.4.26은 할당 지점에서
   즉시 중단되어 `Done`을 출력하지 못했다. 8.4.27은 VM 안전 지점까지 실행해
   `Done`을 출력한 뒤 OOM fatal과 shutdown callback을 처리했다.
2. CVE-2026-109619 관련 RFC1867 회귀 시나리오에서 8.4.26은 스크립트 시작 전
   `_SESSION`을 남기고 기존 세션 레코드를 파기했다. 8.4.27은 `_SESSION`을
   남기지 않았고 레코드를 byte-for-byte 보존했으며, autoload와 magic method를
   명시적 `session_start()` 이후에만 실행했다.

공개 full-RCE PoC 두 종류도 실제로 실행했다. 첫 실행이 주소 누출 단계에서
멈춘 원인은 취약점이나 heap 배치가 아니라 PoC의 포인터 판별식이었다. PoC는
`0x7f...` 이상만 사용자 포인터로 인정했지만, 이 WSL2 호스트는 같은 amd64
이미지의 Zend MM chunk와 `libphp`를 `0x7e...` 등에 매핑했다. 판별식의 하한만
`0x700000000000`으로 낮추고 기존 QEMU-user 상한을 유지하자 PHP 8.4.26에서
heap 주소 누출, `libphp` 주소 누출, `zif_system` 호출까지 모두 통과했다.

최종 A/B 실행에서 취약한 PHP 8.4.26은 첫 stage-3 시도에 Apache worker 권한으로
`id>/out/p`를 실행했고, proof는
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`였다. 같은 PoC와 설정을
PHP 8.4.27에 적용하면 stage 1에서 누출이 차단되고 proof가 생성되지 않았다.
여기서 RCE는 interactive shell을 띄운 것이 아니라, 변조한 `pDestructor`가
`zif_system("id>/out/p")`을 실행해 서버 측 결과 파일을 만든 것으로 확인했다.
따라서 이번 결과는 **CVE-2026-109619 세션 체인의 UAF·정보 유출·RCE와,
CVE-2026-109618/109619 각각의 공식 회귀 시나리오에서 패치 효과를 함께 재현한
것**이다.

검토한 [`Bulletdev/php2shell-poc`](https://github.com/Bulletdev/php2shell-poc/tree/2d80235ccdf62bd01c1ef6ce36ae4a93b31c88cd)의
Chain A/B/C는 공식 두 CVE의 재현 코드로 볼 수 없다. 일부는 실제로 위험할 수
있는 별도 세션/LFI/역직렬화 패턴이지만, 공식 취약점의 OOM producer와 다음
요청의 stale-state consumer를 연결한 체인이 아니다.

## 공식 기준

PHP가 공개한 기준은 다음과 같다.

- [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w):
  OOM 처리의 `longjmp()`가 부분 초기화된 요청 상태를 남기고, 이후 shutdown이
  그 상태를 소비해 메모리 손상과 RCE로 이어질 수 있다. 패치는 OOM을 VM 안전
  지점까지 지연하는 soft OOM과 상한 초과 시 즉시 `_exit()`하는 hard OOM으로
  교체한다.
- [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp):
  치명적 중단 뒤 요청 소유 전역 상태가 worker에 남아 다음 요청의 정상 초기화
  전에 소비될 수 있다. 공식 영향은 unauthenticated UAF, memory disclosure,
  web-worker 권한의 RCE다.
- PHP 8.4의 두 수정은 같은 보안 커밋
  [`506e87fa`](https://github.com/php/php-src/commit/506e87fa7dcdd306975e5b8f8265ee03527aacbf)에
  포함됐다. PHP CNA가 열거한 stable branch의 수정 릴리스는 PHP 8.2.35,
  8.3.36, 8.4.27, 8.5.12다.
- [PHP 8.4.27 릴리스 공지](https://www.php.net/releases/8_4_27.php)는 이를
  security release로 명시한다.
- [PHP 보안 공지](https://www.php.net/archive/2026.php#2026-10-21-1)는 EOL인
  PHP 7.4, 8.0, 8.1용 최소 source mitigation commit도 별도로 제공한다.
- [Calif](https://calif.io/php2shell/)와
  [Wiz](https://www.wiz.io/blog/php2shell-php-rce)의 연구 결과는 적용 가능한
  공격 경로의 기술적 계보가 PHP 5.4.0까지 이어진다고 설명한다. 이는 CNA가
  열거한 제품 범위 및 이 저장소의 exact-build 지원 범위와 별개의 축이다.

두 CVE 모두 fatal/OOM 이후의 내부 상태 안전성과 관련되지만 공식 분류상 서로
다른 결함이다. 이 저장소의 runnable session upload-progress 체인은 첫 요청의
fatal/OOM으로 request-owned 세션 상태를 남긴 뒤 같은 persistent worker의 다음
요청이 그 stale 상태를 소비하는 **CVE-2026-109619** 체인이다.
CVE-2026-109618은 부분 초기화된 요청 메모리를 shutdown이 유효한 값처럼 처리하는
별도 OOM corruption 결함이며, 여기서는 공식 회귀 시나리오의 취약·패치 차등으로
검증했다.

## PoC 선별 결과

### 1. 9bie full HTTP chain

가장 공식 메커니즘에 가까운 공개 코드는
[`9bie/php2shell-bypass-aslr-exp`](https://github.com/9bie/php2shell-bypass-aslr-exp/tree/17e98ee81025cccfd94b4f9c9a17bf269c65ff75),
검토 커밋 `17e98ee81025cccfd94b4f9c9a17bf269c65ff75`다. 이 코드는 다음 단계를
구현한다.

1. prefork worker를 고정한다.
2. multipart OOM으로 session 관련 상태를 요청 경계 밖에 남긴다.
3. 다음 요청의 `Set-Cookie` OOB read로 Zend MM chunk와 `libphp` 주소를 찾는다.
4. 가짜 reference와 `HashTable`을 배치하고 `pDestructor`를 `zif_system`으로
   향하게 한다.

즉, CVE-2026-109619의 실제 php2shell 구조다. 다만 특정 PHP/Apache 빌드의
offset, heap 배치, 누출 창 형태에 강하게 의존한다.

### 2. cozybear 차등 체인

[`cozybear-dev/cve-2026-109619`](https://github.com/cozybear-dev/cve-2026-109619/tree/7a73bb50fbc9d0f5aafce9c135bf4cbf4575601b),
검토 커밋 `7a73bb50fbc9d0f5aafce9c135bf4cbf4575601b`도 같은 producer/consumer
구조를 취하고 취약·패치 이미지를 함께 고정해 A/B 비교한다. 따라서 보조
검증 대상으로 선택했다.

### 3. Bulletdev Chain A/B/C

검토 기준 커밋은
[`2d80235c`](https://github.com/Bulletdev/php2shell-poc/commit/2d80235ccdf62bd01c1ef6ce36ae4a93b31c88cd)다.

| 체인 | 코드가 실제로 하는 일 | 공식 CVE와의 관계 |
|---|---|---|
| A | upload-progress 세션 파일의 filename에 PHP를 넣고 애플리케이션 LFI로 그 파일을 include | LFI가 필수인 애플리케이션 체인이다. OOM, 요청 간 stale pointer, UAF가 없다. 스크립트도 원격 세션 파일 생성을 직접 확인하지 않고 사용자가 확인하라는 문구를 출력한다. |
| B | 한 번의 `unserialize()` 안에서 destructor 재진입과 `R:1500` back-reference로 별도 `var_destroy` UAF를 ASAN에서 찾으려 한다 | multipart producer/consumer나 요청 경계가 없다. 스크립트는 실제 ASAN 판정과 관계없이 마지막에 항상 `exit(0)`한다. 공식 두 CVE의 재현 판정기로 사용할 수 없다. |
| C | 서로 다른 `session.serialize_handler`, 사전 로드된 `Evil` gadget, decode 실패 시 destructor 실행을 조합한다 | 8.4.27의 “RFC1867 중 사용자 코드 금지”와 맞닿은 동작은 있지만, 공식 advisory의 stale request-global UAF·주소 누출 체인을 재현하지 않는다. 특수 서버 설정과 공격용 gadget도 필요하다. |

따라서 Bulletdev 저장소는 관련 공격 아이디어 모음으로는 볼 수 있지만,
“CVE-2026-109618/109619을 재현했다”는 증거로는 부적합하다. Chain A나 C가 해당
저장소의 인공 lab에서 명령을 실행하더라도 공식 CVE 재현을 뜻하지 않는다.

## 후속 exact-build 멀티버전 포팅

후속 작업에서는 MIT 라이선스의
[`78ResearchLab/PHP2Shell-Full-Chain-Exploit`](https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit)
commit `167085410a9342fafbd1bd64f5006920dbc83b8e`를 기준으로 request lifecycle,
leak sequence와 packed `r0` spray를 profile-driven framework에 맞게 일부
수정·확장했다. 검토한 upstream `exploit.py` SHA-256은
`6aadf7bc93b3f4f93b755fed727d3f017e806419c96853290cf2250e567c1323`이며,
원 저작권 고지와 MIT 전문을 `poc/multiversion/` 아래에 보존했다.

### Runnable profile

| Profile | stage 2 | stage 3 calibration | 관찰 결과 |
|---|---|---|---|
| PHP 8.2.34 | pure-HTTP B1, stale SID raw offset `0xe2968`, disclosure `0xc8000` | fake array `main+0xf9398`, A2 880/64/115, B2 384/500/495 | 5/5 fresh proof |
| PHP 8.3.35 | adaptive `0x20000` window, 150 arrays | `r0=chunk+0x74180`, 400 spray fields | 2/2 direct proof |
| PHP 8.4.26 | fixed-array leak | fixed carrier `HTDATA=chunk+0x690d8` | 4/4 documented proof |
| PHP 8.5.11 | adaptive `0x20000` window, 150 arrays | `r0=chunk+0x73180`, one 19-byte pre-session field, 128 total spray fields | 2/2 direct proof |

PHP 8.5.11에서 초기 recipe가 실패한 원인은 stale multipart name storage가
비정상적인 `zend_string` 길이로 다시 해석되어 stage 3 전에 큰 realloc으로
이어졌기 때문이다. session/progress field 앞에 평범한 19-byte field 하나를
배치하고, 전체 spray field 수를 128로 유지하자 ptrace 없이 두 번 연속 proof를
얻었다. 이 배치는 8.5.11 exact profile에만 기록했으며 다른 빌드에 일반화하지
않았다.

PHP 8.3.35와 8.5.11은 fixed-array 주소를 재사용하는 대신 각 request에서 leak
window를 다시 관찰하는 adaptive stage 2를 사용한다. 성공한 worker를 stage 2
사이에서 불필요하게 회전시키지 않도록 lifecycle도 profile에 명시했다.

PHP 8.2.34의 A1은 70-byte boundary, 860개 depth-64 nested file field,
bin별 filler와 35/35 tail field 하나로 `php_url_encode()` 경로에서 OOM이 나도록
고정했다. B1은 generated SID의 chunk-relative raw offset `0xe2968`에 fake
`zend_string`을 배치해 main chunk와 `libphp`를 얻는다. A2/B2는
`PS(http_session_vars)` stale value를 fake reference와 fake `zend_array`로
회수하며, 공개 renderer가 만든 A1은 성공 입력과 같은 1,117,868 bytes 및
SHA-256 `643be7a49073fc4af53a2d87aec3ec4b7f67fade1f0d458d00c6f88675326178`로 검증했다.

### 수정판 대조군

동일한 취약판 recipe를 공식 수정 image에 적용한 bounded control 결과는 다음과
같다.

| Control | 결과 |
|---|---|
| PHP 8.2.35 | 3/3 B1에서 heap pointer 없음, status 1, `PROOF_ABSENT` |
| PHP 8.3.36 | stage-1 disclosure 실패, exploit exit 1, `NO_PROOF` |
| PHP 8.4.27 | 259-byte 정상 응답만 반환, stage-1 leak 실패, proof 없음 |
| PHP 8.5.12 | stage-1 disclosure 실패, exploit exit 1, `NO_PROOF` |

대조군의 실패는 공식 수정이 현재 chain의 필수 disclosure를 차단한다는 관찰이다.
운영 환경의 안전 판정은 PoC 결과가 아니라 official advisory와 vendor backport
상태를 기준으로 해야 한다.

### standalone HTTP PoC의 PHP 8.1/7.2 포팅 경계

PHP 8.1.34/7.2.34의 source 및 runtime probe에서는 공개 체인이 기대하는 cookie
disclosure가 나오지 않았다. 이들 branch는 intentionally non-runnable로
standalone framework에 문서화했으며, 취약성 부정이나 별도 exploit chain의
불가능성을 뜻하지 않는다.
특히 PHP 8.1에는 공식 최소 완화가 존재하고, 연구진은 PHP 7.2를 포함하는 5.4+
계보에서 버전·SAPI에 맞는 다른 공격 경로를 보고했다. 이 표의 상태는 오직 현재
cookie-disclosure recipe의 포팅 결과다.

PHP 7.2.34에는 별도의 bounded pre-RINIT OOM 조사를 수행했다. exact image
`php@sha256:4dc0f0115acf8c2f0df69295ae822e49f5ad5fe849725847f15aa0e5802b55f8`
(image ID `sha256:c61d277263e19d2ce30a6bae41115c811eb0f9274a601a5e3ee621e54c8a74f7`)
에서 request-owned `zend_reference`가 다음 요청까지 남고
`php_session_track_init()`에 다시 소비되는 현상을 fresh-ASLR 8회 모두 확인했다.
pointer는 매번 Zend MM chunk `+0x6a018`에 있었다.

이 결과는 RCE가 아니다. reference의 refcount가 2여서 consumer는 `2 → 1` 감소만
수행했고 destructor에 도달하지 않았다. PHP 7.2의 24-byte reference를 시험한
POST/Cookie allocation으로 reclaim하지도 못했다. 또한 PHP 7.2 소스는 key를 먼저
할당하고 그 성공 뒤 `nNumUsed`를 증가시키므로, 7.3+ raw-key partial-`Bucket`
producer를 이식할 수 없다. proof는 생성되지 않았다. 상세 결과는
`docs/PHP-7.2-STALE-STATE.md`에 있다.

### PHP 7.3.33 / 7.4.33 / 8.0.30 / 8.1.34 locally calibrated terminal RCE

별도의 exact-build 실험에서는 네 구버전의 terminal primitive를 실제 고정 명령
실행까지 연결했다.

| Build | 경로 | 반복 결과 | 주소 공급 |
|---|---|---:|---|
| PHP 7.3.33 Apache | raw-key OOM partial `Bucket` → fake `HashTable` → libc `system()` | 3/3 fresh 개발 실행 | `/proc`에서 재사용 block `arData`와 libc base 측정 |
| PHP 7.4.33 Apache | raw-key OOM partial `Bucket` → fake `HashTable` → libc `system()` | 개발 3회 + 게시용 runner 재현 | `/proc`에서 재사용 block `arData`와 libc base 측정 |
| PHP 8.0.30 Apache | raw-key OOM partial `Bucket` → fake `HashTable` → libc `system()` | 3/3 fresh 개발 실행 | `/proc`에서 재사용 block `arData`와 libc base 측정 |
| PHP 8.1.34 Apache | stale `zend_reference` → fake `HashTable` → `zif_passthru` | 개발 3회 + 게시용 runner 반복 재현 | `/proc`에서 libphp와 Zend MM chunk base 측정 |

네 실험의 proof는 모두 고정 명령 `id>/out/p`로 만든
`uid=33(www-data) gid=33(www-data) groups=33(www-data)`였다. GDB trace는
raw-key 계열을 대표해 PHP 7.4에서 stale bucket이 `zend_array_destroy()`의
destructor 인자로 들어가는 경로와 PHP 8.1에서
`php_session_track_init → zend_reference_destroy → zend_hash_destroy → zif_passthru`
경로를 각각 확인했다. 게시용 replay에는 GDB나 ptrace를 붙이지 않았다.

다만 runner가 target worker의 로컬 `/proc/<pid>/maps`와
`/proc/<pid>/mem`을 읽어 ASLR 값을 공급한다. 그러므로 이는 해당 exact build의
RCE primitive와 terminal chain에 대한 검증이며, 원격 클라이언트가 주소를 얻는
HTTP-only exploit 증거는 아니다. 고정 image, 고정 명령, internal Docker network만
허용하는 실행기는 `poc/legacy-calibrated-rce/`, 상세 근거는
`docs/LEGACY-RCE-VALIDATION.md`에 있다.

PHP 7.3/7.4/8.0은 같은 raw-key geometry를 사용하고, PHP 8.1은 별도의
stale-session 경로를 사용한다. PHP 8.1의 pure-HTTP ASLR leak은 확인하지 못했다.
PHP 7.4/8.0/8.1에는 공식 EOL 최소 완화가 있지만 PHP 7.3에는 공식 php-src
backport가 없다. PHP 7.2는 위 stale-state primitive까지 확인했으나 terminal
RCE에는 도달하지 못했고, PHP 5.4–7.1은 benign 선행 표면만 확인했다. PHP
5.4–7.2의 end-to-end RCE는 이 저장소에서 아직 검증되지 않았다.

### PHP 5.4–8.1 runtime surface matrix

영향 하한을 문서만으로 추정하지 않기 위해 PHP 5.4.45, 5.5.38, 5.6.40,
7.0.33, 7.1.33, 7.2.34, 7.3.33, 7.4.33, 8.0.30, 8.1.34 Apache build를
WSL Docker에서 각각 실행했다. 고정된 1 MiB multipart upload를 64 KiB 뒤에서
5초간 멈춘 동안 session file을 관찰했다. 열 build 모두 기본
`session.upload_progress.enabled=1`이었고, application script가 응답하기 전에
`upload_progress_bounded` 값이 생성됐다. 업로드를 끝내면 script marker가
응답했고 progress 값은 정상 cleanup됐다.

이 실험은 pre-script upload-progress callback과 session write라는 선행 표면만 해당
exact build에서 확인한다. OOM, cross-request stale state, 주소 유출, ASLR bypass
또는 RCE를 입증하지 않는다.
전체 image digest와 재현기는 각각
`evidence/legacy-runtime-matrix.txt`와 `poc/legacy-scope-probe/`에 있으며,
상세한 해석은 `docs/LEGACY-RUNTIME-MATRIX.md`에 분리했다. PHP 5.4.45는 현행
Docker가 원본 schema-v1 official manifest를 거부하므로 source가 공개된
eugenesia archive image를 별도로 표시해 사용했다.

### 안전한 재현 runner

새 `poc/multiversion/run-local-docker-lab.sh`는 command-line 인자를 거부하고
bundled verified profile ID 네 개만 허용한다. 각 profile마다 다음 순서로 검증한다.

1. target과 attacker image를 immutable digest로 불러오고 image ID를 확인한다.
2. fresh `--internal` network와 `/out` volume을 만들며 host port를 게시하지 않는다.
3. live target에서 Apache SAPI, single prefork worker, runtime 설정과 `libphp.so`를
   관찰하고 SHA-256, GNU build ID와 symbol offset을 profile에 대조한다.
4. read-only, capability-free attacker container에서 fixed proof command
   `id>/out/p`만 실행한다.
5. proof와 checksummed artifacts를 기록하고 container, network, volume 및 임시
   `libphp.so`를 제거한다.

기존 `poc/run-wsl-docker-lab.sh`는 초기 PHP 8.4 A/B 결과를 보존하는 legacy
runner다. 새 실험에는 exact-build fingerprinting과 internal-only network를 갖춘
multi-version runner를 사용한다.

## 초기 PHP 8.4 실험 환경

| 항목 | 값 |
|---|---|
| 호스트 | Ubuntu 24.04 / WSL2, x86_64 |
| WSL 커널 | `6.6.87.2-microsoft-standard-WSL2` |
| Docker | client/server 29.8.0 |
| 자원 | 16 CPU, 약 16 GB RAM |
| 취약 이미지 | `php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` |
| 취약 image config | `sha256:46b195b6378e712d1a65cd3f853242bebd7f3cb4cafe137fd592b365909d2c17`, PHP 8.4.26 |
| 패치 이미지 | `php@sha256:e6bad969f0b673ce9121c88dabb53488ab1ca139d8ebfac1d1b1ab63f245f725` |
| 패치 image config | `sha256:675af91f3349cf6dba7bd50ce967eb38732c5aa23b9e5b021dc15e2b1a2d1e5e`, PHP 8.4.27 |

자체 비교 컨테이너에는 loopback 포트, Docker 기본 seccomp,
`no-new-privileges`, 256/512 MiB 메모리 제한, PID 64 제한을 적용했다. CLI OOM
검사에서는 모든 capability도 제거했다. 최종 cozybear A/B는 upstream Compose의
target·offset·요청 흐름을 그대로 쓰고 포인터 판별식 한 줄만 수정했다. 이
Compose도 host port를 loopback에만 열었으며 privileged mode나 host network를
쓰지 않았다. 모든 실험 컨테이너·Compose network·proof volume은 로그와 proof를
수집한 뒤 삭제했고 이미지 layer만 로컬 cache에 남겼다.

## 실행 결과

### 공개 exploit

| 실험 | 결과 | 관찰 |
|---|---|---|
| 9bie, 원본 포인터 필터 | 실패, 총 11회 | `0x7f...` 하한 때문에 실제 `0x7a...`/`0x7b...` 포인터 8,756개를 모두 버렸다. |
| 9bie, 포인터 하한 보정 | B1 성공, B2 실패 | 7495/1095/87/79 fingerprint와 `libphp` base가 `/proc/.../maps`와 byte 단위로 일치했다. B2에서 child SIGSEGV가 발생해 이 구현은 RCE까지 가지 못했다. |
| cozybear, 원본 포인터 필터 | 실패 | 취약 8.4.26에서도 stage 1이 포인터를 찾지 못해 최초 실행은 `INCONCLUSIVE`였다. |
| cozybear, 하한 보정, PHP 8.4.26 | **RCE 성공** | stage 1·2가 첫 시도에 성공했고 stage 3 첫 시도에 `id>/out/p` 실행, `uid=33(www-data)` proof 생성. |
| cozybear, 동일 보정, PHP 8.4.27 | **차단됨** | 두 번 모두 259-byte 정상 응답만 반환하고 stage 1 누출 실패. fixed proof 없음. |

실패 원인은 WSL2의 높은 mmap randomization이었다. 이 호스트의
`vm.mmap_rnd_bits=32`에서는 shared mapping이 반드시 `0x7f...`에 놓이지 않는다.
최소 수정은 다음과 같이 하한만 넓혀 원래의 QEMU-user 상한을 보존하는 것이다.

```diff
- return 0x7F0000000000 <= v < 0x0001000000000000
+ return 0x700000000000 <= v < 0x0001000000000000
```

최종 깨끗한 Compose 실행에서 계산된 주소는 다음과 같다.

```text
Zend MM chunk = 0x71ab23400000
libphp base   = 0x71ab25137000
HTDATA        = 0x71ab234690d8
zif_system    = 0x71ab2559c370
PROOF         = uid=33(www-data) gid=33(www-data) groups=33(www-data)
RESULT        = CONFIRMED
```

취약 target은 준비 단계에서 `zend_mm_heap corrupted`와 SIGABRT를 각각 3회
기록했고, 명령 실행 직후 해당 child가 SIGSEGV로 종료됐다. proof는 그 전에 이미
생성됐다. 패치 target에는 heap-corruption/SIGABRT가 없었다.

수정은 target, PHP binary, offset, heap filler, multipart 요청 또는 control-flow
payload를 바꾸지 않는다. 누출 응답에 이미 있던 올바른 주소를 WSL2에서도
인식하게 만든 이식성 보정이다. 동일한 소스와 옵션으로 새 proof volume을 만든
최종 A/B의 Compose 종료 코드는 0이었다.

### 공식 OOM 회귀 시나리오

사용한 입력은 PHP 8.4.27의
[`Zend/tests/oom_after_main_script.phpt`](https://github.com/php/php-src/blob/php-8.4.27/Zend/tests/oom_after_main_script.phpt)
`--FILE--` 본문이며, `memory_limit=8M`, `opcache.optimization_level=0`을 동일하게
적용했다.

PHP 8.4.26:

```text
Fatal error: Allowed memory size of 8388608 bytes exhausted ...
Shutdown function called
docker_exit=255
```

PHP 8.4.27:

```text
Done

Fatal error: Allowed memory size of 8388608 bytes exhausted ...
Shutdown function called
docker_exit=255
```

종료 코드보다 `Done`의 유무와 출력 순서가 판정 기준이다. 8.4.27의 지연된
soft OOM 동작이 공식 기대값과 일치한다.

### 공식 RFC1867 회귀 시나리오

PHP 8.4.27의
[`ext/session/tests/rfc1867_no_user_code.phpt`](https://github.com/php/php-src/blob/php-8.4.27/ext/session/tests/rfc1867_no_user_code.phpt)를
Apache/mod_php 요청으로 옮겼다. 요청 전 동일한 직렬화 레코드를 `www-data`
소유의 tmpfs 세션 파일에 기록했고, SID와 progress field를 file part보다 먼저
보냈다.

PHP 8.4.26의 핵심 출력:

```text
PHP Request Startup: Class 'Suit' not found
PHP Request Startup: Failed to decode session object. Session has been destroyed
bool(true)   # target script 진입 시 _SESSION이 남음
bool(true)   # session은 아직 정상 시작 전
bool(false)  # 원본 record 보존 실패
```

PHP 8.4.27의 전체 핵심 순서:

```text
bool(false)
bool(true)
--- record after the update:
bool(true)
string(20) "upload_progress_key|"
--- session_start():
autoload(Missing)
W::__wakeup
U::__unserialize
string(17) "rfc1867nousercode"
...
bool(true)
```

패치 버전에서는 `_SESSION`이 target script 전에 노출되지 않았고, 기존 레코드가
보존됐으며, 사용자 코드 실행 지표가 `--- session_start():` 이후에만 나타났다.
이는 공식 테스트 기대값과 정확히 일치한다.

## 증거의 범위

이번 실험이 확인한 것:

- exact official image와 runtime profile이 일치하는 PHP 8.2.34, 8.3.35,
  8.4.26, 8.5.11에서 full chain이 `www-data` proof를 생성한다.
- exact PHP 7.3.33, 7.4.33, 8.0.30, 8.1.34 Apache image에서 로컬 `/proc`로
  주소를 보정한 terminal chain이 고정 `id>/out/p` proof를 생성한다.
- exact PHP 7.2.34에서 pre-RINIT OOM 뒤 stale `zend_reference`가 다음 요청에
  소비되는 primitive가 fresh container 8회 재현되지만 destructor와 proof는
  발생하지 않는다.
- 대응하는 수정 image PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12에서는 같은 recipe가 필수
  disclosure를 얻지 못하고 proof를 만들지 않는다.
- 취약 8.4.26에서 OOM 처리와 RFC1867 전역/세션 상태가 패치 전 방식으로
  동작한다.
- 패치 8.4.27에서 공식 두 회귀 시나리오가 기대하는 안전 불변식이 성립한다.
- 실제 full-chain PoC가 8.4.26에서 Zend MM chunk와 `libphp` 주소를 누출한다.
- 가짜 `HashTable`의 `pDestructor`를 `zif_system`으로 향하게 해 Apache worker
  권한의 명령 실행과 proof 파일 생성을 완료한다.
- 동일 체인은 8.4.27에서 stage 1 주소 누출이 차단되고 proof를 만들지 못한다.
- 9bie PoC의 B1도 같은 포인터 판별 오류를 고치면 성공하며, 계산된 `libphp`
  base가 실제 process map과 일치한다.
- Bulletdev 코드의 동작 모델은 CVE-2026-109618의 partial-init shutdown 모델 및
  CVE-2026-109619의 stale request-global 모델과 다르다.

이번 실험의 범위 밖인 것:

- 9bie 구현의 B2 heap 배치를 이 호스트에 맞춰 최종 RCE까지 보정하는 작업
- 다른 커널·배포판·아키텍처에서 공개 PoC의 성공률
- Bulletdev Chain A/B/C를 공식 두 CVE의 full chain으로 입증하는 것
- PHP 8.1 locally calibrated lab에 사용할 pure-HTTP ASLR disclosure primitive
- PHP 7.2의 refcount 및 24-byte reclaim blocker를 넘어 terminal primitive로
  연결하는 작업
- PHP 5.4–7.1 각 historical branch/SAPI용 별도 exploit primitive를 개발하고
  exact-build end-to-end RCE profile로 검증하는 작업

운영 환경의 취약 여부는 PoC 성공/실패로 판단하면 안 된다. CNA가 열거한
stable branch는 지원되는 수정 릴리스로 업데이트하고, EOL branch는 유지보수
릴리스로 업그레이드하거나 해당 배포판/LTS 공급자의 검증된 backport를 적용해야
한다.

## 첨부 증거

이 저장소의 `evidence/`에는 다음 공개용 증거가 들어 있다.

- 최종 cozybear 취약·패치 A/B 전체 Compose 로그와 종료 코드
- 실제 `www-data` proof 파일과 fixed proof 부재 확인
- 9bie B1 `/proc/maps` 교차검증 기록
- 취약·패치 공식 OOM/RFC1867 원시 출력
- PHP 7.3.33/7.4.33/8.0.30/8.1.34 로컬 보정형 고정 명령 proof의 sanitized 기록
- PHP 7.2.34 request 간 stale-state primitive와 proof 부재의 sanitized 기록
- 모든 공개 증거 파일의 SHA-256 manifest

host bind path가 포함된 Docker inspect JSON, 사설 작업 경로, 명시적 라이선스가
없는 upstream PoC 전체 소스는 공개 자료에서 제외했다. 새 multi-version runner는
MIT 고지를 보존한 bundled framework와 검증된 exact profile만 사용한다. 기존
PHP 8.4 runner의 고정 upstream commit 임시 checkout 방식은 초기 조사 재현을 위한
legacy 경로로 남겼다.

