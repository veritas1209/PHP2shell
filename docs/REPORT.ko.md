# PHP2Shell PoC 및 공식 패치 차등 검증 보고서

작성일: 2026-10-23 (Asia/Seoul)

> 이 문서는 공개된 보안 권고와 수정 릴리스에 대한 사후 보안 연구 기록이다.
> 본인이 소유하거나 명시적으로 허가받은 격리 환경에서만 재현해야 한다.

## 결론

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
따라서 이번 결과는 **CVE-2026-109618/109619 결합 체인의 UAF·정보 유출·RCE와
공식 패치 효과를 함께 재현한 것**이다.

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
  포함됐다. 수정 릴리스는 PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12다.
- [PHP 8.4.27 릴리스 공지](https://www.php.net/releases/8_4_27.php)는 이를
  security release로 명시한다.

이 두 CVE는 결합될 수 있다. multipart 처리 중 OOM이 첫 요청의 세션 상태를
비정상적으로 남기고(CVE-2026-109618), 같은 persistent worker의 다음 multipart
요청이 정상 초기화 전에 그 포인터를 소비하면(CVE-2026-109619) 공격자는 UAF를
주소 누출과 제어 흐름 탈취로 발전시킬 수 있다.

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

즉, 두 CVE를 결합한 실제 php2shell 구조다. 다만 특정 PHP/Apache 빌드의
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

## 실험 환경

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

- 취약 8.4.26에서 OOM 처리와 RFC1867 전역/세션 상태가 패치 전 방식으로
  동작한다.
- 패치 8.4.27에서 공식 두 회귀 시나리오가 기대하는 안전 불변식이 성립한다.
- 실제 full-chain PoC가 8.4.26에서 Zend MM chunk와 `libphp` 주소를 누출한다.
- 가짜 `HashTable`의 `pDestructor`를 `zif_system`으로 향하게 해 Apache worker
  권한의 명령 실행과 proof 파일 생성을 완료한다.
- 동일 체인은 8.4.27에서 stage 1 주소 누출이 차단되고 proof를 만들지 못한다.
- 9bie PoC의 B1도 같은 포인터 판별 오류를 고치면 성공하며, 계산된 `libphp`
  base가 실제 process map과 일치한다.
- Bulletdev 코드의 동작 모델은 공식 두 CVE의 producer/consumer 모델과 다르다.

이번 실험의 범위 밖인 것:

- 9bie 구현의 B2 heap 배치를 이 호스트에 맞춰 최종 RCE까지 보정하는 작업
- 다른 커널·배포판·아키텍처에서 공개 PoC의 성공률
- Bulletdev Chain A/B/C를 공식 두 CVE의 full chain으로 입증하는 것

운영 환경의 취약 여부는 PoC 성공/실패로 판단하면 안 된다. 공식 advisory가
지정한 버전이면 [지원되는 패치 릴리스](https://www.php.net/releases/8_4_27.php)나
해당 배포판의 검증된 backport로 업데이트해야 한다.

## 첨부 증거

이 저장소의 `evidence/`에는 다음 공개용 증거가 들어 있다.

- 최종 cozybear 취약·패치 A/B 전체 Compose 로그와 종료 코드
- 실제 `www-data` proof 파일과 fixed proof 부재 확인
- 9bie B1 `/proc/maps` 교차검증 기록
- 취약·패치 공식 OOM/RFC1867 원시 출력
- 모든 공개 증거 파일의 SHA-256 manifest

host bind path가 포함된 Docker inspect JSON, 사설 작업 경로, 명시적 라이선스가
없는 upstream PoC 전체 소스는 공개 자료에서 제외했다. 최종 PoC runner는
고정 upstream 커밋을 임시 checkout하고 검증한 한 줄만 치환한다.

