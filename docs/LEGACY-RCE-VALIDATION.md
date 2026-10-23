# PHP 7.3.33–8.1.34 locally calibrated RCE validation

작성일: 2026-10-23 (Asia/Seoul)

> [!CAUTION]
> 이 문서와 재현 코드는 보안 연구·교육·방어 검증 전용입니다. 본인이 소유하거나
> 명시적으로 허가받은 격리 환경에서만 사용하세요. runner는 외부 target과 임의
> 명령을 받지 않으며 proof 명령을 `id>/out/p`로 고정합니다.

> [!NOTE]
> 이 문서는 local `/proc` 보정으로 terminal primitive를 먼저 확인한 historical
> 경로를 보존합니다. 2026-10-24에는 PHP 8.1.34의 별도 128 MiB trans-SID
> profile이 두 ASLR base를 HTTP 응답에서 복원해 3/3 fresh proof를 만들었습니다.
> 새 end-to-end 결과는
> [`PHP-8.1-HTTP-RCE-VALIDATION.md`](PHP-8.1-HTTP-RCE-VALIDATION.md)에 있습니다.

## 결론과 증거의 경계

PHP 7.3.33, 7.4.33, 8.0.30 및 8.1.34의 exact official Apache image에서
terminal primitive를 실제 `www-data` 명령 실행까지 연결했다. 네 build 모두 고정
명령 `id>/out/p`로 다음 proof를 생성했다.

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

이 결과는 네 exact build의 terminal RCE primitive를 입증한다. 현재 legacy runner는
ASLR 주소를 target의 HTTP 응답에서 얻지 않는다. 로컬 Docker host의 root가
`/proc/<worker>/maps`와 `/proc/<worker>/mem`을 읽어 주소를 공급하므로,
standalone remote exploit 또는 HTTP-only ASLR bypass를 입증하지 않는다.
PHP 8.1.34에 대한 이 제한은 이 legacy runner에만 적용된다. 새 multi-version
profile은 다른 runtime과 producer를 사용해 HTTP-only ASLR disclosure까지
검증했다.

| Build | Primitive | 로컬 주소 보정 | 독립 fresh 결과 |
|---|---|---|---:|
| PHP 7.3.33 Apache | raw-key OOM의 partial `Bucket` → fake `HashTable` → libc `system()` | 재사용 block의 `arData`, libc load bias | 개발 runner 3/3 |
| PHP 7.4.33 Apache | raw-key OOM의 partial `Bucket` → fake `HashTable` → libc `system()` | 재사용 block의 `arData`, libc load bias | 개발 runner 3회 + 게시용 runner 재현 |
| PHP 8.0.30 Apache | raw-key OOM의 partial `Bucket` → fake `HashTable` → libc `system()` | 재사용 block의 `arData`, libc load bias | 개발 runner 3/3 |
| PHP 8.1.34 Apache | stale `zend_reference` → fake `HashTable` → `zif_passthru` | libphp base, Zend MM main chunk base | 개발 runner 3회 + 게시용 runner 3회 |

게시용 runner는 [`poc/legacy-calibrated-rce`](../poc/legacy-calibrated-rce/)에
있다. PHP 7.3/7.4/8.0은 공통 raw-key runner를 사용하고 PHP 8.1은 별도의
stale-session runner를 사용한다. 두 runner 모두 exact image allow-list, 새 internal
Docker network와 새 proof volume만 사용한다.

## PHP 7.3.33 / 7.4.33 / 8.0.30: partial Bucket 경로

세 profile의 정확한 대상은 다음과 같다.

| Build | Image digest | Image ID | Apache / libphp build ID | libc `system` ELF value |
|---|---|---|---|---:|
| PHP 7.3.33 | `sha256:b9872cd287ef72bc17d45d713aa2742f3d3bcf2503fea2506fd93aa94995219f` | `sha256:35da9118b3c0980fbaf84a4d410653642c9d55fb2f6c40011cc78de303837d64` | Apache 2.4.52 / `cb5f3581bd8fa554ea126c1b1b58020cfa3e8ebc` | `0x48e50` |
| PHP 7.4.33 | `sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d` | `sha256:20a3732f422b7b28dcf99e8597f093a8c135efca62ff0dc02a2d92d916369413` | Apache 2.4.54 / `a8f9e89e11da8db14855af2dd3a0d966f8e72d86` | `0x45e50` |
| PHP 8.0.30 | `sha256:c87b4c94d53b35520467b6d026f38656ab9a6d446fa3a0fbba1bc633125f9ad2` | `sha256:3357132d6ece3a509ce6f8abf6e7cf9886b343c504cb58428a7302cbe7abe446` | Apache 2.4.56 / `22ea5e392e39c122039896feb5c9c52b75846581` | `0x45e50` |

모두 `linux/amd64`, prefork/mod_php, `memory_limit=32M`, non-root Apache worker
1개로 고정했다. image reference에는 위 digest 앞에
`mirror.gcr.io/library/php@`를 붙인다. PHP 7.3/7.4는
`/usr/lib/apache2/modules/libphp7.so`, PHP 8.0은
`/usr/lib/apache2/modules/libphp.so`를 사용한다.

URL-encoded POST의 중첩 raw key를 등록할 때 mixed `HashTable`은 entry count를
먼저 증가시키고 key `zend_string`을 뒤에 할당한다. 이 key 할당에서 OOM bailout이
발생하면 `nNumUsed`는 증가했지만 새 `Bucket`은 초기화되지 않은 상태가 된다.
request shutdown은 증가한 count를 신뢰하고 stale zval을 파괴한다.

세 exact build는 같은 검증 geometry를 사용했다.

- raw key 길이: 7,400,000 bytes
- donor query value: 264 bytes
- 재사용 Zend MM bin: 320 bytes
- `Bucket`: 32 bytes
- fake `HashTable`: 56 bytes
- stale zval type flags: `IS_ARRAY_EX=0x307`

264-byte query value의 `zend_string`은 header, data와 NUL을 합쳐 320-byte bin에
들어간다. 8-entry mixed `HashTable`도 64-byte hash area와
`8 × 32-byte Bucket`으로 같은 bin을 사용한다. 안전한 control 요청은 stale
zval을 non-refcounted `IS_LONG`으로 두어 worker를 살린다. 보정기는
`/proc/<worker>/mem`에서 control pattern을 찾아 현재 `arData`를 구하고, maps와
컨테이너 libc ELF에서 runtime `system()`을 계산한다. terminal 요청은 stale zval을
`IS_ARRAY_EX`로 만들고 같은 block 안의 fake `HashTable`을 가리킨다.

```text
zend_array_destroy(fake)
  -> zend_hash_destroy(fake)
  -> fake pDestructor = libc system
  -> system("id>/out/p")
```

GDB primitive 확인에서는 stale bucket의 공격자 값
`0x1122334455667788`이 `zend_array_destroy()`의 destructor 인자 `rdi`로 들어가고,
backtrace가 `zend_array_destroy → php_request_shutdown → php_handler`로 이어졌다.
게시용 replay에는 GDB나 ptrace를 붙이지 않았다.

PHP 7.3과 8.0의 세 fresh 실행은 매번 다른 ASLR 주소에서 proof를 만들었다.

| Build / Run | `arData` | runtime `system()` | 결과 |
|---|---:|---:|---|
| PHP 7.3.33 / 1 | `0x75658c061e00` | `0x75658e730e50` | proof 생성 |
| PHP 7.3.33 / 2 | `0x79e6f9a61e00` | `0x79e6fc199e50` | proof 생성 |
| PHP 7.3.33 / 3 | `0x70828d861e00` | `0x70828ff62e50` | proof 생성 |
| PHP 8.0.30 / 1 | `0x78fc8da57e00` | `0x78fc903cfe50` | proof 생성 |
| PHP 8.0.30 / 2 | `0x75f901057e00` | `0x75f9038d6e50` | proof 생성 |
| PHP 8.0.30 / 3 | `0x7d4611057e00` | `0x7d46139e4e50` | proof 생성 |

PHP 7.4의 no-GDB 게시용 실행에서도 현재 process에서 읽은 값으로 proof가
생성됐다.

```text
PROC_ARDATA=0x7d1559a57e00
PROC_ARDATA_FF_SCORE=56/64
PROC_LIBC_BIAS=0x7d155c28d000
PROC_SYSTEM=0x7d155c2d2e50
RCE_PROOF_PRESENT
```

이 raw-key partial-`Bucket` 순서는 PHP 7.3에서 도입된 소스 계보에 해당한다.
여기서 확인한 것은 위 세 exact image와 geometry이며, branch 전체나 다른 SAPI로
일반화할 수 없다.

## PHP 8.1.34: stale zend_reference 경로

PHP 8.1은 raw-key profile과 다른 stale-session 경로를 사용한다. 정확한 대상은
다음과 같다.

- image digest:
  `mirror.gcr.io/library/php@sha256:72f0c0134922985022d55a39b0390d35dc7a10e961aa6c44fa35b4c3102f4268`
- image ID:
  `sha256:e6c924c6e862e6c74e01be964f88cb0c7ccbd673925e9a648cbbf77ff53b7ca1`
- PHP `8.1.34`, Apache prefork/mod_php, linux/amd64
- 실험 설정 `memory_limit=8M`, non-root Apache worker 1개

multipart upload-progress callback이 ordinary module activation보다 먼저 Session을
초기화하고 OOM bailout을 일으킨다. 정상 shutdown reset이 건너뛰어지면
`PS(http_session_vars)`가 request-owned `zend_reference`를 계속 가리킨다. 다음
multipart 요청의 4 KiB field가 해제된 page를 회수하고, stale 주소에 fake
`zend_reference`와 fake `HashTable`을 둔다.

확인된 호출 경로는 다음과 같다.

```text
php_session_rfc1867_callback
  -> php_session_initialize
  -> php_session_track_init
  -> zend_reference_destroy
  -> zend_array_destroy
  -> zend_hash_destroy
  -> zif_passthru("id>/out/p")
```

exact image에서 측정한 offset은 다음과 같다.

| 항목 | 값 |
|---|---:|
| `zif_passthru` | libphp `+0x36f480` |
| `zif_system` | libphp `+0x36f470` |
| `zval_ptr_dtor` | libphp `+0x457150` |
| `alloc_globals` | libphp `+0xf12c18` |
| stale reference | main chunk `+0x74160` |
| fake `HashTable` | main chunk `+0x74800` |

GDB trace는 forged reference를 거쳐 `zif_passthru`에 도달한 backtrace를
확인했다. 이후 GDB를 붙이지 않은 fresh container replay에서도 로컬 `/proc`
보정 뒤 서로 다른 ASLR 주소로 proof가 반복 생성됐다. 게시용 runner의 세 실행은
다음 base를 사용했다.

| Run | libphp base | Zend MM chunk base | 결과 |
|---|---:|---:|---|
| 1 | `0x7cf4364fb000` | `0x7cf434800000` | proof 생성 |
| 2 | `0x770361fe8000` | `0x770360400000` | proof 생성 |
| 3 | `0x7d464c7e2000` | `0x7d464ac00000` | proof 생성 |

PHP 8.2+ standalone profiles에서 사용한 Set-Cookie disclosure는 8.1에 그대로
적용되지 않는다. 이 historical 8 MiB lab은 두 runtime base를 로컬 `/proc`에서
공급한다. 후속 연구에서는 128 MiB runtime의 FILE_START OOM으로 `PS(id)`를 남긴
뒤 trans-SID rewrite를 사용해 main chunk와 `libphp` base를 HTTP로 누출했다. 해당
chain은 별도의 `php-8.1.34-apache-amd64-trans-sid` profile로 제공하며, 이 lab의
producer geometry나 주소 보정과 혼용하지 않는다.

## 공식 EOL 완화와 PHP 7.3의 차이

PHP 7.4, 8.0, 8.1은 새 point release 없이 별도의 최소 source mitigation을
받았다. 이 완화는 OOM 뒤 손상된 request state를 shutdown이 순회하지 않도록
fail-closed로 종료하고 upload-progress callback을 제한한다.

- PHP 7.4: [`712e60f9`](https://github.com/php/php-src/commit/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2)
- PHP 8.0: [`82f8f31b`](https://github.com/php/php-src/commit/82f8f31b16a035c1b67cc253e79f7cc288f4cc20)
- PHP 8.1: [`1d7dec17`](https://github.com/php/php-src/commit/1d7dec178a094e6e75b229ce22754045f8c6070a)

PHP 7.3은 PHP CNA의 maintained stable matrix에 포함되지 않았고, 위 EOL 최소
완화 세트에도 해당 branch의 공식 php-src backport가 없다. PHP 7.3 proof는 공식
제품 범위를 넓힌다는 행정적 주장이 아니라, 해당 exact pre-fix image에서 raw-key
terminal primitive가 실제로 동작했다는 실험 증거다.

위 vulnerable images는 완화 전 마지막 point release다. 운영 환경에서는 PoC
성공 여부와 무관하게 유지보수되는 수정 릴리스로 업그레이드하거나 배포판/LTS
공급자의 검증된 backport를 적용해야 한다.

## PHP 7.2.34의 중간 결과와 더 오래된 범위

PHP 7.2.34 exact image
`php@sha256:4dc0f0115acf8c2f0df69295ae822e49f5ad5fe849725847f15aa0e5802b55f8`
(image ID `sha256:c61d277263e19d2ce30a6bae41115c811eb0f9274a601a5e3ee621e54c8a74f7`)
에서는 pre-RINIT upload-progress OOM 뒤 dangling `zend_reference`가 다음 요청까지
남는 것을 확인했다. fresh-ASLR 실행 8회 모두 위치는 Zend MM chunk
`+0x6a018`이었다.

그러나 reference의 refcount가 2여서 consumer는 이를 `2 → 1`로만 낮췄고
destructor를 호출하지 않았다. 또한 PHP 7.2의 24-byte `zend_reference` slot을
시험한 HTTP-controlled allocation으로 reclaim하지 못했다. 7.3+ raw-key producer도
PHP 7.2에서는 key allocation이 `nNumUsed` 증가보다 먼저 일어나므로 이식되지
않는다. command proof는 생성되지 않았으며 RCE로 분류하지 않는다. 상세 근거는
[`PHP-7.2-STALE-STATE.md`](PHP-7.2-STALE-STATE.md)에 있다.

별도 benign probe는 PHP 5.4.45–7.1.33에서도 application script 전
`session.upload_progress` callback이 실행되는 선행 표면만 확인했다. PHP
5.4–7.1에는 cross-request stale state, 주소 disclosure, terminal primitive 또는
RCE 성공 증거가 없다. 이 저장소에서 PHP 5.4–7.2의 end-to-end RCE는 현재
검증되지 않았다.

## 공개 증거

sanitized 실행 기록과 manifest는 [`evidence/legacy-rce`](../evidence/legacy-rce/)에
있다. raw `/proc` maps, 전체 container inspect와 로컬 host path는 공개 증거에서
제외했다. 각 runner는 로컬 ignored `artifacts/` 아래에 더 상세한 checksummed
실행 자료를 남긴다.
