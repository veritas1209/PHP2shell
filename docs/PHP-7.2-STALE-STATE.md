# PHP 7.2.34 pre-RINIT stale session-state validation

작성일: 2026-10-23 (Asia/Seoul)

> [!CAUTION]
> 이 문서는 격리된 로컬 Docker 환경에서 수행한 초기 개발 경로의 기록이다. 이
> 실험 자체는 PHP 7.2 RCE PoC가 아니며 명령 실행이나 proof를 만들지 못했다.
> 이후 별도 HTTP-only chain은 exact PHP 7.2.34에서 3/3 고정 proof를 만들었고
> [`../poc/legacy-http-rce/php-7.2.34/`](../poc/legacy-http-rce/php-7.2.34/)에
> 분리해 게시한다.

## 결론

정확히 고정한 PHP 7.2.34 Apache image에서 pre-RINIT upload-progress OOM 뒤
`PS(http_session_vars)`에 request-owned `zend_reference`가 남고, 같은 prefork
worker의 다음 multipart 요청이 그 stale pointer를 다시 소비하는 현상을 확인했다.
ASLR 주소가 달라지는 fresh container 여덟 번 모두 stale reference의 위치는 Zend
2 MiB chunk 기준 `+0x6a018`이었다.

terminal RCE에는 도달하지 못했다. destructor dispatch가 발생하지 않았고, 시험한
고정 marker 명령도 실행되지 않았으며 proof 파일은 생성되지 않았다. 따라서 이
결과는 **request 간 stale-state primitive 확인, RCE 미확인**으로 분류한다.

## 고정 대상

| 항목 | 값 |
|---|---|
| Image | `php@sha256:4dc0f0115acf8c2f0df69295ae822e49f5ad5fe849725847f15aa0e5802b55f8` |
| Image ID | `sha256:c61d277263e19d2ce30a6bae41115c811eb0f9274a601a5e3ee621e54c8a74f7` |
| Runtime | PHP 7.2.34 NTS, Apache 2.4.38 Debian mod_php, linux/amd64 |
| Module | `/usr/lib/apache2/modules/libphp7.so` |
| PHP settings | `memory_limit=8M`, `post_max_size=64M`, upload progress enabled |
| Process model | non-root Apache prefork worker 1개, host port 미공개 internal network |

exact image의 ABI에서 `zend_reference`는 24 bytes이고, reference의 value는
`IS_ARRAY_EX=0x1407` 상태로 관찰됐다.

## 확인된 producer와 consumer

첫 multipart 요청은 Session ID와 upload-progress field를 먼저 처리하게 한 뒤 큰
field allocation에서 `memory_limit` OOM을 유도한다. ordinary RINIT보다 앞서 실행된
session upload-progress callback이 Session reference를 만들고, bailout 뒤 정상
reset이 완료되지 않아 `PS(http_session_vars)`가 request-owned 주소를 유지한다.

같은 worker의 다음 upload-progress 요청에서 `php_session_track_init()`은 stale
zval을 다시 읽었다. fresh container 여덟 번에서 실제 pointer의 ASLR 값은 매번
달랐지만 chunk-relative 위치는 모두 같았다.

```text
stale reference = Zend 2 MiB chunk + 0x6a018
gc.refcount      = 2
gc.type          = IS_REFERENCE
referenced value = IS_ARRAY_EX (0x1407)
```

## terminal RCE를 막은 두 조건

1. 두 번째 요청에서도 stale reference의 `gc.refcount`가 2였다.
   `zval_ptr_dtor()`는 이를 `2 → 1`로 낮췄을 뿐 `_zval_dtor_func()`와 내부 array
   destructor를 호출하지 않았다.
2. PHP 7.2의 `zend_reference`는 24 bytes다. 시험한 작은·큰 POST value와 조기
   Cookie parsing allocation은 이 24-byte slot을 공격자 제어 데이터로 reclaim하지
   못했다. user-controlled `zend_string`은 allocator header와 string header 때문에
   다른 size class를 사용했다.

둘 중 하나만 해결돼도 충분하다는 의미는 아니다. terminal chain에는 stale
reference를 제어 가능한 데이터로 대체하고, refcounted destructor 또는 다른 유효한
consumer까지 연결하는 추가 primitive가 필요하다.

## PHP 7.3+ raw-key 경로가 이식되지 않는 이유

PHP 7.2의 변수 등록 경로는 먼저 key `zend_string`을 할당하고, 그 성공 뒤에
`nNumUsed`를 증가시킨다. 따라서 key allocation OOM 시점에는 증가한 metadata와
partial `Bucket`이 남지 않는다. PHP 7.3+ raw-string 최적화 경로는 반대로
`nNumUsed`를 먼저 증가시킨 뒤 key를 할당하므로, 이 저장소에서 PHP
7.3/7.4/8.0에 검증한 raw-key partial-`Bucket` producer를 만들 수 있다.

이는 단순 offset이나 filler 조정 문제가 아니라 source ordering 차이다. PHP 7.2에
같은 raw-key recipe를 적용할 수 없다는 사실을 exact source와 runtime에서
확인했다.

## 증거의 범위

이 초기 조사가 입증한 것은 pre-RINIT OOM 뒤 request 간 dangling session reference와
다음 요청의 stale read/refcount 감소다. memory disclosure, controlled reclaim,
destructor dispatch, command execution 또는 RCE는 입증하지 않았다. 이 문서가
기록한 실패 경로와 별개로 PHP 5.4.45–7.4.33의 후속 exact-build HTTP chain은
[`../poc/legacy-http-rce/`](../poc/legacy-http-rce/)에서 검증됐다. 두 결과는 서로
다른 producer, disclosure와 terminal geometry를 설명하므로 함께 보존한다.

공개용 요약 trace와 exact image identity는
[`evidence/legacy-rce/php-7.2.34-stale-state.txt`](../evidence/legacy-rce/php-7.2.34-stale-state.txt)에
있다. 로컬 조사 스크립트와 원시 debugger 로그는 이 공개 문서의 재현 자료로
포함하지 않는다.
