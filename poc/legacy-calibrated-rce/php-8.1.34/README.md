# PHP 8.1.34 locally calibrated RCE lab

> [!CAUTION]
> **보안 연구·교육·방어 검증 전용입니다.** 본인이 소유하거나 명시적으로 시험을
> 허가받은 격리 환경에서만 사용하세요. 제3자 시스템, 운영 서비스, 공개 워게임
> 서버 또는 허가받지 않은 네트워크에는 사용하지 마세요.

이 디렉터리는 CVE-2026-109618/109619 계열의 pre-RINIT OOM 이후 stale Session
state가 PHP 8.1.34에서도 실제 destructor 제어와 명령 실행까지 이어짐을 확인하는
고정형 로컬 실험기입니다. 성공 시 target container에서 다음 고정 명령만
실행합니다.

> [!NOTE]
> 이 8 MiB `/proc` 보정형 lab은 historical terminal-primitive 검증기로
> 보존됩니다. 새 128 MiB HTTP-only profile
> `php-8.1.34-apache-amd64-trans-sid`는 target process memory를 읽지 않고
> trans-SID 응답에서 두 ASLR base를 복원해 3/3 fresh proof를 만들었습니다.
> 새 end-to-end 재현은 [`../../multiversion`](../../multiversion/)을 사용하고,
> 상세 비교는
> [`../../../docs/PHP-8.1-HTTP-RCE-VALIDATION.md`](../../../docs/PHP-8.1-HTTP-RCE-VALIDATION.md)를
> 참고하세요.

```text
id>/out/p
```

## 검증 결과

- exact target: PHP `8.1.34`, Apache prefork/mod_php, `linux/amd64`
- official image digest:
  `mirror.gcr.io/library/php@sha256:72f0c0134922985022d55a39b0390d35dc7a10e961aa6c44fa35b4c3102f4268`
- image ID:
  `sha256:e6c924c6e862e6c74e01be964f88cb0c7ccbd673925e9a648cbbf77ff53b7ca1`
- `memory_limit=8M`, single persistent Apache worker
- fresh container 3회에서 서로 다른 ASLR 주소로 모두
  `uid=33(www-data) gid=33(www-data)` proof 생성
- 확인된 호출 경로:
  `php_session_rfc1867_callback` → `php_session_initialize` →
  `php_session_track_init` → `zend_reference_destroy` →
  `zend_array_destroy` → `zend_hash_destroy` → `zif_passthru`

## 중요한 한계

이 PoC는 **stand-alone 원격 exploit이 아닙니다**. runner가 target worker의 로컬
`/proc/<pid>/maps`와 `/proc/<pid>/mem`을 읽어 다음 두 ASLR 값을 보정한 뒤, HTTP
terminal chain에 전달합니다.

- `libphp.so` base
- Zend MM main chunk base

HTTP 요청 자체는 GDB나 ptrace 없이 실행되지만 주소 공급은 out-of-band 로컬
관찰입니다. 따라서 이 결과는 PHP 8.1.34의 RCE primitive와 terminal chain을
입증하며, 이 8 MiB 경로 자체는 원격 ASLR 우회를 입증하지 않습니다. PHP 8.1의
`php_session_reset_id()`는 PHP 8.4에서 사용한 Set-Cookie 누출과 다르게
`PS(send_cookie)`를 정리하므로 그 disclosure chain을 그대로 쓸 수 없습니다. 새
128 MiB profile은 Set-Cookie 경로를 재사용하지 않고 FILE_START OOM과 trans-SID를
조합합니다.

## 실행

runner는 인자를 받지 않으며 root 권한에서만 실행됩니다. root는 로컬 worker의
`/proc/<pid>/mem` 8바이트를 읽는 보정 단계에 필요합니다.

```bash
cd poc/legacy-calibrated-rce/php-8.1.34
sudo ./run-local-docker-lab.sh
```

runner는 다음 제한을 강제합니다.

1. target과 attacker image를 immutable digest로 고정합니다.
2. 새 Docker `--internal` network와 새 proof volume을 만들고 host port를 열지
   않습니다.
3. 외부 URL, image, offset, command 인자를 받지 않습니다.
4. attacker를 non-root, read-only, capability-free container로 실행합니다.
5. exact image ID, PHP version/SAPI, `memory_limit`, network와 port binding을
   확인합니다.
6. 종료 시 container, network와 volume을 제거하고 checksummed 관찰 자료를
   `artifacts/<UTC-run-id>/`에 남깁니다.

성공 출력의 핵심은 다음과 같습니다.

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
RCE_PROOF_PRESENT
```

## 구현 메모와 저작권

exact build에서 측정한 값은 다음과 같습니다.

| 항목 | 값 |
|---|---:|
| `zif_passthru` image offset | `0x36f480` |
| `zval_ptr_dtor` image offset | `0x457150` |
| `alloc_globals` image offset | `0xf12c18` |
| stale reference offset | `chunk + 0x74160` |
| forged HashTable address | `chunk + 0x74800` |

multipart lifecycle과 forged HashTable/spray 구현 일부는 MIT 라이선스의
[`78ResearchLab/PHP2Shell-Full-Chain-Exploit`](https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit)
commit `167085410a9342fafbd1bd64f5006920dbc83b8e`에서 수정했습니다. 원 저작권
고지와 MIT 전문은 상위 디렉터리의 `THIRD_PARTY_NOTICES.md`와
`THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt`에 보존합니다.
