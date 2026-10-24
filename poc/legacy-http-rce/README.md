# PHP 5.4–7.4 exact-build HTTP-only RCE labs

이 디렉터리는 PHP 5.4.45, 5.5.38, 5.6.40, 7.0.33, 7.1.33, 7.2.34,
7.3.33, 7.4.33의 고정 Apache 이미지에서 검증한 로컬 연구용 PoC를 담습니다.
각 최종 chain은 HTTP 응답에서 런타임 주소를 구하고, 고정 명령
`id>/out/p`만 실행합니다. 저장된 runner는 GDB, ptrace, `LD_PRELOAD`,
`/proc/*/maps`, `/proc/*/mem`을 사용하지 않습니다.

> [!CAUTION]
> **보안 연구·교육·방어 검증 목적으로만 사용하세요.** 본인이 소유하거나
> 명시적인 시험 허가를 받은 격리 환경에서만 실행해야 합니다. 제3자 시스템,
> 운영 서비스, 공개 워게임 서버 또는 허가받지 않은 네트워크에 적용하지
> 마세요. 관련 법률, 서비스 약관, 승인된 시험 범위를 준수할 책임은 사용자에게
> 있습니다.

> [!IMPORTANT]
> **Research-use only.** Run these profiles only in an isolated environment
> that you own or are explicitly authorized to test. Do not use them against
> third-party systems, production services, public wargame instances, or any
> network without prior permission.

## 공식 CVE 범위와 이 디렉터리의 의미

CVE-2026-109618/109619의 PHP CNA 레코드가 열거한 유지보수 stable branch는
PHP 8.2–8.5입니다. 이 디렉터리의 PHP 5.4–7.4 결과는 그 공식 제품 범위를
확장하는 선언이 아닙니다. 취약 코드 계보가 남아 있는 historical exact build에서
관찰한 **기술적 증거**입니다. PHP 7.4/8.0/8.1의 EOL source mitigation과 공식 범위의
차이는 [`../../docs/AFFECTED-SCOPE.md`](../../docs/AFFECTED-SCOPE.md)에 정리되어
있습니다.

## 검증 매트릭스

| Exact build | Fresh-ASLR HTTP-only RCE | HTTP 주소원 | Terminal primitive |
|---|---:|---|---|
| PHP 7.4.33 | 3/3 | 4 MiB trans-SID body | stale reference → fake HashTable → `zif_system` |
| PHP 7.3.33 | 3/3 | 4 MiB trans-SID body | raw-key partial Bucket → fake HashTable → `zif_system` |
| PHP 7.2.34 | 3/3 | 4 MiB trans-SID body | worker rollover + stale reference → `zif_system` |
| PHP 7.1.33 | 3/3 | 4 MiB trans-SID body | detached fake HashTable → libc `system` |
| PHP 7.0.33 | 4/4 | 1 MiB `Set-Cookie` value | detached fake HashTable → libc `system` |
| PHP 5.6.40 | 3/3 | reflected POST bytes → mbstring symbol | ZE2 fake HashTable → libc `system` |
| PHP 5.5.38 | 3/3 | reflected POST bytes → mbstring symbol | ZE2 fake HashTable → libc `system` |
| PHP 5.4.45 | 3/3 + independent fresh audit 2/2 | reflected POST bytes → mbstring symbol | ZE2 fake HashTable → libc `system` |

PHP 5.4–5.6의 주소 유출은 application response sink를 전제로 합니다. 번들된
`reflect.php`/`leak.php`처럼 영향을 받은 POST 값을 worker 종료 전에 binary-safe
형태로 응답해야 합니다. 따라서 이 결과만으로 모든 구형 PHP 애플리케이션이 같은
원격 주소 유출 surface를 가진다고 판단할 수 없습니다.

각 행은 디렉터리 안의 `REPORT.md`와, 제공되는 경우 `verification.json` 또는
`EVIDENCE.json`에서 exact image ID, binary hash, 주소식, 개별 실행값을 확인할 수
있습니다. 대용량 raw response, debugger trace, interposer, process map, calibration
utility는 공개 묶음에서 제외했습니다.

## 실행

runner는 WSL/Linux의 Docker CLI를 사용합니다. 필요한 immutable image가 로컬에
없으면 해당 `REPORT.md`의 digest를 먼저 받아야 합니다. runner 자체는 임의 image,
URL, 명령 또는 offset을 입력받지 않습니다.

한 버전만 실행하려면 해당 디렉터리에서 고유 label을 지정합니다.

```bash
cd poc/legacy-http-rce/php-7.0.33
./run-http-only.sh review-1
```

허용된 profile을 순서대로 실행하려면 상위 runner를 사용합니다.

```bash
./poc/legacy-http-rce/run-local-docker-lab.sh
```

하나만 선택할 때는 allow-list 값만 지정할 수 있습니다.

```bash
PHP2SHELL_LEGACY_VERSION=5.6 \
  ./poc/legacy-http-rce/run-local-docker-lab.sh
```

허용값은 `5.4`, `5.5`, `5.6`, `7.0`, `7.1`, `7.2`, `7.3`, `7.4`, `all`입니다.

모든 profile은 다음 경계를 적용합니다.

- target/attacker image digest와 image ID 검증
- 매 실행마다 새 Docker `--internal` network와 proof volume 생성
- host port 미공개
- attacker container read-only, capability drop, `no-new-privileges`
- terminal payload를 `id>/out/p`로 고정
- 실행 후 target, network, proof volume 정리

생성되는 `results/`는 Git에서 제외됩니다. 원본 검증 매트릭스는
[`VALIDATION.md`](VALIDATION.md), 공개 파일 무결성 값은
[`SHA256SUMS.txt`](SHA256SUMS.txt)를 참고하세요.
