# PHP2Shell: CVE-2026-109618 / CVE-2026-109619 재현 기록

WSL2의 격리된 Docker 환경에서 PHP의 OOM bailout 및 stale request-global state
취약점을 공식 패치 전후 빌드로 비교한 보안 연구 자료입니다. 공개 full-chain
기법을 exact-build profile로 제한해 PHP 8.2.34, 8.3.35, 8.4.26, 8.5.11에서
`www-data` 권한의 명령 실행을 확인했고, 대응하는 수정 릴리스에서는 같은 재현
절차가 disclosure 단계에서 중단되는 것을 확인했습니다.

> [!CAUTION]
> **보안 연구·교육·방어 검증 목적으로만 사용하세요.** 이 저장소의 자료와 PoC는
> 본인이 소유하거나 명시적인 시험 허가를 받은 격리 환경에서만 사용해야 합니다.
> 제3자 시스템, 운영 서비스, 공개 워게임 서버 또는 허가받지 않은 네트워크에
> 적용하지 마세요. 사용자는 관련 법률, 서비스 약관 및 승인된 시험 범위를 준수할
> 책임이 있습니다.

> [!IMPORTANT]
> **Research-use only.** Use this material only in an isolated environment that
> you own or are explicitly authorized to test. Do not use it against third-party
> systems, production services, public wargame instances, or networks without
> prior permission.

## 검증 결과

이 결과는 버전 계열 전체에 대한 지원 선언이 아닙니다. 아래에 적은 공식
`linux/amd64` Apache image digest, image ID, `libphp` hash/build ID, runtime 설정과
heap calibration이 일치하는 빌드만 실행 profile로 제공합니다.

| 취약 빌드 | 로컬 proof | 수정 빌드 대조군 | 동일 체인 결과 |
|---|---|---|---|
| PHP 8.2.34 | 5/5 fresh 실행에서 `uid=33(www-data)` | PHP 8.2.35 | 3/3 B1 heap pointer 없음, proof 없음 |
| PHP 8.3.35 | 2/2 독립 실행에서 `uid=33(www-data)` | PHP 8.3.36 | disclosure 실패, proof 없음 |
| PHP 8.4.26 | 4/4 기록된 실행에서 `uid=33(www-data)` | PHP 8.4.27 | stage-1 leak 실패, proof 없음 |
| PHP 8.5.11 | 2/2 독립 실행에서 `uid=33(www-data)` | PHP 8.5.12 | disclosure 실패, proof 없음 |

성공 판정은 interactive shell이 아니라 변조된 destructor가 고정 명령
`id>/out/p`를 호출해 target container의 새 `/out` volume에 proof를 생성했는지로
확인합니다. 재현은 ptrace 없이 수행했습니다.

PHP 8.2.34는 stock `php.ini-production`의 128M/`display_errors=Off` 환경에 맞춘
별도 `pure-http-oom-v1` profile을 사용합니다. PHP 8.1.34와 7.2.34는 실행
profile로 제공하지 않습니다. 이는 해당 버전이 취약하지 않다는 판정이 아닙니다.

## 권장 로컬 PoC

[`poc/multiversion/run-local-docker-lab.sh`](poc/multiversion/run-local-docker-lab.sh)는
검증된 네 profile만 허용하는 no-argument WSL/Linux Docker runner입니다. 기본
실행은 네 profile을 모두 순서대로 검사합니다.

```bash
chmod +x poc/multiversion/run-local-docker-lab.sh
./poc/multiversion/run-local-docker-lab.sh
```

runner는 다음 제한을 강제합니다.

- PHP target과 Python attacker image를 immutable digest로 고정
- 새 `--internal` Docker network와 새 proof volume 사용
- host port 미공개 및 외부 target/명령 인자 거부
- live target에서 runtime과 `libphp.so`를 관찰하고 profile fingerprint 검증
- proof 명령을 `id>/out/p`로 고정
- 실행 후 container, network, volume과 임시 파일 정리

특정 profile만 재검증하려면 runner에 정의된 allow-list ID를 환경 변수로 고를 수
있습니다. URL, image, offset 또는 명령은 선택할 수 없습니다.

```bash
PHP2SHELL_PROFILE_ID=php-8.5.11-apache-amd64-r0-spray \
  ./poc/multiversion/run-local-docker-lab.sh
```

기존 [`poc/run-wsl-docker-lab.sh`](poc/run-wsl-docker-lab.sh)는 초기 PHP 8.4.26/
8.4.27 조사 과정을 보존한 legacy runner입니다. 새 재현에는 exact-build 검증과
격리 제약을 포함한 multi-version runner를 사용하세요.

## 출처와 라이선스

multi-version framework의 request lifecycle, leak sequence와 packed `r0` spray는
MIT 라이선스의
[`78ResearchLab/PHP2Shell-Full-Chain-Exploit`](https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit)
commit `167085410a9342fafbd1bd64f5006920dbc83b8e`에서 일부를 수정·확장했습니다.
원 저작권 고지와 MIT 전문은
[`poc/multiversion/THIRD_PARTY_NOTICES.md`](poc/multiversion/THIRD_PARTY_NOTICES.md)와
`poc/multiversion/THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt`에 보존합니다.

라이선스가 확인되지 않은 다른 공개 PoC는 소스 파일을 vendoring하지 않고 prior
art, commit과 로컬 관찰 결과를 인용합니다. 자세한 범위는
[THIRD_PARTY.md](THIRD_PARTY.md)를 참고하세요.

## 문서와 증거

- [multi-version PoC 사용법](poc/README.md)
- [multi-version 릴리스 검증 기록](poc/multiversion/VALIDATION.md)
- [공개 가능 범위 검토](docs/PUBLICATION-SCOPE.md)
- [공식 자료 및 upstream 출처](REFERENCES.md)
- [제3자 코드 처리 범위](THIRD_PARTY.md)
- [상세 한국어 멀티버전·패치 차등 보고서](docs/REPORT.ko.md)
- [증거 SHA-256 manifest](evidence/SHA256SUMS.txt)

공식 권고와 수정 릴리스는 2026-10-21에 공개됐습니다. 운영 환경은 PoC 성공
여부와 관계없이 upstream 또는 배포판이 제공하는 검증된 수정 버전으로
업데이트해야 합니다.

