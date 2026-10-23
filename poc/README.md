# Local Docker PoC runners

> [!CAUTION]
> **보안 연구 및 방어 검증 전용입니다.** 본인이 소유하거나 명시적으로 시험을
> 허가받은 격리 Docker 환경에서만 실행하세요. 공개 워게임 서버, 운영 서비스,
> 제3자 시스템에는 실행하지 마세요.

> **Research-use only.** Run these tools only in an isolated Docker environment
> that you own or are explicitly authorized to test. Do not use them against a
> third-party, production, or public wargame target.

## Recommended: exact-profile multi-version runner

[`multiversion/run-local-docker-lab.sh`](multiversion/run-local-docker-lab.sh)는
다음 네 exact official PHP Apache `linux/amd64` build만 실행합니다.

| Profile ID | 검증 결과 |
|---|---|
| `php-8.2.34-apache-amd64-pure-http-oom` | 5/5 fresh proof; PHP 8.2.35 fixed control 3/3 blocked |
| `php-8.3.35-apache-amd64-r0-spray` | 2/2 ptrace-free proof |
| `php-8.4.26-apache-amd64-fixed-carrier` | 4/4 documented proof |
| `php-8.5.11-apache-amd64-r0-spray` | 2/2 ptrace-free proof |

이 네 profile은 runner의 exact-build **지원 범위**입니다. 취약점 전체 범위와
같지 않습니다. PHP CNA의 공식 stable matrix는 8.2–8.5이고, PHP 프로젝트는
EOL인 7.4/8.0/8.1에 최소 소스 완화를 제공했습니다. Calif/Wiz 연구진은
버전·SAPI별 경로를 구분해 PHP 5.4.0까지 기술적 영향을 확인했다고 보고합니다.
PHP 5.4–7.3에는 CNA 열거도 공식 php-src backport도 없습니다. 자세한 구분은
[`../docs/AFFECTED-SCOPE.md`](../docs/AFFECTED-SCOPE.md)를 참고하세요.

기본 실행은 네 profile을 모두 순서대로 검사합니다. script는 command-line 인자를
받지 않습니다.

```bash
chmod +x poc/multiversion/run-local-docker-lab.sh
./poc/multiversion/run-local-docker-lab.sh
```

WSL Ubuntu에서 snap Docker를 사용해도 script가 `/snap/bin/docker`를 자동으로
찾습니다. 현재 사용자가 Docker socket에 접근할 수 있어야 합니다.

한 profile만 실행하려면 bundled allow-list에서 ID를 고를 수 있습니다.

```bash
PHP2SHELL_PROFILE_ID=php-8.3.35-apache-amd64-r0-spray \
  ./poc/multiversion/run-local-docker-lab.sh
```

이 selector는 외부 target, 임의 image, offset 또는 명령을 받지 않습니다. runner는
고정된 image digest와 image ID를 확인하고, 다음 안전 경계를 강제합니다.

1. local Unix Docker endpoint만 허용합니다.
2. 매 profile마다 새 `--internal` network와 새 `/out` volume을 만들며 host port를
   공개하지 않습니다.
3. live target의 image/platform/network, Apache SAPI와 prefork worker 수, runtime
   설정, `libphp.so` SHA-256/build ID/symbol을 profile과 대조합니다.
4. read-only, capability-free attacker container에서 표준 라이브러리만으로 실행하고
   명령을 `id>/out/p`로 고정합니다.
5. proof와 checksummed 관찰 자료를 `artifacts/multiversion/<UTC-run-id>/`에 남긴 뒤
   container, network, volume과 임시 `libphp.so`를 제거합니다.

수정판 PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 대조 실험에서는 같은 체인이
disclosure 단계에서 실패했고 proof가 생성되지 않았습니다. PHP 8.1.34와
7.2.34에는 실행 profile이 없습니다. 이는 해당 branch의 취약성 여부를
부정하거나 공개된 PHP 5.4+ 연구 범위를 축소하는 결론이 아닙니다.

framework와 profile 형식의 상세 설명은
[`multiversion/FRAMEWORK.md`](multiversion/FRAMEWORK.md), 지원 경계는
[`multiversion/SUPPORT.md`](multiversion/SUPPORT.md)에 있습니다.

## PHP 5.4–8.1 benign scope probe

[`legacy-scope-probe/run-local-docker-lab.sh`](legacy-scope-probe/run-local-docker-lab.sh)는
PHP 5.4.45부터 8.1.34까지 각 minor branch의 마지막 Apache build에서
default-enabled upload-progress callback이 application script 전에 Session 값을
만드는지만 확인합니다. 고정된 1 MiB inert upload를 사용하며 OOM, fake object,
command payload 또는 RCE 단계를 포함하지 않습니다.

```bash
chmod +x poc/legacy-scope-probe/run-local-docker-lab.sh
./poc/legacy-scope-probe/run-local-docker-lab.sh
```

이 probe의 성공은 pre-script upload-progress callback이라는 선행 표면만 해당
exact build에서 확인합니다. 구버전의 end-to-end 취약성이나 RCE 성공 판정으로
사용하면 안 됩니다. 결과와 한계는
[`../docs/LEGACY-RUNTIME-MATRIX.md`](../docs/LEGACY-RUNTIME-MATRIX.md)에 있습니다.

## Legacy PHP 8.4 runner

[`run-wsl-docker-lab.sh`](run-wsl-docker-lab.sh)는 PHP 8.4.26/8.4.27 초기 A/B
조사를 재현하는 legacy runner입니다. 라이선스가 확인되지 않은 upstream commit을
임시 checkout하고 최소 patch를 적용하는 기존 방식을 보존합니다. 그 upstream
소스의 권리를 이 저장소가 부여하지는 않습니다.

새 실험에는 bundled MIT notices, exact-build profiles, live fingerprinting,
internal-only network를 갖춘 multi-version runner를 권장합니다.

## Third-party attribution

multi-version framework는 MIT 라이선스의
`78ResearchLab/PHP2Shell-Full-Chain-Exploit` commit
`167085410a9342fafbd1bd64f5006920dbc83b8e`에서 일부 코드를 수정·확장했습니다.
저작권 고지와 MIT 전문은
[`multiversion/THIRD_PARTY_NOTICES.md`](multiversion/THIRD_PARTY_NOTICES.md)와
`multiversion/THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt`에 포함되어 있습니다.

