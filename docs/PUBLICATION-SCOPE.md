# 공개 가능 범위 검토

검토일: 2026-10-23

## 결론

이 저장소의 구성은 공개된 취약점에 관한 교육, 방어 검증 및 재현 가능한 보안
연구 자료로 제한했습니다. 이는 법률 의견이나 명시된 범위를 벗어난 시스템을
시험할 권한을 뜻하지 않습니다. 저장소의 사용 조건은 본인이 소유하거나 명시적인
허가를 받은 격리 환경으로 한정합니다.

공개 범위에는 다음 자료가 포함됩니다.

- 공식 PHP advisory, patch와 수정 릴리스 링크
- 격리된 WSL2 Docker lab에서 얻은 PHP 8.2.34, 8.3.35, 8.4.26, 8.5.11 exact-build 결과
- PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 fixed-build 대조 결과
- `id>/out/p`로 고정한 `www-data` 권한 proof
- image digest/ID, `libphp` hash/build ID, runtime과 heap calibration을 묶은 profile
- 외부 target이나 임의 명령을 받지 않는 local-only multi-version runner
- PHP 8.1/7.2에 현재 disclosure chain을 포팅하지 못한 구조적 이유

마지막 항목은 해당 버전이 안전하거나 취약하지 않다는 결론이 아닙니다. 검증한
사실은 현재 체인이 요구하는 session-cookie disclosure가 성립하지 않았다는
것뿐이며, 별도의 primitive를 이용하는 체인은 본 공개 PoC의 범위 밖입니다.

다음 자료는 공개 대상에서 제외했습니다.

- 자격 증명, 토큰, 개인 이메일 및 로컬 사용자 경로
- Docker inspect의 host bind path와 unrelated container metadata
- 악성 실행 파일, persistence, C2, 외부 target 목록 또는 임의 명령 기능
- 제3자 공개 서비스나 워게임 인스턴스를 대상으로 한 실행 결과
- 명시적 라이선스가 없는 upstream PoC의 전체 소스 사본

## 실행 범위 제한

권장 runner `poc/multiversion/run-local-docker-lab.sh`는 command-line 인자를 받지
않고, bundled allow-list에 있는 네 exact profile만 실행합니다. 대상과 attacker
image는 immutable digest로 고정합니다. runner는 매 실행마다 새 internal Docker
network와 proof volume을 만들고 host port를 공개하지 않습니다. live container의
fingerprint를 profile과 대조한 뒤 고정 명령 `id>/out/p`만 사용하고, 실행 후
container, network, volume과 임시 파일을 정리합니다.

이 제한은 외부 시스템을 시험할 수 있는 권한을 만들어 주지 않습니다. 사용자는
저장소 코드와 별개로 대상 소유권 또는 명시적인 시험 허가를 확보해야 합니다.

## 저작권 및 라이선스 처리

multi-version framework의 request lifecycle, leak sequence와 packed `r0` spray는
다음 MIT 라이선스 프로젝트에서 일부를 수정·확장했습니다.

- Project: `78ResearchLab/PHP2Shell-Full-Chain-Exploit`
- Reviewed commit: `167085410a9342fafbd1bd64f5006920dbc83b8e`
- Reviewed `exploit.py` SHA-256:
  `6aadf7bc93b3f4f93b755fed727d3f017e806419c96853290cf2250e567c1323`
- License: MIT
- Copyright: Copyright (c) 2026 78ResearchLab

저작권 고지와 MIT 전문은 `poc/multiversion/THIRD_PARTY_NOTICES.md`,
`poc/multiversion/THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt` 및 해당 디렉터리의
`LICENSE`에 보존합니다.

`cozybear-dev/cve-2026-109619`, `9bie/php2shell-bypass-aslr-exp`,
`Bulletdev/php2shell-poc`는 검토 시점의 GitHub metadata에서 명시적 라이선스를
확인하지 못했습니다. 이 저장소는 해당 소스 파일을 vendoring하지 않고 URL,
commit SHA와 로컬에서 재현·검증한 관찰 결과를 인용합니다. 기존 PHP 8.4 legacy runner의
임시 checkout은 upstream 코드의 라이선스나 권리를 새로 부여하지 않습니다.

## 사용 조건

이 공개 판단은 허가받은 보안 연구, 교육 및 방어 검증을 전제로 합니다. 저장소를
제3자 시스템에 대한 무단 접근, 서비스 방해 또는 실제 공격에 사용하는 것은
README와 SECURITY.md에 명시된 범위를 벗어납니다.

> **Research-use only.** Publication of this material does not grant permission
> to test any system. Use it only in an isolated environment you own or are
> explicitly authorized to assess.

