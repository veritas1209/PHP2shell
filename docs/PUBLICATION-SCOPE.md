# 공개 가능 범위 검토

검토일: 2026-10-24

## 결론

이 저장소의 구성은 공개된 취약점에 관한 교육, 방어 검증 및 재현 가능한 보안
연구 자료로 제한했습니다. 이는 법률 의견이나 명시된 범위를 벗어난 시스템을
시험할 권한을 뜻하지 않습니다. 저장소의 사용 조건은 본인이 소유하거나 명시적인
허가를 받은 격리 환경으로 한정합니다.

공개 범위에는 다음 자료가 포함됩니다.

- 공식 PHP advisory, patch와 수정 릴리스 링크
- 격리된 WSL2 Docker lab에서 얻은 PHP 8.0.30, 8.1.34, 8.2.34, 8.3.35,
  8.4.26, 8.5.11 exact-build 결과
- PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 fixed-build 대조 결과
- `id>/out/p`로 고정한 `www-data` 권한 proof
- image digest/ID, `libphp` hash/build ID, runtime과 heap calibration을 묶은 profile
- 외부 target이나 임의 명령을 받지 않는 local-only multi-version runner
- PHP 8.1.34의 FILE_START/trans-SID HTTP-only 주소 누출과 3/3 fresh 고정 명령 proof
- PHP 5.4.45–7.4.33 여덟 exact build의 HTTP-only 고정 명령 proof, 고정 image와
  version-specific runtime configuration
- PHP 7.3.33/7.4.33/8.0.30 및 historical PHP 8.1.34 lab에서 local `/proc` 주소 보정 뒤 고정 명령의
  terminal RCE에 도달한 exact-build 실험기와 그 한계
- PHP 7.2.34의 초기 stale `zend_reference` 경로에서 확인한 blocker와, 이후 다른
  HTTP-only chain으로 3/3 proof에 도달한 결과의 구분

PHP 5.4–7.4 결과는 exact image와 runtime에 한정한 기술 연구 증거입니다. PHP
5.4–5.6의 주소 누출은 영향을 받은 POST 값을 worker 종료 전에 binary-safe로
반사하는 application endpoint를 전제로 합니다. 이는 PHP CNA가 열거한 공식
8.2–8.5 범위를 넓히거나 EOL branch에 공식 php-src backport가 존재한다고
주장하는 자료가 아닙니다. historical `/proc` 보정형 lab과 초기 no-RCE 개발
기록은 후속 HTTP-only profile의 입력이 아니라 독립적인 연구 이력으로 보존합니다.

다음 자료는 공개 대상에서 제외했습니다.

- 자격 증명, 토큰, 개인 이메일 및 로컬 사용자 경로
- Docker inspect의 host bind path와 unrelated container metadata
- 악성 실행 파일, persistence, C2, 외부 target 목록 또는 임의 명령 기능
- 제3자 공개 서비스나 워게임 인스턴스를 대상으로 한 실행 결과
- 명시적 라이선스가 없는 upstream PoC의 전체 소스 사본

## 실행 범위 제한

권장 runner `poc/multiversion/run-local-docker-lab.sh`는 command-line 인자를 받지
않고, bundled allow-list에 있는 여섯 exact profile만 실행합니다. 대상과 attacker
image는 immutable digest로 고정합니다. runner는 매 실행마다 새 internal Docker
network와 proof volume을 만들고 host port를 공개하지 않습니다. live container의
fingerprint를 profile과 대조한 뒤 고정 명령 `id>/out/p`만 사용하고, 실행 후
container, network, volume과 임시 파일을 정리합니다.

PHP 8.1 profile의 exploit과 주소 복원 경로는 target의 `/proc/<pid>/maps` 또는
`/proc/<pid>/mem`, GDB, ptrace를 사용하지 않습니다. 공통 runner는 profile의
single-worker 조건 확인에만 `/proc/*/comm`의 process name을 읽습니다.
B1 응답의 고정 trans-SID 표식과 반복된 `zval_ptr_dtor` 포인터가 fail-closed
검사를 모두 통과한 경우에만 B2를 구성합니다. profile 밖의 URL, image, address,
offset 또는 command를 공급하는 인터페이스는 제공하지 않습니다.

historical `poc/legacy-calibrated-rce/run-local-docker-lab.sh`도 command-line 인자를 거부하고
고정 exact images, 새 internal network와 고정 `id>/out/p`만 사용합니다. 이
runner는 로컬 `/proc/<worker>/maps`와 `/proc/<worker>/mem`을 읽어 ASLR 주소를
보정하므로 root가 필요하며, 그 사실을 코드·README·증거에 명시합니다. 외부 target
또는 임의 command로 바꾸는 인터페이스는 제공하지 않습니다.

이 제한은 외부 시스템을 시험할 수 있는 권한을 만들어 주지 않습니다. 사용자는
저장소 코드와 별개로 대상 소유권 또는 명시적인 시험 허가를 확보해야 합니다.

## 저작권 및 라이선스 처리

multi-version framework와 legacy calibrated lab의 request lifecycle, leak
sequence와 reclaim payload 일부는
다음 MIT 라이선스 프로젝트에서 일부를 수정·확장했습니다.

- Project: `78ResearchLab/PHP2Shell-Full-Chain-Exploit`
- Reviewed commit: `167085410a9342fafbd1bd64f5006920dbc83b8e`
- Reviewed `exploit.py` SHA-256:
  `6aadf7bc93b3f4f93b755fed727d3f017e806419c96853290cf2250e567c1323`
- License: MIT
- Copyright: Copyright (c) 2026 78ResearchLab

저작권 고지와 MIT 전문은 `poc/multiversion/THIRD_PARTY_NOTICES.md`,
`poc/multiversion/THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt` 및 해당 디렉터리의
`LICENSE`, 그리고 `poc/legacy-calibrated-rce/THIRD_PARTY_NOTICES.md`와
`poc/legacy-calibrated-rce/THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt`에
보존합니다.

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

