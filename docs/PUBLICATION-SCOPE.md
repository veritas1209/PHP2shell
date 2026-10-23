# 공개 가능 범위 검토

검토일: 2026-10-23

## 결론

이 저장소의 구성은 GitHub의 dual-use exploit 정책이 허용하는 보안 연구 범위로
판단했습니다. 이는 법률 의견이나 제3자 저작물의 이용 허락을 뜻하지 않습니다.
공식 PHP 보안 권고와 수정 릴리스는 이미 공개됐고, GitHub는 교육·취약점 연구·
보안 개선에 기여하는 자료를 허용합니다. GitHub가 권장하는 유해 가능성 안내와
SECURITY.md의 연락 경로도 반영했습니다.

공개 범위는 다음과 같이 제한했습니다.

- 본인이 통제하는 WSL2 Docker lab의 검증 결과
- 공식 advisory와 패치 전후 회귀 테스트
- `id>/out/p`로 제한한 `www-data` 권한 proof
- WSL2 포인터 필터 실패 원인과 최소 diff
- 외부 target을 받지 않는 로컬 Docker A/B runner

다음 자료는 제외했습니다.

- 자격 증명, 토큰, 개인 이메일 및 로컬 사용자 경로
- Docker inspect의 host bind path와 unrelated container metadata
- 악성 실행 파일, persistence, C2 또는 외부 target 목록
- 명시적 라이선스가 없는 upstream PoC의 전체 소스 사본

## 저작권 처리

`cozybear-dev/cve-2026-109619`, `9bie/php2shell-bypass-aslr-exp`,
`Bulletdev/php2shell-poc`는 검토 시점의 GitHub metadata에 명시적 라이선스가
없었습니다. 이 저장소는 해당 소스를 vendoring하지 않고 URL과 commit SHA로
참조합니다. 최종 PoC는 사용자가 upstream commit을 직접 checkout한 뒤 이
연구에서 작성한 최소 patch를 적용하는 방식입니다.

runner와 문서가 upstream 코드의 권리나 라이선스를 부여하는 것은 아닙니다.
자동 checkout도 라이선스를 생성하지 않으므로 사용자는 별도 허가 또는 적용
가능한 법적 근거가 있는지 직접 확인해야 합니다.

## 사용 조건

이 공개 판단은 허가받은 보안 연구와 방어 검증을 전제로 합니다. 저장소를
제3자 시스템에 대한 무단 접근, 서비스 방해 또는 실제 공격에 사용하는 것은
README와 SECURITY.md의 사용 범위를 벗어납니다.

