# Security and authorized-use policy

이 저장소는 CVE-2026-109618 및 CVE-2026-109619의 보안 연구, 교육, 패치 검증,
탐지 및 방어 개선을 위한 자료입니다.

## 허용 범위

- 본인이 소유한 격리된 lab
- 소유자로부터 명시적 시험 허가를 받은 시스템
- 방어 목적의 버전 확인, 패치 차등 검증 및 로그 분석

## 금지 범위

- 제3자 시스템 또는 운영 서비스에 대한 무단 실행
- 취약 시스템 침해, 지속성 확보, 데이터 접근 또는 서비스 방해
- 이 저장소를 공격 인프라, payload 전달망 또는 command-and-control에 사용

PoC runner는 외부 target을 받지 않고 고정된 Docker Compose lab만 실행하도록
구성했습니다. 연구 중 발견한 실제 취약 시스템 정보나 자격 증명을 issue에
게시하지 마세요.

콘텐츠 오용, 저작권 또는 공개 범위에 관한 문의는
[repository issue](https://github.com/veritas1209/PHP2shell/issues)로 알려주세요.
민감한 정보는 공개 issue에 첨부하지 마세요.

