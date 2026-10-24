# Third-party notices

PHP 7.1–7.4의 HTTP disclosure clients는 이 저장소의
[`../multiversion`](../multiversion/) request framework를 import합니다. 해당
framework가 수정·확장한 78ResearchLab 코드의 저작권 고지와 MIT 전문은
[`../multiversion/THIRD_PARTY_NOTICES.md`](../multiversion/THIRD_PARTY_NOTICES.md)와
[`../multiversion/THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt`](../multiversion/THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt)에
보존되어 있습니다.

이 legacy package에는 PHP 또는 glibc binary를 vendoring하지 않습니다. Runner는
보고서에 기록된 immutable container image를 로컬 Docker image store에서
검증합니다.
