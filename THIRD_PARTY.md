# Third-party material

이 저장소는 다음 프로젝트의 동작을 검토했지만 전체 소스나 수정본을 vendoring하지
않습니다.

| Project | Reviewed commit | License detected at review time | Treatment here |
|---|---|---|---|
| `cozybear-dev/cve-2026-109619` | `7a73bb50fbc9d0f5aafce9c135bf4cbf4575601b` | None | Runner가 사용자의 임시 디렉터리로 직접 checkout |
| `9bie/php2shell-bypass-aslr-exp` | `17e98ee81025cccfd94b4f9c9a17bf269c65ff75` | None | 결과와 commit link만 인용 |
| `Bulletdev/php2shell-poc` | `2d80235ccdf62bd01c1ef6ce36ae4a93b31c88cd` | None | 분석 결과와 commit link만 인용 |

`poc/run-wsl-docker-lab.sh`는 upstream 파일을 이 저장소에 포함하지 않습니다.
실행 시 지정 commit을 GitHub에서 임시 checkout하고, 검증된 포인터 하한 한 줄을
로컬에서 치환한 뒤 Docker lab을 종료하면서 checkout을 삭제합니다.

이 저장소의 문서나 runner는 위 upstream 코드에 관한 권리 또는 라이선스를
부여하지 않습니다. 자동 checkout과 로컬 수정도 upstream 라이선스를 생성하지
않습니다. runner 사용자는 해당 자료의 사용에 필요한 별도 허가 또는 적용 가능한
법적 근거를 직접 확인해야 합니다.

PHP 프로젝트의 advisory, commit 및 회귀 테스트는 링크로 참조합니다. 공개된
로그는 이 연구에서 해당 테스트를 실행해 얻은 관찰 출력입니다.

