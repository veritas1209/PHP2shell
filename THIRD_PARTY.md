# Third-party material

이 저장소의 multi-version framework는 다음 MIT 라이선스 프로젝트에서 일부
코드를 수정·확장해 포함합니다.

| Project | Reviewed commit | License | Treatment here |
|---|---|---|---|
| [`78ResearchLab/PHP2Shell-Full-Chain-Exploit`](https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit) | `167085410a9342fafbd1bd64f5006920dbc83b8e` | MIT | request lifecycle, leak sequence 및 reclaim/spray 일부를 수정·확장하여 `poc/multiversion/`과 PHP 7.3/7.4/8.0 raw-key 및 PHP 8.1 stale-session lab을 포함한 `poc/legacy-calibrated-rce/`에 반영 |

검토한 upstream `exploit.py`의 SHA-256은
`6aadf7bc93b3f4f93b755fed727d3f017e806419c96853290cf2250e567c1323`입니다.
원 저작권은 `Copyright (c) 2026 78ResearchLab`이며, attribution과 license 전문은
다음 파일에 보존합니다.

- `poc/multiversion/THIRD_PARTY_NOTICES.md`
- `poc/multiversion/THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt`
- `poc/multiversion/LICENSE`
- `poc/legacy-calibrated-rce/THIRD_PARTY_NOTICES.md`
- `poc/legacy-calibrated-rce/THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt`

MIT 라이선스는 해당 고지와 조건에 따라 사용, 수정 및 재배포를 허용합니다. 이
저장소의 연구 전용 사용 안내는 시험 대상과 사용 행위를 제한하는 안전·권한
지침이며, 78ResearchLab 코드에 적용되는 MIT 저작권 고지와 허가 문구를 삭제하거나
대체하지 않습니다.

다음 프로젝트는 동작과 공개 결과를 검토했지만, 검토 시점에 명시적 라이선스를
확인하지 못해 전체 소스나 수정본을 vendoring하지 않습니다.

| Project | Reviewed commit | License detected at review time | Treatment here |
|---|---|---|---|
| `cozybear-dev/cve-2026-109619` | `7a73bb50fbc9d0f5aafce9c135bf4cbf4575601b` | None | Legacy runner가 사용자의 임시 디렉터리로 직접 checkout |
| `9bie/php2shell-bypass-aslr-exp` | `17e98ee81025cccfd94b4f9c9a17bf269c65ff75` | None | pure-HTTP A1/B1/A2/B2 단계와 알고리즘을 prior art로 검토; upstream source file은 포함하지 않고, 로컬에서 측정한 geometry를 범용 profile renderer로 표현 |
| `Bulletdev/php2shell-poc` | `2d80235ccdf62bd01c1ef6ce36ae4a93b31c88cd` | None | 분석 결과와 commit link만 인용 |

기존 `poc/run-wsl-docker-lab.sh`의 자동 checkout과 로컬 patch는 위
no-license upstream의 권리나 라이선스를 생성하지 않습니다. 사용자는 해당 자료를
사용하기 전에 별도 허가 또는 적용 가능한 법적 근거를 직접 확인해야 합니다.

PHP 프로젝트의 advisory, commit, release와 regression test는 링크로 참조합니다.
공개된 로그와 exact-build profile은 이 연구에서 격리 Docker 실험을 실행해 얻은
관찰 결과입니다.

