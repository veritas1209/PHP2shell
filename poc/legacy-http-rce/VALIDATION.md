# Legacy HTTP-only validation manifest

검증일: 2026-10-24 (Asia/Seoul)

성공 판정은 새 Docker volume의 `/out/p`가
`uid=33(www-data) gid=33(www-data)`로 시작하는지로 결정했습니다. 모든 행은 fresh
container/ASLR 실행이며, target에는 host port가 없고 Docker-internal network만
연결했습니다.

| Version | Target image digest | Success | Final address source |
|---|---|---:|---|
| 7.4.33 | `mirror.gcr.io/library/php@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d` | 3/3 | HTTP B1 trans-SID disclosure |
| 7.3.33 | `mirror.gcr.io/library/php@sha256:b9872cd287ef72bc17d45d713aa2742f3d3bcf2503fea2506fd93aa94995219f` | 3/3 | HTTP B1 trans-SID disclosure |
| 7.2.34 | `php@sha256:4dc0f0115acf8c2f0df69295ae822e49f5ad5fe849725847f15aa0e5802b55f8` | 3/3 | HTTP B1 trans-SID disclosure |
| 7.1.33 | `mirror.gcr.io/library/php@sha256:70eefcf4372b279101259e905996b7733a87688d0b48625af01b55947836bb1f` | 3/3 | HTTP B1 trans-SID disclosure |
| 7.0.33 | `mirror.gcr.io/library/php@sha256:1d34b2e491a02ba7a8d26478132015e197a5ffea37f0a93b42621d11cfe042cc` | 4/4 | HTTP B1 `Set-Cookie` disclosure |
| 5.6.40 | `mirror.gcr.io/library/php@sha256:0a40fd273961b99d8afe69a61a68c73c04bc0caa9de384d3b2dd9e7986eec86d` | 3/3 | reflected POST bytes (`mbfl_encoding_ascii`) |
| 5.5.38 | `mirror.gcr.io/library/php@sha256:be7f9332d3bea49084d74a0718a5400f7b5d128c1937575e76f72df3a41e8eac` | 3/3 | reflected POST bytes (`mbfl_encoding_ascii`) |
| 5.4.45 | `mirror.gcr.io/eugenesia/php@sha256:5681afdd0e07c7cbbece3f9cde77e5b7281768f54e1a2bbba319833c1ef638a9` | 3/3 + audit 2/2 | reflected POST bytes (`mbfl_encoding_ascii`) |

공개 최종 runner의 실행 경로에는 `/proc/`, GDB, ptrace, `LD_PRELOAD`, Docker
socket mount, host port publishing, 임의 target 또는 임의 명령 입력이 없습니다. 각
runner는 고정된 exact image와 `id>/out/p`만 사용합니다. PHP 7.1–7.4의 disclosure 단계는
기존 `poc/multiversion` request builder를 읽기 전용으로 mount합니다.

PHP 5.4–5.6은 application endpoint가 affected POST 값을 worker 종료 전에
binary-safe로 응답하는 조건이 추가로 필요합니다. 이 조건과 exact-build allocator
geometry 때문에 이 매트릭스는 버전 계열 전체에 대한 portable exploit 지원 선언이
아닙니다.
