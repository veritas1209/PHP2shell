# Legacy PHP locally calibrated RCE labs

> [!CAUTION]
> **보안 연구·교육·방어 검증 목적으로만 사용하세요.** 본인이 소유하거나
> 명시적인 시험 허가를 받은 격리 환경에서만 실행해야 합니다. 제3자 시스템,
> 운영 서비스, 공개 워게임 서버 또는 허가받지 않은 네트워크에 적용하지 마세요.

이 디렉터리는 PHP 8.2 이전 exact build에서도 PHP2Shell 계열의 stale-state/OOM
primitive가 실제 명령 실행까지 이어지는지를 분리해 검증합니다.

| Exact build | 검증 경로 | fresh 결과 | 주소 공급 | 실행기 |
|---|---|---:|---|---|
| PHP 7.3.33 Apache | raw-key partial `Bucket` → fake `HashTable` → libc `system()` | 3/3 fresh 개발 재현 | 로컬 `/proc`에서 `arData`와 libc base 보정 | [`raw-key-partial-bucket/`](raw-key-partial-bucket/) |
| PHP 7.4.33 Apache | raw-key partial `Bucket` → fake `HashTable` → libc `system()` | 3회 개발 재현 + 게시용 runner 재현 | 로컬 `/proc`에서 `arData`와 libc base 보정 | [`raw-key-partial-bucket/`](raw-key-partial-bucket/) |
| PHP 8.0.30 Apache | raw-key partial `Bucket` → fake `HashTable` → libc `system()` | 3/3 fresh 개발 재현 | 로컬 `/proc`에서 `arData`와 libc base 보정 | [`raw-key-partial-bucket/`](raw-key-partial-bucket/) |
| PHP 8.1.34 Apache | stale `zend_reference` → fake `HashTable` → `zif_passthru` | 개발 재현 3회 + 게시용 runner 3회 | 로컬 `/proc`에서 libphp와 Zend MM chunk base 보정 | [`php-8.1.34/`](php-8.1.34/) |

네 exact build 모두 `uid=33(www-data) gid=33(www-data)` proof를 생성했습니다.
하지만 raw-key shared runner와 PHP 8.1 runner 두 하위 runner는 ASLR 주소를
HTTP 응답에서 얻지 않습니다. Docker host의 로컬
`/proc/<worker>/maps`와 `/proc/<worker>/mem`을 읽으므로, 이는 **terminal RCE
primitive 검증기**이며 standalone remote exploit 또는 HTTP-only ASLR bypass가
아닙니다.

각 runner는 인자를 받지 않고 다음 경계를 고정합니다.

- immutable target/attacker image digest와 expected image ID
- 매 실행마다 새 Docker `--internal` network, host port 미공개
- 외부 target과 임의 command 입력 없음
- proof 명령 `id>/out/p`
- non-root, read-only, capability-free attacker container
- 실행 후 container, network와 proof volume 정리

실행에는 Linux/WSL, 로컬 Unix Docker socket과 root 권한이 필요합니다. 기본
dispatcher는 두 하위 runner를 통해 네 exact build를 차례로 실행합니다.

```bash
sudo ./run-local-docker-lab.sh
```

하나만 실행하려면 고정 allow-list selector를 사용할 수 있습니다. URL, image,
offset 또는 command를 바꿀 수는 없습니다.

```bash
sudo PHP2SHELL_LEGACY_PROFILE_ID=php-8.1.34 ./run-local-docker-lab.sh
sudo PHP2SHELL_LEGACY_PROFILE_ID=raw-key-partial-bucket \
  PHP2SHELL_RAWKEY_PROFILE_ID=php-7.4.33 ./run-local-docker-lab.sh
```

상위 selector의 허용 값은 `all`, `raw-key-partial-bucket`, `php-8.1.34`입니다.
raw-key 하위 runner의 exact-build selector는 해당 디렉터리 README에 정리했습니다.

각 exact build의 README에서 이미지, 환경, 주소 보정 방식과 구현 한계를
확인하세요.

코드 일부는 MIT 라이선스의 78ResearchLab 연구에서 수정·확장했습니다. 원 저작권
고지와 라이선스는 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) 및
[`THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt`](THIRD_PARTY_LICENSES/78ResearchLab-MIT.txt)에
보존합니다.
