# PHP 7.3–8.0 raw-key partial-Bucket locally calibrated RCE lab

> [!CAUTION]
> **보안 연구·교육·방어 검증 목적으로만 사용하세요.** 본인이 소유하거나
> 명시적인 시험 허가를 받은 격리 환경에서만 실행해야 합니다. 제3자 시스템,
> 운영 서비스, 공개 워게임 서버 또는 허가받지 않은 네트워크에 적용하지
> 마세요.

이 패키지는 다음 공식 Docker Apache exact build에서 raw-key allocation OOM이
남기는 partial `Bucket`을 fake `HashTable`로 연결해, 고정 명령
`id>/out/p`가 Apache worker 권한으로 실행되는지 확인한다.

| Profile ID | Immutable target | Image ID | Runtime |
|---|---|---|---|
| `php-7.3.33` | `mirror.gcr.io/library/php@sha256:b9872cd287ef72bc17d45d713aa2742f3d3bcf2503fea2506fd93aa94995219f` | `sha256:35da9118b3c0980fbaf84a4d410653642c9d55fb2f6c40011cc78de303837d64` | PHP 7.3.33, Apache 2.4.52, `apache2handler` |
| `php-7.4.33` | `mirror.gcr.io/library/php@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d` | `sha256:20a3732f422b7b28dcf99e8597f093a8c135efca62ff0dc02a2d92d916369413` | PHP 7.4.33, Apache 2.4.54, `apache2handler` |
| `php-8.0.30` | `mirror.gcr.io/library/php@sha256:c87b4c94d53b35520467b6d026f38656ab9a6d446fa3a0fbba1bc633125f9ad2` | `sha256:3357132d6ece3a509ce6f8abf6e7cf9886b343c504cb58428a7302cbe7abe446` | PHP 8.0.30, Apache 2.4.56, `apache2handler` |

공격자 이미지는
`python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704`
및 image ID
`sha256:a33c10a97f11005523814c6eee013986119fe41f3122f444518117536675c8e1`로
고정된다.

## 검증 범위와 한계

세 profile 모두 exact image에서 terminal RCE primitive를 검증한다. 그러나
standalone remote exploit 또는 HTTP-only ASLR bypass는 아니다. control 요청
뒤 runner가 Docker host의 `/proc/<apache-worker>/maps`와
`/proc/<apache-worker>/mem`을 root로 읽어 다음 주소를 보정한다.

- 재사용된 320-byte Zend-MM block의 `arData`
- exact target libc의 runtime `system()` 주소

원격 HTTP client는 이 `/proc` 접근 권한을 갖지 않는다. 이 결과는 주소가
로컬 계측으로 주어졌을 때 OOM 상태 손상에서 실제 `www-data` 명령 실행까지
이어지는지를 분리해 입증한다.

세 버전은 같은 측정 geometry를 사용한다.

- 264-byte query value와 8-entry mixed `HashTable`: Zend-MM 320-byte bin
- `Bucket`: 32 bytes
- fake `HashTable`: 56 bytes, `pDestructor` offset 48
- stale zval: `IS_ARRAY_EX=0x307`
- raw key length: 7,400,000
- lab: `memory_limit=32M`, single prefork worker

libc symbol offset은 profile에 공통으로 hard-code하지 않는다. runner는 exact
container에서 libc를 복사해 build ID와 SHA-256을 확인한 뒤 ELF `system`
symbol을 읽는다. PHP 7.3의 measured offset은 `0x48e50`, PHP 7.4와 8.0은
`0x45e50`이며 libc build ID는 모두 다르다.

## 실행

Linux 또는 WSL의 로컬 Unix Docker daemon에서 root로 실행한다. runner는
인자를 받지 않으며 기본값은 세 profile 모두이다.

```bash
sudo ./run-local-docker-lab.sh
```

하나만 실행하려면 아래 allow-list selector만 사용할 수 있다.

```bash
sudo PHP2SHELL_RAWKEY_PROFILE_ID=php-7.3.33 ./run-local-docker-lab.sh
sudo PHP2SHELL_RAWKEY_PROFILE_ID=php-7.4.33 ./run-local-docker-lab.sh
sudo PHP2SHELL_RAWKEY_PROFILE_ID=php-8.0.30 ./run-local-docker-lab.sh
```

허용 값은 `all`, `php-7.3.33`, `php-7.4.33`, `php-8.0.30`뿐이다. URL,
image, address, offset 또는 command를 runner 환경이나 인자로 바꿀 수 없다.

정상 실행은 profile별 ASLR 보정값, 다음 proof와 artifact 위치를 출력한다.

```text
PROC_ARDATA=0x...
PROC_SYSTEM=0x...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
php-7.x.xx: RCE_PROOF_PRESENT
artifacts: .../artifacts/raw-key-partial-bucket/<run-id>
```

## 격리와 fail-closed 검사

각 profile 실행은 다음 경계를 새로 만들고 확인한다.

- immutable target/attacker digest, expected image ID, linux/amd64
- fresh Docker `--internal` network와 host port 미공개 상태
- target의 exact PHP version, Apache version, `apache2handler` SAPI,
  32M memory limit, prefork/mod_php module
- 단 하나의 Apache worker와 host `/proc`의 UID/GID 33 identity
- exact libphp 및 libc build ID, libc SHA-256과 `system` ELF value
- non-root `65532:65532` attacker, read-only rootfs, `--cap-drop ALL`,
  `no-new-privileges`
- 격리 proof volume의 `/out/p` 및 소스/증거 SHA-256 manifest
- 성공과 실패 모두에서 container, network, proof volume cleanup

Docker endpoint 선택 순서는 실제 CLI 환경 우선순위를 따른다.
`DOCKER_CONTEXT`가 `DOCKER_HOST`보다 우선하고, 둘 다 없을 때 current context를
사용한다. effective endpoint가 `unix://`가 아니면 `docker info`를 호출하기
전에 거부한다.

## 파일

- `run-local-docker-lab.sh`: 무인자 multi-profile runner
- `probe.py`: 세 profile이 공유하는 고정 target/payload client
- `calibrate_local.py`: 공유 local `/proc` address calibrator
- `verify_lab.py`: image, network, container, runtime, worker verifier
- `lab/`: 고정 PHP/Apache 설정과 최소 runtime endpoint
- `THIRD_PARTY_NOTICES.md`: 선행 연구와 MIT 고지

각 실행 artifact에는 inspect JSON, runtime/worker/ELF fingerprint, maps,
보정값, target log, proof, `SOURCE_SHA256SUMS.txt`, `SHA256SUMS.txt`가 남는다.
