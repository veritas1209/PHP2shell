# PHP2Shell: CVE-2026-109618 / CVE-2026-109619 재현 기록

WSL2 Docker 환경에서 PHP의 OOM bailout 및 stale request-global state 취약점을
공식 패치 전후 버전으로 비교한 보안 연구 자료입니다. 공개된 full-chain PoC의
초기 실패 원인을 분석하고, PHP 8.4.26에서 `www-data` 권한의 명령 실행을 확인한
뒤 PHP 8.4.27에서 동일 체인이 차단되는지 검증했습니다.

> [!CAUTION]
> **보안 연구·교육·방어 검증 목적으로만 사용하세요.** 이 저장소의 자료와 PoC는
> 본인이 소유하거나 명시적인 시험 허가를 받은 격리 환경에서만 사용해야 합니다.
> 제3자 시스템, 운영 서비스 또는 허가받지 않은 네트워크에 적용하는 행위를
> 금지합니다. 사용자는 관련 법률, 서비스 약관 및 시험 범위를 준수할 책임이
> 있습니다.

> [!IMPORTANT]
> **Research-use only.** Use this material only in an isolated environment that
> you own or are explicitly authorized to test. Do not use it against third-party
> systems, production services, or networks without prior permission.

## 검증 결과

| 대상 | 결과 |
|---|---|
| PHP 8.4.26, pinned official image | `zif_system("id>/out/p")` 실행 성공 |
| 취약판 proof | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| PHP 8.4.27, pinned official image | stage-1 leak 실패, proof 없음 |
| 최종 Docker Compose 판정 | `RESULT: CONFIRMED`, exit code `0` |

최종 재현에서 취약판은 heap 주소와 `libphp` 주소를 누출한 뒤 stage 3 첫 시도에
명령을 실행했습니다. 이 결과는 대화형 shell이 아니라 변조된 `pDestructor`가
`zif_system()`을 호출해 서버 측 proof 파일을 생성한 RCE입니다.

초기 실패 원인은 exploit의 사용자 포인터 판별식이 native mapping을
`0x7f...`로 가정한 것이었습니다. WSL2에서는 같은 amd64 image가 다른 `0x7x...`
주소에 배치됐습니다. 원래 QEMU-user 상한을 유지하면서 하한만 넓혔습니다.

```diff
- return 0x7F0000000000 <= v < 0x0001000000000000
+ return 0x700000000000 <= v < 0x0001000000000000
```

## 최종 PoC

[`poc/run-wsl-docker-lab.sh`](poc/run-wsl-docker-lab.sh)는 검증한 upstream
커밋을 임시 디렉터리에 받아 검증한 포인터 하한 한 줄을 치환하고,
loopback에만 노출된 PHP 8.4.26/8.4.27 Docker A/B lab을 실행합니다.
PHP target과 attacker base image를 digest로 고정하며, 외부 target URL이나
인자를 받지 않습니다. 로컬 Unix Docker endpoint만 허용하고 실행 후
컨테이너·network·volume을 정리합니다.

```bash
chmod +x poc/run-wsl-docker-lab.sh
sudo env DOCKER_BIN=/snap/bin/docker ./poc/run-wsl-docker-lab.sh
```

가급적 WSL 사용자를 Docker group에 추가한 뒤 `sudo env` 없이 실행하세요.
일반 Linux Docker에서는 `DOCKER_BIN`을 생략할 수 있습니다. 실행 결과는 Git에서
제외되는 `artifacts/` 아래에 저장됩니다.

## 문서와 증거

- [상세 한국어 보고서](docs/REPORT.ko.md)
- [공개 가능 범위 검토](docs/PUBLICATION-SCOPE.md)
- [공식 자료 및 upstream 출처](REFERENCES.md)
- [제3자 코드 처리 범위](THIRD_PARTY.md)
- [최종 A/B 원시 로그](evidence/cozybear-compose-final-exact.log)
- [취약판 RCE proof](evidence/rce-proof.txt)
- [패치판 proof 부재 확인](evidence/fixed-proof-check.txt)
- [9bie B1 주소 누출 교차검증](evidence/9bie-b1-leak-diagnosis.txt)
- [증거 SHA-256 manifest](evidence/SHA256SUMS.txt)

## 공개 범위

공식 권고와 수정 릴리스는 2026-10-21에 공개됐습니다. GitHub 정책은 교육 및
보안 개선에 기여하는 dual-use 취약점 연구 자료의 게시를 허용합니다. 이
저장소는 악성 실행 파일, command-and-control 기능 또는 외부 공격 인프라를
포함하지 않습니다.

검토한 공개 PoC 저장소들은 명시적 라이선스가 없으므로 전체 소스를 이
저장소에 복사하지 않았습니다. 대신 원본 커밋을 고정해 참조하고, 이 연구에서
확인한 한 줄 치환을 수행하는 로컬 Docker 전용 runner만 제공합니다.
이 저장소는 upstream 코드에 관한 권리나 라이선스를 부여하지 않습니다. 자동
checkout도 라이선스를 생성하지 않으므로 runner 사용자는 upstream 사용에 필요한
별도 허가 또는 적용 가능한 법적 근거를 직접 확인해야 합니다.

패치된 릴리스는 PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12입니다. 운영 환경은 PoC
성공 여부와 관계없이 upstream 또는 배포판의 검증된 수정 버전으로 업데이트해야
합니다.

