# Final WSL2 Docker PoC

> [!CAUTION]
> Run this only in an isolated Docker environment that you own or are explicitly
> authorized to test. The runner does not accept an external target.

The upstream PoC has no detected license, so its complete source is not copied
into this repository. The runner checks out the reviewed upstream commit into
a temporary directory, applies the verified one-line pointer-bound change, and
pins the attacker base image to the digest used in the validated run. This
repository grants no rights to upstream code; automatic checkout does not
create a license. Confirm that you have permission or another applicable legal
basis before using the upstream material.

## Run

WSL Ubuntu with snap Docker:

```bash
chmod +x poc/run-wsl-docker-lab.sh
sudo env DOCKER_BIN=/snap/bin/docker ./poc/run-wsl-docker-lab.sh
```

Standard Linux Docker:

```bash
./poc/run-wsl-docker-lab.sh
```

If the user already belongs to the Docker group, omit `sudo env` in WSL too.

The runner verifies the pinned commit and image digests, refuses arguments and
non-local Docker endpoints, fixes the Compose files and project name, and adds
an internal network plus resource and privilege limits. It creates fresh proof
volumes, runs both targets, copies the proof and log into
`artifacts/<timestamp>/`, and removes its containers, network, volumes and
temporary checkout.

