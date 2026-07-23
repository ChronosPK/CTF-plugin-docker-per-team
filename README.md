# `docker_per_team` Runtime Contract

This plugin runs one isolated challenge container per team or user. The repository uses direct
mode: Docker publishes one random host TCP port for each instance. Every CTFd process is bound to
one immutable event, release, target, image namespace, and challenge network.

## Required process identity

The CTFd process must provide all of these values:

```text
CTF_EVENT_ID=cybersea26
CTF_RELEASE_ID=development
CTF_TARGET_ID=local
CTF_CHALLENGE_NETWORK=cybersea26_challenge_net
CTF_IMAGE_PREFIX=cybersea/
CTF_EGRESS_POLICY=not-enforced
CTF_CHALLENGE_BIND_IP=127.0.0.1
```

`CTF_TARGET_ID` is `local`, `staging`, or `production`. Staging and production require:

- `CTF_EGRESS_POLICY=worker-firewall-default-deny`;
- an event-owned Docker network carrying the same egress-policy label;
- image references under the event prefix.

Production additionally requires a non-placeholder release ID and image references pinned by
`@sha256` digest. Set `CTF_CHALLENGE_BIND_IP` to the deliberate worker ingress address; local
Compose defaults to loopback so challenge ports are not accidentally exposed to the LAN.

These values are process configuration, not mutable admin settings. The admin-only
`/containers/admin/api/runtime` endpoint returns the non-secret identity and enforced policy for
deployment doctors.

Cloud deployments may provide immutable worker settings:

```text
CTF_DOCKER_BASE_URL=ssh://ctfworker@10.0.0.8
CTF_DOCKER_PUBLIC_HOSTNAME=challenges.cybersea.ro
```

These override database defaults at runtime, so a new CTFd database can boot without first storing
a worker endpoint through the admin UI. Staging and production reject the local socket and
unencrypted `tcp://`; they require an `ssh://user@host[:port]` endpoint without embedded passwords.
Mount the worker private key and pinned `known_hosts` file from the target secret provider.

## Local setup

Create separate application and challenge networks for the intended event:

```bash
cd Infrastructure/CTFd
./scripts/create-local-networks.sh cybersea26
```

For the yearly CSCTF instance, use `csctf26` instead. The helper refuses an omitted or malformed
event ID and validates existing network labels/options instead of silently reusing them.

The local challenge bridge is deliberately non-internal because Docker direct-mode port publishing
does not work on an internal bridge. Inter-container communication is disabled, CTFd is not attached
to the challenge bridge, and the network is labelled `ctfd.egress_policy=not-enforced`. A bridge
alone does not deny outbound access. Staging and production need a separately provisioned and
tested host/cloud firewall before their network may be labelled
`worker-firewall-default-deny`.

Start the corresponding stack:

```bash
# CSCTF 2026
SECRET_KEY='<local-only-random-value>' docker compose up -d

# CyberSea 2026
SECRET_KEY='<local-only-random-value>' \
  docker compose -f docker-compose.cybersea26.yml up -d
```

The challenge network must never be the CTFd/MariaDB/Redis application network.

## Enforced runtime baseline

The plugin refuses to initialize if Docker cannot enforce memory, memory+swap, CPU CFS, or PID
limits. Each spawned challenge receives:

- event, release, target, egress, and bind-address ownership labels;
- the exact event-owned challenge network;
- all Linux capabilities dropped before any explicitly allowlisted additions;
- `no-new-privileges`;
- a read-only root filesystem;
- bounded `/tmp` tmpfs;
- positive memory, memory+swap, CPU, and PID limits;
- an init process;
- bounded `json-file` log rotation;
- a startup deadline and health wait.

The image must declare a non-root `USER`, a Docker `HEALTHCHECK`, and the configured TCP `EXPOSE`
port. An instance is recorded and returned to the player only after it becomes healthy. Volumes
remain disabled by default; when globally enabled, the runtime accepts only read-only mappings and
does not allow a volume to replace managed `/tmp`. Capability requests are rechecked against the
current global allowlist at launch time.

Lifecycle operations require matching event and target labels. Bulk running-container discovery is
filtered the same way, so one CTFd instance cannot kill or adopt another event/target's containers.

## Admin settings

Normal settings:

- `docker_base_url`
- `docker_hostname`
- `docker_api_timeout`
- `challenge_network` (displayed in the UI, but fixed by `CTF_CHALLENGE_NETWORK`)
- `container_expiration`
- `max_containers`
- `container_maxmemory`
- `container_maxcpu`
- `container_pids_limit`
- `container_tmpfs_size_mb`
- `container_log_max_size`
- `container_log_max_files`
- `container_start_timeout_seconds`

Advanced settings:

- `allow_challenge_volumes`
- `allowed_capabilities`

All resource and lifetime settings must be greater than zero. `allowed_capabilities` is a global
allowlist such as `NET_ADMIN,NET_RAW`; leaving it blank disallows every extra capability.

## Per-challenge fields

Supported fields are:

- `image`
- `internal_port` in `challenge.yml` / `port` in the CTFd API
- `connection_type` (`web` or `tcp`)
- `flag_mode` (`static` or `random`)
- `flag_prefix`, `flag_suffix`, and `random_flag_length`
- optional `capabilities`, `volumes`, and `command`

Example:

```yaml
type: container
image: "cybersea/example:development"
internal_port: 8000
connection_type: web
flag_mode: random
flag_prefix: "CSCTF{"
flag_suffix: "}"
random_flag_length: 24
capabilities: []
```

The repository deploy helper maps `internal_port` to the plugin API field `port`.

## Current limits

- One public TCP port and one container are supported per challenge.
- UDP, multiple public services, Compose sidecars, Compose `sysctls`, and Compose `extra_hosts`
  are not reproduced by this launcher.
- Resource values are one global safe ceiling, not measured per-challenge classes.
- Direct random ports still require an explicit public port-range firewall policy.
- The Docker socket is root-equivalent; CTFd belongs on a dedicated, hardened challenge worker.
- The egress label is an operator attestation, not proof. Release evidence must include active
  denial tests for Internet, cloud metadata, host/application networks, and other teams.

Do not approve a challenge whose intended topology depends on an unsupported Compose-only feature.
Redesign it to one public service or extend and test the launcher first.

## Raspberry Pi worker check

This repository's current Debian 12 Raspberry Pi worker boots with `cgroup_disable=memory` embedded
in the BCM2712 device tree. Docker consequently reports memory and swap limit support as false and
silently discards `--memory`; the plugin now refuses that worker. Update to a kernel/device tree
that does not disable the memory controller, reboot, and verify all required Docker capabilities
before using it. Do not patch a production device tree in place without a tested recovery path.

## Quick checks

```bash
docker network inspect cybersea26_ctfd_net cybersea26_challenge_net
docker info
docker logs <event-ctfd-container> --tail 200
curl -fsS http://127.0.0.1:8001/
```

Common failures now fail closed with a concrete message: missing identity, wrong event network,
unverified release egress, unsupported resource controls, cross-event image, floating production
image, invalid bind address, root image, missing health check, missing exposed port, or disallowed
runtime privilege.
