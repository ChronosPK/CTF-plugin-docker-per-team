# `docker_per_team` in This Repo

This plugin runs one Docker container per team for container challenges.

This repository uses it in a local-first way:
- direct mode only
- random host ports
- one app network: `csctf_ctfd_net`
- one challenge network: `csctf_challenge_net`

## Required Setup

1. Create the Docker networks:

```bash
cd Infrastructure/CTFd
./scripts/create-local-networks.sh
```

2. Start CTFd:

```bash
docker compose up -d
```

3. In CTFd admin, open `/containers/admin/settings` and keep:
- `Base URL`: `unix:///var/run/docker.sock`
- `Challenge Docker Network`: `csctf_challenge_net`

Do not use `csctf_ctfd_net` as the challenge network.

## Admin Settings

These are the settings that matter for normal local use:
- `docker_base_url`
- `docker_hostname`
- `docker_api_timeout`
- `challenge_network`
- `container_expiration`
- `max_containers`
- `container_maxmemory`
- `container_maxcpu`

Advanced settings:
- `allow_challenge_volumes`
- `allowed_capabilities`

`allowed_capabilities` is a global allowlist. A challenge can only request capabilities that appear there.

Example:

```text
NET_ADMIN,NET_RAW,SYS_PTRACE
```

## Per-Challenge Fields

You can configure capabilities in either place:
- CTFd admin challenge form
- top-level `challenge.yml` in the repo challenge flow

Supported container-specific fields:
- `image`
- `internal_port` in `challenge.yml` / `port` in the CTFd admin form
- `connection_type`
- `capabilities`
- `volumes`
- `command`

`connection_type` must be one of:
- `web`
- `tcp`

## `challenge.yml` Example

```yaml
type: container
image: "networking_vpn:networking_vpn"
internal_port: 1194
connection_type: tcp
capabilities:
  - NET_ADMIN
  - NET_RAW
```

Notes:
- `challenge.yml` uses `internal_port`
- the deploy helper maps that to the plugin API field `port`
- `capabilities` is optional

## Runtime Behavior

- Each spawned challenge container is attached to `csctf_challenge_net`
- CTFd, MariaDB, and Redis stay on `csctf_ctfd_net`
- Web challenges return endpoints like `http://host:random_port`
- TCP challenges return endpoints like `host:random_port`

## What Was Intentionally Removed

This repo does not use:
- Traefik routing
- hostname-based instance routing
- wildcard DNS
- proxy-specific Docker networks

That belongs in the separate deployment repo, not here.

## Quick Checks

If container challenges stop working, check these first:

```bash
docker network inspect csctf_challenge_net
docker exec ctfd-db-1 mysql -uctfd -pctfd -Dctfd -e 'SELECT `key`, value FROM container_settings_model;'
docker logs ctfd-ctfd-1 --tail 200
curl -I http://127.0.0.1:8000/
```

Common causes:
- wrong `challenge_network`
- Docker socket not mounted
- requested challenge capabilities not included in `allowed_capabilities`
- container image exits immediately
