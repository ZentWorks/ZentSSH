<p align="center">
  <img src="frontend/public/zentssh-logo.png" alt="ZentSSH" width="180">
</p>

# ZentSSH

ZentSSH is a self-hosted web interface for SSH and SFTP. It gives you browser-based terminals, file management and shared server access without handing your infrastructure to a third-party service.

## Features

- SSH terminals directly in the browser
- SFTP file manager with upload, download, editor and dual-pane transfers
- private servers and administrator-managed shared workspaces
- reusable SSH credentials and server templates
- Jump Host / Bastion support
- private and shared command snippets
- OpenSSH config import and Quick Connect
- local users, TOTP MFA and OIDC/SSO
- persistent SSH sessions with reconnect
- encrypted Backup / Restore from the WebUI

## Docker Compose

The repository contains a ready-to-use [`compose.yaml`](compose.yaml). The quickest setup is:

```bash
git clone https://github.com/ZentWorks/ZentSSH.git
cd ZentSSH
cp .env.example .env
docker compose up -d
docker logs -f zentssh
```

A minimal Compose file looks like this:

```yaml
services:
  zentssh:
    image: ghcr.io/zentworks/zentssh:latest
    container_name: zentssh
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      TZ: Europe/Berlin
    volumes:
      - zentssh_data:/data

volumes:
  zentssh_data:
```

Open `http://localhost:8080`. On the first start ZentSSH needs a one-time setup token. If you did not set `SETUP_TOKEN` yourself, the generated token is shown in the container log. After the first administrator has been created, the setup token can no longer be used.

## Docker Run

```bash
docker volume create zentssh_data

docker run -d \
  --name zentssh \
  --restart unless-stopped \
  -p 8080:8080 \
  -e TZ=Europe/Berlin \
  -v zentssh_data:/data \
  ghcr.io/zentworks/zentssh:latest
```

Then read the setup token with:

```bash
docker logs zentssh
```

## Configuration

Most installations only need the variables below. With Docker Compose, copy `.env.example` to `.env` and change what you need.

| Variable | Default | Description |
| --- | --- | --- |
| `ZENTSSH_PORT` | `8080` | Port used on the Docker host |
| `ZENTSSH_DATA_VOLUME` | `zentssh_data` | Docker volume or bind mount for persistent data |
| `TZ` | `Europe/Berlin` | Container timezone |
| `BASE_URL` | empty | Public HTTPS URL, for example `https://ssh.example.com` |
| `TRUSTED_PROXY_CIDRS` | empty | IPs/CIDRs of trusted reverse proxies |
| `COOKIE_SECURE` | `auto` | Secure-cookie handling: `auto`, `true` or `false` |
| `SETUP_TOKEN` | generated | Optional fixed token for the first administrator setup |
| `MASTER_KEY` | generated | Optional externally managed master encryption key |
| `ALLOW_WS_NO_ORIGIN` | `false` | Allow WebSockets without an Origin header; normally keep disabled |

`MASTER_KEY` normally does not need to be set. ZentSSH creates `/data/master.key` automatically and keeps it in the persistent data volume.

<details>
<summary>Advanced limits</summary>

| Variable | Default | Description |
| --- | --- | --- |
| `WEB_SESSION_TTL` | `24h` | Lifetime of a WebUI login session |
| `MAX_WEB_SESSIONS_PER_USER` | `20` | Maximum WebUI sessions per user |
| `LOGIN_RATE_LIMIT_MAX` | `10` | Login attempts allowed per rate-limit window |
| `LOGIN_RATE_LIMIT_WINDOW` | `10m` | Login rate-limit window |
| `MAX_PASSWORD_HASH_CONCURRENCY` | `4` | Maximum parallel password hash operations |
| `SSH_SESSION_RETENTION` | `30m` | Default retention for detached SSH sessions |
| `SESSION_BUFFER_SIZE` | `2097152` | Terminal reconnect buffer per SSH session in bytes |
| `MAX_SESSIONS_PER_USER` | `8` | Maximum SSH sessions per user |
| `MAX_TOTAL_SESSIONS` | `64` | Maximum SSH sessions for the instance |
| `MAX_TRANSFERS_PER_USER` | `3` | Maximum server-to-server transfers per user |
| `MAX_TOTAL_TRANSFERS` | `12` | Maximum server-to-server transfers for the instance |
| `MAX_SFTP_OPERATIONS_PER_USER` | `6` | Maximum parallel SFTP operations per user |
| `MAX_TOTAL_SFTP_OPERATIONS` | `48` | Maximum parallel SFTP operations for the instance |
| `SFTP_STREAM_IDLE_TIMEOUT` | `2m` | Idle timeout for SFTP upload/download streams |
| `AUDIT_RETENTION` | `2160h` | Audit-log retention; `0`/`off` disables cleanup |

</details>

## Reverse Proxy

For an internet-facing installation, use HTTPS and set the public URL:

```env
BASE_URL=https://ssh.example.com
TRUSTED_PROXY_CIDRS=172.20.0.0/16
COOKIE_SECURE=auto
```

Only add the address or network of your actual reverse proxy to `TRUSTED_PROXY_CIDRS`.

## Backup / Restore

Administrators can create password-protected backups under **Settings → Admin → Backup / Restore**. A restore replaces the complete ZentSSH application state contained in the backup.

Keep the persistent `/data` volume protected. It contains the database and, unless you provide `MASTER_KEY` externally, the key used to encrypt stored credentials.

## Update

Docker Compose:

```bash
docker compose pull
docker compose up -d
```

Docker Run installations can pull the new image and recreate the container with the same volume and environment settings.

## API

ZentSSH includes an API overview at `/api/docs` and an OpenAPI document at `/api/openapi.yaml`.

## Security

Do not expose ZentSSH publicly without HTTPS. Security reports should be submitted privately as described in [`SECURITY.md`](SECURITY.md).

## License

ZentSSH is licensed under the [MIT License](LICENSE).
