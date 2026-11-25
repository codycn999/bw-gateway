# bw-gateway

A minimal HTTP gateway in front of Bitwarden Secrets Manager (cloud).

## Why

Some agents cannot hold a Bitwarden machine-account access token directly
(key isolation). This gateway holds the real token on one VM only and exposes
a plain API key (`X-Gateway-Key`) to agents. The machine-account token never
leaves the VM.

## How it works

- The gateway runs on the VM, listening only on `127.0.0.1:8080`.
- It reads the machine-account token and organization ID from `.env`
  (`/opt/bw-gateway/.env`, mode `600`, owned by the `bw-gateway` user).
- Agents call the gateway over SSH with the `X-Gateway-Key` header.
- The gateway logs in to Bitwarden with the machine-account token (via the
  official Bitwarden SDK) and fetches the requested secret.

```
agent --(SSH)--> 127.0.0.1:8080 --(X-Gateway-Key)--> bw-gateway
bw-gateway --(machine-account token)--> vault.bitwarden.com
```

## API

| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/health` | No auth. Reports whether token/org are configured and logged in. |
| GET | `/projects` | List projects in the organization. |
| GET | `/secrets` | List secrets (metadata; values included by the SDK). |
| GET | `/secrets/{id}` | Get one secret by ID. |
| GET | `/secrets/by-key/{key}` | Get one secret by its key. |

All endpoints except `/health` require the `X-Gateway-Key` header.
FastAPI also serves interactive docs at `/docs` (Swagger UI) and `/redoc`.

## Setup (on the VM)

```bash
# System user and directory
sudo useradd -r -s /usr/sbin/nologin bw-gateway
sudo mkdir -p /opt/bw-gateway
sudo chown bw-gateway:bw-gateway /opt/bw-gateway
sudo chmod 750 /opt/bw-gateway

# Code and dependencies
cd /opt/bw-gateway
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

# Config (never commit the real .env)
cp .env.example .env
sudo nano .env   # fill in BWS_ACCESS_TOKEN, BWS_ORGANIZATION_ID, GATEWAY_API_KEY
sudo chmod 600 .env
sudo chown bw-gateway:bw-gateway .env

# Service
sudo cp bw-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bw-gateway
```

Generate the gateway API key with, e.g.:

```bash
openssl rand -hex 32
```

## Updating / deploying

The code in this repo is the source of truth. To deploy an update to the VM:

1. Pull or copy the new `app.py` (and any other changed files) to
   `/opt/bw-gateway/`.
2. If dependencies changed, re-run `./venv/bin/pip install -r requirements.txt`.
3. Restart the service: `sudo systemctl restart bw-gateway`.
4. Verify: `curl http://127.0.0.1:8080/health` and fetch one secret.

Notes:

- The gateway API key is read once at startup, so changing
  `GATEWAY_API_KEY` requires a restart.
- The machine-account token and organization ID are re-read on every
  (re)login, so filling them in after first start needs no restart.
  Rotating the token later does need a restart (the logged-in client is
  cached).
- The `.env` file is never committed and never leaves the VM.

## Logging

Logs go to journald: `sudo journalctl -u bw-gateway`. The uvicorn access log
records each request's time, method, path and status code (including which
secret ID was fetched and failed 401 attempts). It does not log the API key
value or secret values.

## Security

- The machine-account token and the gateway API key are secrets. Keep them
  out of chat, memory, and version control.
- The gateway binds only to localhost; reach it via SSH.
- Give each calling agent its own gateway key when multi-key support lands,
  so one key can be revoked without affecting others.
