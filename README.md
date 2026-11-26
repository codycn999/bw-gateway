# bw-gateway

A small HTTPS gateway in front of Bitwarden Secrets Manager (cloud). An agent
sends its own gateway key in a header and gets back the secrets that key is
allowed to read. The Bitwarden machine-account token stays on the VM.

```
agent --HTTPS, Authorization: Bearer <agent key>--> Caddy / Cloudflare Tunnel
      --> 127.0.0.1:8080 bw-gateway --machine-account token--> vault.bitwarden.com
```

## For agents

Send the key in a header, never in the URL (URLs land in logs; the gateway
answers `400` if it sees `?key=`). `X-Gateway-Key: <key>` also works.

```bash
GW=https://<gateway-host>
H="Authorization: Bearer $BW_GATEWAY_KEY"

curl -fsS -H "$H" $GW/v1/secrets                    # names you may read (no values)
curl -fsS -H "$H" $GW/v1/secrets/OPENAI_API_KEY     # {"id","name","value","note"}
export OPENAI_API_KEY=$(curl -fsS -H "$H" $GW/v1/value/OPENAI_API_KEY)   # bare value
curl -fsS -H "$H" -H 'Content-Type: application/json' \
     -d '{"names":["OPENAI_API_KEY","GITHUB_TOKEN"]}' $GW/v1/secrets/batch
```

| Method | Path | Returns |
| ------ | ---- | ------- |
| GET | `/health` | No auth. Service status. |
| GET | `/v1/whoami` | Agent name and what it may read. |
| GET | `/v1/secrets` | Names and ids this key may read. Never values. |
| GET | `/v1/secrets/{name}` | One secret as JSON. `{name}` may also be the secret id. |
| GET | `/v1/value/{name}` | One secret's value as `text/plain`. |
| POST | `/v1/secrets/batch` | `{"names":[...]}` (max 50) → `{"secrets":{name:value}, "missing":[...]}` |
| GET | `/secrets/by-key/{key}` | Old route, same scoping. Not exposed through the HTTPS entry. |

Errors are JSON `{"error": "..."}`:

- `401` wrong or missing key.
- `404` the secret does not exist **or** this key may not read it (the two look the same on purpose).
- `409` several secrets share that name; ask by id (listed in the error).
- `429` rate limited; see `Retry-After`.

The old `GET /secrets` (every secret at once) and `GET /projects` are gone.

## Agent keys

Each agent has its own key, limited to the secrets it needs. Revoking one
agent means deleting its line.

```bash
python3 scripts/new-agent-key.py cody 'OPENAI_*,GITHUB_TOKEN'
python3 scripts/new-agent-key.py ci 'project:<bitwarden-project-uuid>'
```

The script prints a `GATEWAY_KEY_<NAME>=<sha256>:<allowed>` line for
`/etc/bw-gateway/env` and the key itself, once, to hand to the agent. Only the
hash is stored. Allowed entries are exact names, globs (`OPENAI_*`), or
`project:<uuid>`. Then `sudo systemctl restart bw-gateway`; the log line
`loaded N agent key(s): ...` confirms the names.

The old shared `GATEWAY_API_KEY` still works as a full-access key named
`legacy`, so existing callers keep working during the move. Remove it once
every agent has its own key.

## Limits and logging

- 60 requests per key per minute (`GATEWAY_RATE_PER_MIN`).
- 10 failed authentications from one IP in 10 minutes block that IP for 15
  minutes. Behind Caddy or cloudflared the real client IP comes from the
  proxy's `X-Forwarded-For`, trusted only from `127.0.0.1`.
- Each read is logged to journald as
  `audit agent=<name> ip=<ip> action=get secrets=<names>`. Keys and values are
  never logged. `sudo journalctl -u bw-gateway | grep audit`.
- Responses carry `Cache-Control: no-store`. `/docs` is off unless
  `GATEWAY_ENABLE_DOCS=1`.

All tunables are listed in `.env.example`.

## HTTPS entry (one time, on the VM)

The gateway keeps listening on `127.0.0.1:8080`. Pick one front door:

- **Caddy** (`deploy/Caddyfile`): set the host name (no domain needed:
  `<external-ip>.sslip.io`), install Caddy, copy the file to
  `/etc/caddy/Caddyfile`, `sudo systemctl reload caddy`. Open tcp:80 and
  tcp:443 in the GCP firewall and give the VM a static external IP.
- **Cloudflare Tunnel** (`deploy/cloudflared.yml`): needs a domain on
  Cloudflare; no inbound ports.

Both expose only `/health` and `/v1/*`.

## Setup (on the VM)

```bash
sudo useradd -r -s /usr/sbin/nologin bw-gateway
sudo git clone <repo> /opt/bw-gateway
cd /opt/bw-gateway && sudo python3 -m venv venv && sudo ./venv/bin/pip install -r requirements.txt

sudo mkdir -p /etc/bw-gateway
sudo cp .env.example /etc/bw-gateway/env
sudo nano /etc/bw-gateway/env        # token, org id, one GATEWAY_KEY_<NAME> per agent
sudo chown root:root /etc/bw-gateway/env && sudo chmod 600 /etc/bw-gateway/env

sudo cp bw-gateway.service /etc/systemd/system/
sudo mkdir -p /etc/systemd/system/bw-gateway.service.d
printf '[Service]\nEnvironmentFile=/etc/bw-gateway/env\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nMemoryMax=300M\n' \
  | sudo tee /etc/systemd/system/bw-gateway.service.d/override.conf
sudo systemctl daemon-reload && sudo systemctl enable --now bw-gateway
```

## Deploying updates

Code on `main` is the source of truth. `sudo /usr/local/bin/bw-gateway-deploy`
fetches `main`, installs requirements, restarts and prints `/health`. Config
lives in `/etc/bw-gateway/env`, which deploys never touch. Any change to that
file needs `sudo systemctl restart bw-gateway`.

## Tests

```bash
pip install -r requirements.txt pytest httpx
pytest -q
```

The Bitwarden SDK is replaced by a fake, so no token is needed.

## Security notes

- Keep the machine-account token and agent keys out of chat, memory and git.
- Give each agent the narrowest allowed list that works; avoid `*`.
- Rotate an agent key by generating a new line and deleting the old one.
