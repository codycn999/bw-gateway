"""bw-gateway: minimal HTTP gateway in front of Bitwarden Secrets Manager.

Holds the real machine-account access token on this VM only. Cody calls this
gateway with an ordinary API key (X-Gateway-Key) and the gateway fetches
secrets from Bitwarden (cloud) via the official SDK. The machine-account
token never leaves this VM.
"""
import logging
import os

from bitwarden_sdk import BitwardenClient, ClientSettings, DeviceType
from fastapi import FastAPI, Header, HTTPException

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("bw-gateway")

CONFIG_FILE = "/opt/bw-gateway/.env"


def load_config():
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip('"').strip("'")
    for k in ("BWS_ACCESS_TOKEN", "BWS_ORGANIZATION_ID", "GATEWAY_API_KEY", "BWS_SERVER_URL"):
        if os.environ.get(k):
            cfg[k] = os.environ[k]
    return cfg


_cfg = load_config()
API_KEY = _cfg.get("GATEWAY_API_KEY", "")
SERVER_URL = _cfg.get("BWS_SERVER_URL", "https://vault.bitwarden.com").rstrip("/")

app = FastAPI(title="bw-gateway")
_client = None  # (BitwardenClient, org_id) once logged in


def _is_placeholder(v):
    return (not v) or v.startswith("PASTE_") or v in ("PLACEHOLDER", "TODO")


def get_client():
    """Log in lazily; re-reads the token file on every (re)login attempt so the
    user can drop the token in without restarting the service."""
    global _client
    if _client is not None:
        return _client
    cur = load_config()
    token = cur.get("BWS_ACCESS_TOKEN", "")
    org = cur.get("BWS_ORGANIZATION_ID", "")
    if _is_placeholder(token):
        raise HTTPException(status_code=503, detail="machine account token not configured yet")
    if _is_placeholder(org):
        raise HTTPException(status_code=503, detail="organization id not configured yet")
    client = BitwardenClient(
        ClientSettings(
            api_url=SERVER_URL + "/api",
            identity_url=SERVER_URL + "/identity",
            device_type=DeviceType.SDK,
            user_agent="bw-gateway/1.0",
        )
    )
    try:
        client.auth().login_access_token(token)
    except Exception as e:
        raise HTTPException(status_code=502, detail="bitwarden login failed: %s" % e)
    _client = (client, org)
    log.info("logged in to bitwarden org %s", org)
    return _client


def require_key(x_gateway_key: str = Header(default="")):
    if not API_KEY or x_gateway_key != API_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")


def to_dict(obj):
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (list, tuple)):
        return [to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    if hasattr(obj, "to_dict"):
        try:
            return to_dict(obj.to_dict())
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        return {k: to_dict(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return str(obj)


@app.get("/health")
def health():
    cur = load_config()
    return {
        "status": "ok",
        "token_configured": not _is_placeholder(cur.get("BWS_ACCESS_TOKEN", "")),
        "org_configured": not _is_placeholder(cur.get("BWS_ORGANIZATION_ID", "")),
        "logged_in": _client is not None,
    }


@app.get("/projects")
def list_projects(x_gateway_key: str = Header(default="")):
    require_key(x_gateway_key)
    client, org = get_client()
    resp = client.projects().list(org)
    if not resp.success:
        raise HTTPException(status_code=502, detail=resp.error_message or "list projects failed")
    return {"projects": to_dict(resp.data)}


@app.get("/secrets")
def list_secrets(x_gateway_key: str = Header(default="")):
    require_key(x_gateway_key)
    client, org = get_client()
    resp = client.secrets().list(org)
    if not resp.success:
        raise HTTPException(status_code=502, detail=resp.error_message or "list secrets failed")
    return {"secrets": to_dict(resp.data)}


@app.get("/secrets/{secret_id}")
def get_secret(secret_id: str, x_gateway_key: str = Header(default="")):
    require_key(x_gateway_key)
    client, org = get_client()
    resp = client.secrets().get(secret_id)
    if not resp.success:
        raise HTTPException(status_code=502, detail=resp.error_message or "get secret failed")
    return {"secret": to_dict(resp.data)}


@app.get("/secrets/by-key/{key}")
def get_secret_by_key(key: str, x_gateway_key: str = Header(default="")):
    require_key(x_gateway_key)
    client, org = get_client()
    resp = client.secrets().list(org)
    if not resp.success:
        raise HTTPException(status_code=502, detail=resp.error_message or "list secrets failed")
    items = to_dict(resp.data) or []
    for item in items:
        if isinstance(item, dict) and item.get("key") == key:
            full = client.secrets().get(item.get("id"))
            if not full.success:
                raise HTTPException(status_code=502, detail=full.error_message or "get secret failed")
            return {"secret": to_dict(full.data)}
    raise HTTPException(status_code=404, detail="secret not found: %s" % key)
