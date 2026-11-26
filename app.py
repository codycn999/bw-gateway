"""bw-gateway: minimal HTTP gateway in front of Bitwarden Secrets Manager.

Holds the real machine-account access token on this VM only. Each agent gets
its own gateway key, sent in a request header, and may read only the secrets
its key is scoped to. The machine-account token never leaves this VM.
"""
import fnmatch
import hashlib
import hmac
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from uuid import UUID

from bitwarden_sdk import BitwardenClient, ClientSettings, DeviceType
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("bw-gateway")

# Legacy location. The VM now passes config through systemd EnvironmentFile
# (/etc/bw-gateway/env); environment variables win over this file.
CONFIG_FILE = os.environ.get("BW_GATEWAY_CONFIG_FILE", "/opt/bw-gateway/.env")


def load_config() -> Dict[str, str]:
    cfg: Dict[str, str] = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip('"').strip("'")
    for k, v in os.environ.items():
        if k.startswith(("BWS_", "GATEWAY_")) and v:
            cfg[k] = v
    return cfg


def _is_placeholder(v: Optional[str]) -> bool:
    return (not v) or v.startswith("PASTE_") or v in ("PLACEHOLDER", "TODO")


def _int(cfg: Dict[str, str], name: str, default: int) -> int:
    try:
        return int(cfg.get(name, default))
    except (TypeError, ValueError):
        log.warning("invalid %s, using default %s", name, default)
        return default


# ---------------------------------------------------------------------------
# Agent keys
# ---------------------------------------------------------------------------

KEY_PREFIX = "GATEWAY_KEY_"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


@dataclass
class Agent:
    name: str
    patterns: List[str] = field(default_factory=list)

    def can_read(self, key: str, secret_id: str, project_ids: List[str]) -> bool:
        for p in self.patterns:
            if p.startswith("project:"):
                if p[len("project:"):].lower() in project_ids:
                    return True
            elif p.startswith("id:") or _UUID.match(p):
                if p.split(":", 1)[-1].lower() == secret_id:
                    return True
            elif fnmatch.fnmatchcase(key, p):
                return True
        return False


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def load_agents(cfg: Dict[str, str]) -> Dict[str, Agent]:
    """Return {sha256(key): Agent}.

    Each agent is one config line:
        GATEWAY_KEY_<NAME>=<sha256 of the key>:<pattern>,<pattern>,...
    A pattern is a secret name glob (OPENAI_*, GITHUB_TOKEN), a secret
    uuid, or project:<project-uuid>. Only the hash is stored on the VM.
    """
    agents: Dict[str, Agent] = {}
    for k, v in sorted(cfg.items()):
        if not k.startswith(KEY_PREFIX) or _is_placeholder(v):
            continue
        name = k[len(KEY_PREFIX):].lower()
        digest, _, allow = v.partition(":")
        digest = digest.strip().lower()
        if not _HEX64.match(digest):
            log.error("%s: value must start with a 64-char sha256 hex digest; key ignored", k)
            continue
        patterns = [p.strip() for p in allow.split(",") if p.strip()]
        if not patterns:
            log.warning("%s has no allowed secrets; it can authenticate but read nothing", k)
        if digest in agents:
            log.error("%s reuses the key of agent %s; key ignored", k, agents[digest].name)
            continue
        agents[digest] = Agent(name, patterns)
    legacy = cfg.get("GATEWAY_API_KEY", "")
    if not _is_placeholder(legacy):
        log.warning("GATEWAY_API_KEY (shared full-access key) is still set; "
                    "move each agent to its own GATEWAY_KEY_<NAME> and remove it")
        agents.setdefault(hash_key(legacy), Agent("legacy", ["*"]))
    return agents


# ---------------------------------------------------------------------------
# Rate limiting (in-memory; the service runs as a single process)
# ---------------------------------------------------------------------------


class RateLimiter:
    """Per-key request limit plus a lockout for IPs that keep failing auth."""

    def __init__(self, per_key_per_min: int, fail_limit: int, fail_window: int, block_seconds: int):
        self.per_key_per_min = per_key_per_min
        self.fail_limit = fail_limit
        self.fail_window = fail_window
        self.block_seconds = block_seconds
        self._lock = threading.Lock()
        self._hits: Dict[str, List[float]] = {}
        self._fails: Dict[str, List[float]] = {}
        self._blocked: Dict[str, float] = {}

    def blocked_for(self, ip: str) -> int:
        with self._lock:
            until = self._blocked.get(ip, 0)
            left = until - time.monotonic()
            if left <= 0:
                self._blocked.pop(ip, None)
                return 0
            return int(left) + 1

    def record_failure(self, ip: str) -> None:
        now = time.monotonic()
        with self._lock:
            fails = [t for t in self._fails.get(ip, []) if now - t < self.fail_window]
            fails.append(now)
            if len(fails) >= self.fail_limit:
                self._blocked[ip] = now + self.block_seconds
                self._fails.pop(ip, None)
                log.warning("auth lockout ip=%s for %ss", ip, self.block_seconds)
            else:
                self._fails[ip] = fails

    def allow_request(self, agent: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(agent, []) if now - t < 60]
            if len(hits) >= self.per_key_per_min:
                self._hits[agent] = hits
                return False
            hits.append(now)
            self._hits[agent] = hits
            return True


# ---------------------------------------------------------------------------
# Bitwarden access
# ---------------------------------------------------------------------------


class Vault:
    """Bitwarden SDK wrapper: lazy login, one SDK call at a time, cached name index."""

    def __init__(self, index_ttl: int):
        self.index_ttl = index_ttl
        self._lock = threading.Lock()
        self._client: Optional[Tuple[BitwardenClient, str]] = None
        self._index: Optional[List[dict]] = None
        self._index_at = 0.0

    @property
    def logged_in(self) -> bool:
        return self._client is not None

    def _login(self) -> Tuple[BitwardenClient, str]:
        if self._client is not None:
            return self._client
        cur = load_config()
        token = cur.get("BWS_ACCESS_TOKEN", "")
        org = cur.get("BWS_ORGANIZATION_ID", "")
        if _is_placeholder(token):
            raise HTTPException(status_code=503, detail="machine account token not configured yet")
        if _is_placeholder(org):
            raise HTTPException(status_code=503, detail="organization id not configured yet")
        server = cur.get("BWS_SERVER_URL", "https://vault.bitwarden.com").rstrip("/")
        client = BitwardenClient(
            ClientSettings(
                api_url=server + "/api",
                identity_url=server + "/identity",
                device_type=DeviceType.SDK,
                user_agent="bw-gateway/2.0",
            )
        )
        try:
            client.auth().login_access_token(token)
        except Exception as e:
            log.error("bitwarden login failed: %s", e)
            raise HTTPException(status_code=502, detail="bitwarden login failed")
        self._client = (client, org)
        log.info("logged in to bitwarden org %s", org)
        return self._client

    def _call(self, fn, what: str):
        """Run fn(client, org); on failure re-login once (e.g. expired session)."""
        for attempt in (1, 2):
            client, org = self._login()
            try:
                resp = fn(client, org)
            except Exception as e:
                resp, err = None, str(e)
            else:
                err = resp.error_message if not resp.success else None
            if resp is not None and resp.success:
                return resp.data
            log.warning("%s failed (attempt %d): %s", what, attempt, err)
            self._client = None
        raise HTTPException(status_code=502, detail="%s failed" % what)

    def index(self) -> List[dict]:
        """All secret identifiers [{id, key, project_ids}] visible to the machine account."""
        with self._lock:
            now = time.monotonic()
            if self._index is not None and now - self._index_at < self.index_ttl:
                return self._index
            data = self._call(lambda c, org: c.secrets().list(org), "list secrets")
            self._index = [
                {"id": str(s.id).lower(), "key": s.key,
                 "project_ids": [str(p).lower() for p in (s.project_ids or [])]}
                for s in (data.data or [])
            ]
            self._index_at = now
            return self._index

    def get_many(self, ids: List[str]) -> Dict[str, dict]:
        """Fetch values for ids. Returns {id: {id, key, value, note}}."""
        if not ids:
            return {}
        with self._lock:
            if len(ids) == 1:
                data = self._call(lambda c, org: c.secrets().get(UUID(ids[0])), "get secret")
                items = [data]
            else:
                data = self._call(lambda c, org: c.secrets().get_by_ids([UUID(i) for i in ids]), "get secrets")
                items = data.data or []
        return {
            str(s.id): {"id": str(s.id), "name": s.key, "value": s.value, "note": s.note or ""}
            for s in items
        }


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

_cfg = load_config()
AGENTS = load_agents(_cfg)
LIMITER = RateLimiter(
    per_key_per_min=_int(_cfg, "GATEWAY_RATE_PER_MIN", 60),
    fail_limit=_int(_cfg, "GATEWAY_AUTH_FAIL_LIMIT", 10),
    fail_window=_int(_cfg, "GATEWAY_AUTH_FAIL_WINDOW", 600),
    block_seconds=_int(_cfg, "GATEWAY_AUTH_BLOCK_SECONDS", 900),
)
VAULT = Vault(index_ttl=_int(_cfg, "GATEWAY_INDEX_TTL", 60))
TRUSTED_PROXIES = {
    p.strip() for p in _cfg.get("GATEWAY_TRUSTED_PROXIES", "127.0.0.1,::1").split(",") if p.strip()
}
MAX_BATCH = 50

_docs = _cfg.get("GATEWAY_ENABLE_DOCS", "").lower() in ("1", "true", "yes")
app = FastAPI(
    title="bw-gateway",
    docs_url="/docs" if _docs else None,
    redoc_url="/redoc" if _docs else None,
    openapi_url="/openapi.json" if _docs else None,
)
log.info("loaded %d agent key(s): %s", len(AGENTS), ", ".join(sorted(a.name for a in AGENTS.values())))


def client_ip(request: Request) -> str:
    """Real client IP. Proxy headers are trusted only when the request comes
    from the local cloudflared: Cf-Connecting-IP first (set by Cloudflare's
    edge), else the rightmost X-Forwarded-For entry."""
    peer = request.client.host if request.client else "unknown"
    if peer in TRUSTED_PROXIES:
        cf = request.headers.get("cf-connecting-ip", "").strip()
        if cf:
            return cf
        xff = request.headers.get("x-forwarded-for", "")
        if xff.strip():
            return xff.split(",")[-1].strip()
    return peer


def authenticate(request: Request) -> Agent:
    ip = client_ip(request)
    wait = LIMITER.blocked_for(ip)
    if wait:
        raise HTTPException(status_code=429, detail="too many failed attempts",
                            headers={"Retry-After": str(wait)})
    if any(q in request.query_params for q in ("key", "api_key", "token", "gateway_key")):
        # URLs end up in proxy and access logs; refuse rather than accept silently.
        LIMITER.record_failure(ip)
        raise HTTPException(status_code=400, detail="send the key in the Authorization: Bearer header, "
                                                    "never in the URL")
    raw = request.headers.get("x-gateway-key", "")
    auth = request.headers.get("authorization", "")
    if not raw and auth[:7].lower() == "bearer ":
        raw = auth[7:].strip()
    agent = None
    if raw:
        digest = hash_key(raw)
        for known, a in AGENTS.items():
            if hmac.compare_digest(known, digest):
                agent = a
    if agent is None:
        LIMITER.record_failure(ip)
        log.info("auth failed ip=%s path=%s", ip, request.url.path)
        raise HTTPException(status_code=401, detail="unauthorized",
                            headers={"WWW-Authenticate": "Bearer"})
    if not LIMITER.allow_request(agent.name):
        raise HTTPException(status_code=429, detail="rate limit exceeded", headers={"Retry-After": "60"})
    request.state.agent = agent.name
    request.state.ip = ip
    return agent


def visible(agent: Agent) -> List[dict]:
    return [s for s in VAULT.index() if agent.can_read(s["key"], s["id"], s["project_ids"])]


def resolve(agent: Agent, name: str) -> dict:
    """Find one readable secret by name (or by id). Secrets the agent may not
    read look exactly like missing ones."""
    mine = visible(agent)
    matches = [s for s in mine if s["key"] == name] or [s for s in mine if s["id"] == name.lower()]
    if not matches:
        raise HTTPException(status_code=404, detail="secret not found: %s" % name)
    if len(matches) > 1:
        raise HTTPException(status_code=409, detail="several secrets are named %s; request one by id: %s"
                            % (name, ", ".join(s["id"] for s in matches)))
    return matches[0]


def audit(request: Request, action: str, names: List[str]) -> None:
    log.info("audit agent=%s ip=%s action=%s secrets=%s", request.state.agent, request.state.ip,
             action, ",".join(names))


@app.exception_handler(HTTPException)
def _http_error(request: Request, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code, headers=exc.headers)


@app.middleware("http")
async def _no_store(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    cur = load_config()
    return {
        "status": "ok",
        "token_configured": not _is_placeholder(cur.get("BWS_ACCESS_TOKEN", "")),
        "org_configured": not _is_placeholder(cur.get("BWS_ORGANIZATION_ID", "")),
        "logged_in": VAULT.logged_in,
        "agents": len(AGENTS),
    }


@app.get("/v1/whoami")
def whoami(request: Request):
    agent = authenticate(request)
    return {"agent": agent.name, "allow": agent.patterns}


@app.get("/v1/secrets")
def list_secrets(request: Request):
    """Names this key may read. Never includes values."""
    agent = authenticate(request)
    items = visible(agent)
    audit(request, "list", [])
    return {"secrets": [{"name": s["key"], "id": s["id"]} for s in sorted(items, key=lambda s: s["key"])]}


@app.post("/v1/secrets/batch")
def get_batch(request: Request, names: List[str] = Body(..., embed=True)):
    agent = authenticate(request)
    if len(names) > MAX_BATCH:
        raise HTTPException(status_code=400, detail="at most %d names per request" % MAX_BATCH)
    found, missing = {}, []
    for n in dict.fromkeys(names):
        try:
            found[n] = resolve(agent, n)["id"]
        except HTTPException as e:
            if e.status_code not in (404, 409):
                raise
            missing.append(n)
    values = VAULT.get_many(list(dict.fromkeys(found.values())))
    audit(request, "batch", list(found))
    return {"secrets": {n: values[i]["value"] for n, i in found.items() if i in values}, "missing": missing}


@app.get("/v1/projects/{project_id}/secrets")
def get_project(project_id: str, request: Request):
    """Every secret in one Bitwarden project that this key may read, with values."""
    agent = authenticate(request)
    pid = project_id.lower()
    items = [s for s in visible(agent) if pid in s["project_ids"]]
    if not items:
        raise HTTPException(status_code=404, detail="project not found: %s" % project_id)
    values = VAULT.get_many([s["id"] for s in items])
    audit(request, "project:" + pid, [s["key"] for s in items])
    return {"project": pid,
            "secrets": sorted((values[s["id"]] for s in items if s["id"] in values), key=lambda v: v["name"])}


@app.get("/v1/secrets/{name:path}")
def get_secret(name: str, request: Request):
    agent = authenticate(request)
    s = resolve(agent, name)
    secret = VAULT.get_many([s["id"]])[s["id"]]
    audit(request, "get", [s["key"]])
    return secret


@app.get("/v1/value/{name:path}", response_class=PlainTextResponse)
def get_value(name: str, request: Request):
    """Bare value as text/plain, for `export X=$(curl ...)`."""
    agent = authenticate(request)
    s = resolve(agent, name)
    secret = VAULT.get_many([s["id"]])[s["id"]]
    audit(request, "get", [s["key"]])
    return PlainTextResponse(secret["value"])


@app.get("/secrets/by-key/{key:path}")
def legacy_get_by_key(key: str, request: Request):
    """Old route, kept so existing callers keep working. Now scoped like /v1."""
    agent = authenticate(request)
    s = resolve(agent, key)
    secret = VAULT.get_many([s["id"]])[s["id"]]
    audit(request, "get", [s["key"]])
    return {"secret": {"id": secret["id"], "key": secret["name"], "value": secret["value"], "note": secret["note"]}}
