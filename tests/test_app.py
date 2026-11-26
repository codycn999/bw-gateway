"""Tests for bw-gateway with the Bitwarden SDK replaced by a fake.

Run: pip install -r requirements.txt pytest httpx && pytest -q
"""
import hashlib
import importlib
import os
import sys
import uuid
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

KEY_A = "a" * 64          # agent "cody": OPENAI_* and GITHUB_TOKEN
KEY_B = "b" * 64          # agent "ci": one project
KEY_C = "c" * 64          # agent "one": a single secret by uuid
KEY_LEGACY = "legacy-shared-key"
PROJ = str(uuid.uuid4())

SECRETS = {}


def _add(key, value, project=None):
    sid = uuid.uuid4()
    SECRETS[sid] = SimpleNamespace(id=sid, key=key, value=value, note="", project_ids=[project] if project else [])
    return str(sid)


_add("OPENAI_API_KEY", "sk-openai")
_add("GITHUB_TOKEN", "ghp-token")
DB_ID = _add("DB_PASSWORD", "db-pass", PROJ)
_add("DB_USER", "db-user", PROJ)
_add("ROOT_PASSWORD", "root-pass")
DUP1 = _add("DUP", "one")
DUP2 = _add("DUP", "two")
_add("OPENAI_ORG", "org-1")


def ok(data):
    return SimpleNamespace(success=True, data=data, error_message=None)


class FakeSecrets:
    calls = []

    def list(self, org):
        FakeSecrets.calls.append("list")
        return ok(SimpleNamespace(data=[
            SimpleNamespace(id=s.id, key=s.key, project_ids=s.project_ids) for s in SECRETS.values()
        ]))

    def get(self, sid):
        FakeSecrets.calls.append("get")
        return ok(SECRETS[uuid.UUID(str(sid))])

    def get_by_ids(self, ids):
        FakeSecrets.calls.append("get_by_ids")
        return ok(SimpleNamespace(data=[SECRETS[uuid.UUID(str(i))] for i in ids]))


class FakeClient:
    def secrets(self):
        return FakeSecrets()


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient

    for k in list(os.environ):
        if k.startswith(("GATEWAY_", "BWS_")):
            monkeypatch.delenv(k)
    monkeypatch.setenv("BW_GATEWAY_CONFIG_FILE", "/nonexistent")
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "0.fake")
    monkeypatch.setenv("BWS_ORGANIZATION_ID", str(uuid.uuid4()))
    monkeypatch.setenv("GATEWAY_KEY_CODY", hashlib.sha256(KEY_A.encode()).hexdigest() + ":OPENAI_*, GITHUB_TOKEN,DUP")
    monkeypatch.setenv("GATEWAY_KEY_CI", hashlib.sha256(KEY_B.encode()).hexdigest() + ":project:" + PROJ)
    monkeypatch.setenv("GATEWAY_KEY_ONE", hashlib.sha256(KEY_C.encode()).hexdigest() + ":" + DB_ID.upper())
    monkeypatch.setenv("GATEWAY_KEY_BROKEN", "not-a-hash:*")
    monkeypatch.setenv("GATEWAY_API_KEY", KEY_LEGACY)
    monkeypatch.setenv("GATEWAY_RATE_PER_MIN", "5")
    monkeypatch.setenv("GATEWAY_AUTH_FAIL_LIMIT", "3")
    import app as appmod
    appmod = importlib.reload(appmod)
    monkeypatch.setattr(appmod.Vault, "_login", lambda self: (FakeClient(), "org"))
    FakeSecrets.calls.clear()
    c = TestClient(appmod.app)
    c.appmod = appmod
    return c


def bearer(k):
    return {"Authorization": "Bearer " + k}


def test_health_no_auth(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["agents"] == 4  # cody, ci, one, legacy; broken one ignored


def test_docs_off_by_default(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_requires_key(client):
    assert client.get("/v1/secrets").status_code == 401
    assert client.get("/v1/secrets", headers=bearer("wrong")).status_code == 401


def test_key_in_url_rejected(client):
    r = client.get("/v1/secrets?key=" + KEY_A)
    assert r.status_code == 400
    assert "header" in r.json()["error"]


def test_list_is_scoped_and_has_no_values(client):
    r = client.get("/v1/secrets", headers=bearer(KEY_A))
    assert r.status_code == 200
    names = [s["name"] for s in r.json()["secrets"]]
    assert names == ["DUP", "DUP", "GITHUB_TOKEN", "OPENAI_API_KEY", "OPENAI_ORG"]
    assert "sk-openai" not in r.text


def test_get_by_name(client):
    r = client.get("/v1/secrets/OPENAI_API_KEY", headers=bearer(KEY_A))
    assert r.status_code == 200
    assert r.json()["value"] == "sk-openai"
    assert r.json()["name"] == "OPENAI_API_KEY"
    assert r.headers["cache-control"] == "no-store"


def test_x_gateway_key_header_still_works(client):
    r = client.get("/v1/secrets/GITHUB_TOKEN", headers={"X-Gateway-Key": KEY_A})
    assert r.json()["value"] == "ghp-token"


def test_raw_value(client):
    r = client.get("/v1/value/GITHUB_TOKEN", headers=bearer(KEY_A))
    assert r.status_code == 200
    assert r.text == "ghp-token"
    assert r.headers["content-type"].startswith("text/plain")


def test_out_of_scope_looks_missing(client):
    a = client.get("/v1/secrets/ROOT_PASSWORD", headers=bearer(KEY_A))
    b = client.get("/v1/secrets/NOPE", headers=bearer(KEY_A))
    assert a.status_code == b.status_code == 404


def test_project_scope(client):
    assert client.get("/v1/secrets/DB_PASSWORD", headers=bearer(KEY_B)).json()["value"] == "db-pass"
    assert client.get("/v1/secrets/OPENAI_API_KEY", headers=bearer(KEY_B)).status_code == 404


def test_duplicate_names_need_id(client):
    r = client.get("/v1/secrets/DUP", headers=bearer(KEY_A))
    assert r.status_code == 409
    assert client.get("/v1/secrets/" + DUP2, headers=bearer(KEY_A)).json()["value"] == "two"


def test_batch(client):
    r = client.post("/v1/secrets/batch", headers=bearer(KEY_A),
                    json={"names": ["OPENAI_API_KEY", "GITHUB_TOKEN", "ROOT_PASSWORD", "OPENAI_API_KEY"]})
    assert r.status_code == 200
    assert r.json() == {"secrets": {"OPENAI_API_KEY": "sk-openai", "GITHUB_TOKEN": "ghp-token"},
                        "missing": ["ROOT_PASSWORD"]}
    assert FakeSecrets.calls.count("get_by_ids") == 1


def test_legacy_key_and_route(client):
    r = client.get("/secrets/by-key/ROOT_PASSWORD", headers={"X-Gateway-Key": KEY_LEGACY})
    assert r.status_code == 200
    assert r.json()["secret"]["value"] == "root-pass"
    assert client.get("/secrets/by-key/ROOT_PASSWORD", headers={"X-Gateway-Key": KEY_A}).status_code == 404


def test_old_dump_routes_gone(client):
    assert client.get("/secrets", headers={"X-Gateway-Key": KEY_LEGACY}).status_code == 404
    assert client.get("/projects", headers={"X-Gateway-Key": KEY_LEGACY}).status_code == 404


def test_index_cached(client):
    for _ in range(3):
        client.get("/v1/secrets/OPENAI_API_KEY", headers=bearer(KEY_A))
    assert FakeSecrets.calls.count("list") == 1


def test_per_key_rate_limit(client):
    codes = [client.get("/v1/whoami", headers=bearer(KEY_A)).status_code for _ in range(6)]
    assert codes == [200] * 5 + [429]
    assert client.get("/v1/whoami", headers=bearer(KEY_B)).status_code == 200


def test_auth_failure_lockout(client):
    for _ in range(3):
        assert client.get("/v1/secrets", headers=bearer("guess")).status_code == 401
    r = client.get("/v1/secrets", headers=bearer(KEY_A))
    assert r.status_code == 429
    assert "retry-after" in r.headers


def test_forwarded_for_only_from_trusted_proxy(client):
    req = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"),
                          headers={"x-forwarded-for": "6.6.6.6, 1.2.3.4"})
    assert client.appmod.client_ip(req) == "1.2.3.4"
    req = SimpleNamespace(client=SimpleNamespace(host="9.9.9.9"), headers={"x-forwarded-for": "1.2.3.4"})
    assert client.appmod.client_ip(req) == "9.9.9.9"
    req = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"),
                          headers={"cf-connecting-ip": "5.5.5.5", "x-forwarded-for": "1.2.3.4"})
    assert client.appmod.client_ip(req) == "5.5.5.5"
    req = SimpleNamespace(client=SimpleNamespace(host="9.9.9.9"), headers={"cf-connecting-ip": "5.5.5.5"})
    assert client.appmod.client_ip(req) == "9.9.9.9"


def test_whoami(client):
    r = client.get("/v1/whoami", headers=bearer(KEY_B))
    assert r.json() == {"agent": "ci", "allow": ["project:" + PROJ]}


def test_scope_by_secret_uuid(client):
    r = client.get("/v1/secrets", headers=bearer(KEY_C))
    assert [s["name"] for s in r.json()["secrets"]] == ["DB_PASSWORD"]
    assert client.get("/v1/value/" + DB_ID, headers=bearer(KEY_C)).text == "db-pass"
    assert client.get("/v1/value/DB_USER", headers=bearer(KEY_C)).status_code == 404


def test_get_project(client):
    r = client.get("/v1/projects/%s/secrets" % PROJ.upper(), headers=bearer(KEY_B))
    assert r.status_code == 200
    assert [(s["name"], s["value"]) for s in r.json()["secrets"]] == [("DB_PASSWORD", "db-pass"), ("DB_USER", "db-user")]
    # key scoped to one secret only sees that one in the project
    r = client.get("/v1/projects/%s/secrets" % PROJ, headers=bearer(KEY_C))
    assert [s["name"] for s in r.json()["secrets"]] == ["DB_PASSWORD"]
    # key without access to the project
    assert client.get("/v1/projects/%s/secrets" % PROJ, headers=bearer(KEY_A)).status_code == 404


def test_batch_by_uuid(client):
    r = client.post("/v1/secrets/batch", headers=bearer(KEY_B), json={"names": [DB_ID, "DB_USER"]})
    assert r.json()["secrets"] == {DB_ID: "db-pass", "DB_USER": "db-user"}
