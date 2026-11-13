import pytest
from fastapi.testclient import TestClient

import api

client = TestClient(api.app)


class Req:
    def __init__(self, xff=None, host="9.9.9.9"):
        self.headers = {"x-forwarded-for": xff} if xff else {}
        self.client = type("C", (), {"host": host})()


def test_security_headers_present():
    r = client.get("/health")
    assert r.status_code == 200
    for h in ("content-security-policy", "strict-transport-security", "x-frame-options",
              "x-content-type-options", "referrer-policy", "permissions-policy",
              "cross-origin-opener-policy", "cross-origin-resource-policy"):
        assert h in r.headers, h


def test_csp_script_src_is_strict():
    csp = client.get("/health").headers["content-security-policy"]
    script = [d for d in csp.split(";") if d.strip().startswith("script-src")][0]
    assert "unsafe-inline" not in script and "unsafe-eval" not in script


def test_docs_disabled():
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(p).status_code == 404


def test_head_root_allowed():
    assert client.head("/").status_code == 200


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data", "http://127.0.0.1:22"])
def test_scan_rejects_internal_targets(url):
    assert client.get("/scan", params={"url": url}).status_code == 400


def test_client_ip_ignores_spoofed_prefix(monkeypatch):
    monkeypatch.setattr(api, "TRUSTED_HOPS", 1)
    assert api.client_ip(Req("6.6.6.6, 1.2.3.4")) == "1.2.3.4"
    monkeypatch.setattr(api, "TRUSTED_HOPS", 2)
    assert api.client_ip(Req("9.9.9.9, 6.6.6.6, 1.2.3.4")) == "6.6.6.6"
    assert api.client_ip(Req()) == "9.9.9.9"


def test_rate_tracking_is_bounded(monkeypatch):
    from collections import defaultdict, deque
    import time
    bucket = defaultdict(deque)
    monkeypatch.setattr(api, "MAX_TRACKED", 3)
    for i in range(3):
        bucket[f"ip{i}"].append(time.time())
    with pytest.raises(api.HTTPException) as e:
        api._check(bucket, "baru", 10, "x")
    assert e.value.status_code == 429


FAKE = {"url": "https://x", "score": 50, "grade": "C", "ip_info": {}, "virustotal": "-",
        "missing": [], "weak": {}, "cookie_issues": [], "leaked_info": {}}
PW = "kata-sandi-panjang-123"


def _reset():
    api._auth_fails.clear()
    api._ai_hits.clear()
    api._ai_day.update({"date": "", "count": 0})


def test_explain_disabled_without_password_env(monkeypatch):
    _reset()
    monkeypatch.delenv("AI_PASSWORD", raising=False)
    assert client.get("/explain", params={"url": "example.com"}).status_code == 503


def test_explain_rejects_missing_or_wrong_password(monkeypatch):
    _reset()
    monkeypatch.setenv("AI_PASSWORD", PW)
    assert client.get("/explain", params={"url": "example.com"}).status_code == 401
    r = client.get("/explain", params={"url": "example.com"}, headers={"X-AI-Password": "salah"})
    assert r.status_code == 401


def test_explain_accepts_correct_password(monkeypatch):
    _reset()
    monkeypatch.setenv("AI_PASSWORD", PW)
    monkeypatch.setattr(api, "run_scan", lambda url, use_cache=False: FAKE)
    monkeypatch.setattr(api, "analyze_with_ai", lambda d: "ok")
    r = client.get("/explain", params={"url": "example.com"}, headers={"X-AI-Password": PW})
    assert r.status_code == 200 and r.json() == {"explanation": "ok"}


def test_wrong_password_attempts_are_locked_out(monkeypatch):
    _reset()
    monkeypatch.setenv("AI_PASSWORD", PW)
    for _ in range(api.AUTH_FAIL_LIMIT):
        r = client.get("/explain", params={"url": "x.com"}, headers={"X-AI-Password": "salah"})
        assert r.status_code == 401
    r = client.get("/explain", params={"url": "x.com"}, headers={"X-AI-Password": PW})
    assert r.status_code == 429
