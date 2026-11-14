import httpx
import pytest

import scanner
from scanner import UnsafeURL, fetch_headers

REAL_CLIENT = httpx.Client
IPS = {"redir.test": "93.184.216.34", "ok.test": "93.184.216.35",
       "hop.test": "93.184.216.36", "internal.test": "10.0.0.5"}


@pytest.fixture
def net(monkeypatch):
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers["host"]))
        host = request.headers["host"]
        if host == "redir.test":
            return httpx.Response(302, headers={"location": "http://internal.test/admin"})
        if host == "hop.test":
            return httpx.Response(302, headers={"location": "https://ok.test/final"})
        return httpx.Response(200, headers={"x-content-type-options": "nosniff"})

    def fake_gai(host, port, type=0):
        return [(2, 1, 6, "", (IPS.get(host, host), port))]

    monkeypatch.setattr(scanner.socket, "getaddrinfo", fake_gai)
    monkeypatch.setattr(httpx, "Client",
                        lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))
    return seen


def test_redirect_to_internal_host_is_blocked(net):
    with pytest.raises(UnsafeURL):
        fetch_headers("https://redir.test/start")
    assert net == [("93.184.216.34", "redir.test")]


def test_connects_to_pinned_ip_and_follows_safe_redirect(net):
    headers, final = fetch_headers("http://hop.test/start")
    assert final == "https://ok.test/final"
    assert headers["x-content-type-options"] == "nosniff"
    assert net == [("93.184.216.36", "hop.test"), ("93.184.216.35", "ok.test")]
