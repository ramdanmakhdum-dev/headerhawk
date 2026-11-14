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
    headers, final, status, ip = fetch_headers("http://hop.test/start")
    assert status == 200
    assert final == "https://ok.test/final"
    assert headers["x-content-type-options"] == "nosniff"
    # IP yang dikembalikan harus IP hop TERAKHIR (ok.test), bukan hop pertama —
    # ini IP yang nantinya dipakai plugin, harus konsisten dengan yang dites.
    assert ip == IPS["ok.test"]
    assert net == [("93.184.216.36", "hop.test"), ("93.184.216.35", "ok.test")]


def test_analyze_does_not_resolve_dns_twice(net, monkeypatch):
    """Regresi: analyze() sempat memanggil ensure_public() lagi setelah fetch_headers
    untuk mendapat IP plugin — pada situs round-robin/CDN itu bisa memberi IP BEDA
    dari yang sudah dipakai, membuat scan yang sebenarnya berhasil malah gagal 400.
    fetch_headers sekarang mengembalikan IP yang sudah dipakai; tidak boleh ada
    resolve tambahan sesudahnya."""
    import scanner as sc
    calls = []
    real_ensure = sc.ensure_public

    def counting(url):
        calls.append(url)
        return real_ensure(url)

    monkeypatch.setattr(sc, "ensure_public", counting)
    sc.analyze("http://hop.test/start")
    # Dua hop (hop.test lalu ok.test) -> tepat dua kali resolve, SATU per hop,
    # tidak ada resolve ekstra di luar loop fetch_headers.
    assert len(calls) == 2, f"ensure_public dipanggil {len(calls)}x, diduga ada resolve ganda: {calls}"
