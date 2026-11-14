import httpx
import pytest

import scanner
from scanner import UnsafeURL, analyze, check_cookies, check_csp, check_hsts, ensure_public, parse_csp


# ---------- SSRF guard ----------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.5",
    "http://192.168.1.1",
    "http://[::1]/",
])
def test_blocks_internal_addresses(url):
    with pytest.raises(UnsafeURL):
        ensure_public(url)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com", "gopher://x"])
def test_blocks_non_http_schemes(url):
    with pytest.raises(UnsafeURL):
        ensure_public(url)


def test_normalize_url_adds_https():
    assert scanner.normalize_url("example.com") == "https://example.com"
    assert scanner.normalize_url(" http://a.com ") == "http://a.com"


# ---------- CSP ----------

def test_parse_csp_first_directive_wins():
    d = parse_csp("default-src 'self'; img-src *; default-src 'none'")
    assert d["default-src"] == ["'self'"]
    assert d["img-src"] == ["*"]


def test_csp_strong_policy_has_no_issues():
    assert check_csp("default-src 'self'; object-src 'none'") == []


def test_csp_flags_unsafe_inline_and_eval():
    issues = check_csp("script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'")
    assert any("unsafe-inline" in i for i in issues)
    assert any("unsafe-eval" in i for i in issues)


def test_csp_nonce_makes_unsafe_inline_ignored():
    assert check_csp("script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'") == []


def test_csp_flags_wildcard_and_missing_script_src():
    assert any("longgar" in i for i in check_csp("script-src *; object-src 'none'"))
    assert any("script-src" in i for i in check_csp("img-src *; object-src 'none'"))


# ---------- HSTS ----------

def test_hsts_checks_max_age():
    assert check_hsts("max-age=31536000; includeSubDomains") == []
    assert check_hsts("max-age=300")
    assert check_hsts("includeSubDomains")
    assert check_hsts("max-age=abc")


# ---------- Cookie ----------

def test_cookie_flags():
    h = httpx.Headers([("set-cookie", "sid=1; Secure; HttpOnly; SameSite=Lax")])
    assert check_cookies(h) == []
    h = httpx.Headers([("set-cookie", "sid=1")])
    assert len(check_cookies(h)) == 3


# ---------- Skor ----------

def fake_fetch(headers_list, ip="93.184.216.34"):
    def _fetch(url):
        return httpx.Headers(headers_list), url, 200, ip
    return _fetch


@pytest.fixture(autouse=True)
def _no_plugins(monkeypatch):
    """File ini menguji skor/header inti, bukan plugin. Tanpa ini, kalau
    test_api.py (yang meregistrasi plugin_cors/tls/exposed-files lewat impor
    api.py) sempat jalan lebih dulu dalam sesi pytest yang sama, tes di sini
    bisa diam-diam memicu permintaan jaringan SUNGGUHAN lewat plugin — lambat
    dan tidak deterministik. Dikunci supaya analyze() di sini selalu bersih."""
    monkeypatch.setattr(scanner, "run_all", lambda ctx: ([], []))


GOOD = [
    ("content-security-policy", "default-src 'self'; object-src 'none'"),
    ("strict-transport-security", "max-age=31536000"),
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("permissions-policy", "geolocation=()"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
]


def test_perfect_site_scores_100(monkeypatch):
    monkeypatch.setattr(scanner, "fetch_headers", fake_fetch(GOOD))
    r = analyze("example.com")
    assert r["score"] == 100 and r["grade"] == "A"
    assert r["missing"] == [] and r["weak"] == {}


def test_empty_site_scores_zero(monkeypatch):
    monkeypatch.setattr(scanner, "fetch_headers", fake_fetch([]))
    r = analyze("example.com")
    assert r["score"] == 0 and r["grade"] == "F"
    assert len(r["missing"]) == len(scanner.SECURITY_HEADERS)


def test_weak_header_gets_half_points(monkeypatch):
    headers = [h for h in GOOD if h[0] != "strict-transport-security"]
    headers.append(("strict-transport-security", "max-age=300"))
    monkeypatch.setattr(scanner, "fetch_headers", fake_fetch(headers))
    r = analyze("example.com")
    assert r["score"] == 90  # HSTS bobot 20 -> dapat 10
    assert "strict-transport-security" in r["weak"]


def test_frame_ancestors_replaces_xfo(monkeypatch):
    headers = [h for h in GOOD if h[0] != "x-frame-options"]
    headers[0] = ("content-security-policy",
                  "default-src 'self'; object-src 'none'; frame-ancestors 'none'")
    monkeypatch.setattr(scanner, "fetch_headers", fake_fetch(headers))
    r = analyze("example.com")
    assert "x-frame-options" not in r["missing"]
    assert r["score"] == 100


def test_cookie_penalty_is_capped(monkeypatch):
    cookies = [("set-cookie", f"c{i}=1") for i in range(5)]
    monkeypatch.setattr(scanner, "fetch_headers", fake_fetch(GOOD + cookies))
    r = analyze("example.com")
    assert r["score"] == 100 - scanner.COOKIE_PENALTY_CAP


@pytest.mark.parametrize("url", [
    "http://example.com:22",
    "https://user:pw@example.com",
    "http://example.com:99999",
])
def test_blocks_bad_ports_and_credentials(url):
    with pytest.raises(UnsafeURL):
        ensure_public(url)
