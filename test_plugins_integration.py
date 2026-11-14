"""Integration test: scanner inti + plugin registry + probe aman, disatukan.
Regression test: kontrak field hasil analyze()/respons /scan tidak berubah
untuk field lama (backward compatible untuk index.html/app.js yang sudah ada).

File ini SENGAJA mengimpor plugin_cors/plugin_tls/plugin_exposed_files supaya
plugin-plugin itu teregistrasi dan benar-benar dites berjalan bersama
scanner.analyze() lewat jalur produksi — bukan lewat ScanContext buatan
tangan seperti di unit test plugin masing-masing.
"""
import httpx
import pytest

import plugin_cors  # noqa: F401 — registrasi plugin, sengaja diimpor
import plugin_exposed_files  # noqa: F401
import plugin_tls  # noqa: F401
import scanner
from scanner import analyze

OLD_CONTRACT_KEYS = {"url", "score", "grade", "found", "missing",
                      "weak", "cookie_issues", "leaked_info"}
NEW_CONTRACT_KEYS = {"status_code", "reliability_warning", "findings", "plugin_errors"}

GOOD_HEADERS = [
    ("content-security-policy", "default-src 'self'; object-src 'none'"),
    ("strict-transport-security", "max-age=31536000"),
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("permissions-policy", "geolocation=()"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
]


@pytest.fixture
def stubbed(monkeypatch):
    """Ganti SELURUH jalur jaringan — fetch utama, dua jenis probe plugin
    (lewat scanner), DAN koneksi TLS mentah milik plugin_tls (yang memakai
    socket/ssl langsung, tidak lewat helper scanner) — dengan stub. Tanpa ini,
    plugin_tls diam-diam membuka koneksi TLS SUNGGUHAN ke internet tiap tes,
    membuat seluruh file ini lambat dan tidak deterministik."""
    state = {"status": 200, "headers": GOOD_HEADERS, "ip": "93.184.216.34",
              "probe_headers": httpx.Headers(), "probe_paths": {},
              "tls_version": "TLSv1.3", "tls_not_after": "Jan  1 00:00:00 2099 GMT"}

    def fake_fetch(url):
        return httpx.Headers(state["headers"]), url, state["status"], state["ip"]

    def fake_probe_with_headers(url, ip, extra):
        return state["probe_headers"]

    def fake_probe_path(url, ip, path):
        status = state["probe_paths"].get(path, 404)
        return httpx.Headers(), status

    class _FakeTLSSocket:
        def version(self_s):
            return state["tls_version"]

        def getpeercert(self_s):
            return {"notAfter": state["tls_not_after"]}

        def __enter__(self_s):
            return self_s

        def __exit__(self_s, *a):
            pass

    class _FakeSocket:
        def __enter__(self_s):
            return self_s

        def __exit__(self_s, *a):
            pass

    class _FakeSSLContext:
        def wrap_socket(self_s, sock, server_hostname=None):
            return _FakeTLSSocket()

    monkeypatch.setattr(scanner, "fetch_headers", fake_fetch)
    monkeypatch.setattr(scanner, "probe_with_headers", fake_probe_with_headers)
    monkeypatch.setattr(scanner, "probe_path", fake_probe_path)
    monkeypatch.setattr(plugin_tls.socket, "create_connection", lambda *a, **k: _FakeSocket())
    monkeypatch.setattr(plugin_tls.ssl, "create_default_context", lambda: _FakeSSLContext())
    return state


# ---------- Regression: kontrak field lama tidak berubah ----------

def test_result_keeps_old_fields_for_backward_compatibility(stubbed):
    r = analyze("https://example.com/")
    missing_old = OLD_CONTRACT_KEYS - r.keys()
    assert not missing_old, f"Field lama hilang, akan merusak UI lama: {missing_old}"
    assert r["score"] == 100 and r["grade"] == "A"  # logika skor lama tidak berubah


def test_result_has_new_fields_with_safe_defaults(stubbed):
    r = analyze("https://example.com/")
    assert NEW_CONTRACT_KEYS.issubset(r.keys())
    assert r["status_code"] == 200
    assert r["reliability_warning"] is None
    assert isinstance(r["findings"], list) and isinstance(r["plugin_errors"], list)


# ---------- Regresi bug: double DNS-lookup / status code diabaikan ----------

def test_non_2xx_status_sets_warning_but_still_returns_result(stubbed):
    stubbed["status"] = 403
    r = analyze("https://example.com/")
    assert r["status_code"] == 403
    assert r["reliability_warning"] and "403" in r["reliability_warning"]
    assert r["score"] == 100  # skor tetap dihitung apa adanya dari header yang ada


def test_analyze_never_calls_ensure_public_outside_fetch_headers(monkeypatch, stubbed):
    """fetch_headers di-stub total (tidak memanggil ensure_public sama sekali),
    jadi kalau analyze() masih memanggil ensure_public sendiri di luar itu —
    bug round-robin-DNS yang pernah terjadi akan muncul lagi di sini."""
    calls = []
    monkeypatch.setattr(scanner, "ensure_public", lambda url: calls.append(url) or "1.2.3.4")
    analyze("https://example.com/")
    assert calls == [], f"analyze() memanggil ensure_public() sendiri: {calls}"


# ---------- Integration: plugin sungguhan jalan lewat analyze() ----------

def test_cors_plugin_finding_reaches_final_result(stubbed):
    stubbed["probe_headers"] = httpx.Headers(
        [("access-control-allow-origin", plugin_cors.PROBE_ORIGIN),
         ("access-control-allow-credentials", "true")])
    r = analyze("https://example.com/")
    ids = {f["id"] for f in r["findings"]}
    assert "cors-reflects-arbitrary-origin" in ids
    finding = next(f for f in r["findings"] if f["id"] == "cors-reflects-arbitrary-origin")
    assert finding["severity"] == "Critical" and finding["confidence"] == "Confirmed"
    assert finding["plugin"] == "cors"


def test_exposed_file_finding_reaches_final_result(stubbed):
    stubbed["probe_paths"] = {"/.env": 200}
    r = analyze("https://example.com/")
    ids = {f["id"] for f in r["findings"]}
    assert "exposed-file:/.env" in ids


def test_one_broken_plugin_does_not_break_the_others_or_the_scan(stubbed, monkeypatch):
    import plugins as P

    @P.register
    class AlwaysBroken(P.Plugin):
        id = "always-broken-test"
        def run(self, ctx):
            raise RuntimeError("sengaja rusak untuk tes")

    try:
        stubbed["probe_paths"] = {"/.env": 200}
        r = analyze("https://example.com/")
        assert r["score"] == 100  # scan utama tidak ikut gagal
        assert any(e["plugin"] == "always-broken-test" for e in r["plugin_errors"])
        assert any(f["id"] == "exposed-file:/.env" for f in r["findings"])  # plugin lain tetap jalan
    finally:
        P._REGISTRY.pop("always-broken-test", None)  # jangan bocor ke test lain


def test_feature_flag_can_disable_a_plugin_without_touching_others(stubbed, monkeypatch):
    monkeypatch.setenv("FEATURE_FLAGS", "-exposed-files")
    stubbed["probe_paths"] = {"/.env": 200}
    r = analyze("https://example.com/")
    assert not any(f["plugin"] == "exposed-files" for f in r["findings"])
