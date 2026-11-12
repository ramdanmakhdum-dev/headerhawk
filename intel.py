"""Intel eksternal (IP-DB + VirusTotal) dipisah dari scanner supaya scanner murni,
mudah dites, dan CLI jalan offline. Hasil di-cache agar kuota API hemat."""
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import httpx

CACHE_TTL = 1800  # 30 menit
CACHE_MAX = 500
_cache = {}
_pool = ThreadPoolExecutor(max_workers=4)


def _cached(key, fn):
    """fn() -> (nilai, boleh_di_cache). Kegagalan tidak di-cache."""
    now = time.time()
    hit = _cache.get(key)
    if hit and now - hit[0] < CACHE_TTL:
        return hit[1]
    value, cacheable = fn()
    if cacheable:
        if len(_cache) >= CACHE_MAX:
            _cache.clear()
        _cache[key] = (now, value)
    return value


def _ip_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        r = httpx.get(f"http://ip-api.com/json/{ip}",
                      params={"fields": "status,country,city,isp,query"}, timeout=3)
        data = r.json()
        if data.get("status") == "success":
            return data, True
    except Exception:
        pass
    return {"status": "fail"}, False


def _vt_lookup(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "VirusTotal tidak tersedia", False
    try:
        with httpx.Client(timeout=8, headers={"x-apikey": api_key}) as c:
            r = c.post("https://www.virustotal.com/api/v3/urls", data={"url": url})
            if r.status_code != 200:
                return f"VirusTotal gagal (HTTP {r.status_code})", False
            aid = r.json()["data"]["id"]
            attrs = c.get(f"https://www.virustotal.com/api/v3/analyses/{aid}").json()["data"]["attributes"]
        if attrs.get("status") != "completed":
            return "VirusTotal: analisis masih berjalan, scan lagi sebentar lagi", False
        s = attrs["stats"]
        return f"Malicious: {s['malicious']} | Suspicious: {s['suspicious']} | Harmless: {s['harmless']}", True
    except Exception:
        return "VirusTotal gagal dihubungi", False


def enrich(final_url):
    """Return (ip_info, virustotal). Dua lookup jalan paralel."""
    p = urlparse(final_url)
    host = p.hostname
    # Buang user:pass, query, dan fragment sebelum dikirim ke VirusTotal.
    vt_url = f"{p.scheme}://{host}{':' + str(p.port) if p.port else ''}{p.path}"
    f_ip = _pool.submit(_cached, ("ip", host), lambda: _ip_lookup(host))
    f_vt = _pool.submit(_cached, ("vt", vt_url), lambda: _vt_lookup(vt_url))
    return f_ip.result(), f_vt.result()
