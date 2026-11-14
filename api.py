import hmac
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse

from ai_engine import analyze_with_ai
from intel import enrich
import plugin_cors, plugin_exposed_files, plugin_tls  # noqa: F401 (registrasi plugin)
from scanner import UnsafeURL, analyze

BASE_DIR = Path(__file__).parent
# Dokumentasi interaktif dimatikan: tidak perlu publik dan butuh inline script.
app = FastAPI(title="HeaderHawk API", docs_url=None, redoc_url=None, openapi_url=None)

RATE_LIMIT = 10        # /scan per menit per IP
GLOBAL_LIMIT = 40      # /scan per menit untuk SEMUA pengguna
RATE_WINDOW = 60
AI_LIMIT = 3           # /explain per menit per IP
AI_DAILY_CAP = 200     # /explain total per hari
MAX_TRACKED = 5000     # batas jumlah IP yang dicatat (anti memori membengkak)
MAX_PARALLEL = 4       # scan yang boleh berjalan bersamaan
SCAN_TTL = 300         # /explain memakai hasil /scan terakhir (5 menit)
# Jumlah proxy tepercaya di depan app (Render). Cek lewat DEBUG_IP=1 di log.
TRUSTED_HOPS = max(1, int(os.environ.get("TRUSTED_PROXY_HOPS", "1")))

AUTH_FAIL_LIMIT = 5     # password AI salah maksimal 5x ...
AUTH_FAIL_WINDOW = 900  # ... per 15 menit per IP

_hits = defaultdict(deque)
_auth_fails = defaultdict(deque)
_ai_hits = defaultdict(deque)
_global = defaultdict(deque)
_ai_day = {"date": "", "count": 0}
_scan_cache = {}
_slots = threading.BoundedSemaphore(MAX_PARALLEL)

CSP = ("default-src 'none'; script-src 'self' https://cdn.jsdelivr.net; "
       "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
       "font-src https://cdnjs.cloudflare.com; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")
SEC_HEADERS = {
    "Content-Security-Policy": CSP,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for key, value in SEC_HEADERS.items():
        response.headers[key] = value
    if request.url.path in ("/scan", "/explain"):
        response.headers["Cache-Control"] = "no-store"
    return response


def client_ip(request: Request) -> str:
    """X-Forwarded-For bisa dipalsukan klien di bagian kiri. Hanya entri yang
    ditambahkan proxy tepercaya (bagian kanan) yang boleh dipercaya."""
    fwd = request.headers.get("x-forwarded-for")
    peer = request.client.host if request.client else "unknown"
    ip = peer
    if fwd:
        parts = [p.strip() for p in fwd.split(",") if p.strip()]
        if parts:
            ip = parts[-min(TRUSTED_HOPS, len(parts))]
    if os.environ.get("DEBUG_IP"):
        print(f"DEBUG_IP xff={fwd!r} peer={peer} dipakai={ip} hops={TRUSTED_HOPS}", flush=True)
    return ip


def _check(bucket, ip: str, limit: int, msg: str) -> None:
    now = time.time()
    if ip not in bucket and len(bucket) >= MAX_TRACKED:
        for k in [k for k, q in bucket.items() if not q or now - q[-1] > RATE_WINDOW]:
            del bucket[k]
        if len(bucket) >= MAX_TRACKED:
            raise HTTPException(status_code=429, detail="Server sedang sibuk, coba lagi sebentar")
    q = bucket[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail=msg)
    q.append(now)


def check_rate_limit(ip: str) -> None:
    _check(_hits, ip, RATE_LIMIT, "Terlalu banyak permintaan, coba lagi sebentar")
    _check(_global, "all", GLOBAL_LIMIT, "Server sedang ramai, coba lagi sebentar")


def check_ai_limit(ip: str) -> None:
    today = time.strftime("%Y-%m-%d")
    if _ai_day["date"] != today:
        _ai_day["date"], _ai_day["count"] = today, 0
    if _ai_day["count"] >= AI_DAILY_CAP:
        raise HTTPException(status_code=429, detail="Kuota AI hari ini habis, coba lagi besok")
    _check(_ai_hits, ip, AI_LIMIT, "Terlalu banyak permintaan AI, coba lagi sebentar")
    _ai_day["count"] += 1


def require_ai_password(request: Request, ip: str) -> None:
    """Fitur AI dikunci: hanya yang tahu AI_PASSWORD (env) yang boleh memakai."""
    expected = os.environ.get("AI_PASSWORD", "")
    if not expected:  # fail closed: tanpa password terpasang, AI mati
        raise HTTPException(status_code=503, detail="Fitur AI sedang dinonaktifkan")
    now = time.time()
    if ip not in _auth_fails and len(_auth_fails) >= MAX_TRACKED:
        for k in [k for k, q in _auth_fails.items() if not q or now - q[-1] > AUTH_FAIL_WINDOW]:
            del _auth_fails[k]
        if len(_auth_fails) >= MAX_TRACKED:
            raise HTTPException(status_code=429, detail="Server sedang sibuk, coba lagi nanti")
    q = _auth_fails[ip]
    while q and now - q[0] > AUTH_FAIL_WINDOW:
        q.popleft()
    if len(q) >= AUTH_FAIL_LIMIT:
        raise HTTPException(status_code=429, detail="Terlalu banyak percobaan salah, coba lagi nanti")
    given = request.headers.get("x-ai-password", "")
    if not hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8")):
        q.append(now)
        raise HTTPException(status_code=401, detail="Password salah")


def run_scan(url: str, use_cache: bool = False) -> dict:
    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL terlalu panjang")
    key = url.strip().lower()
    hit = _scan_cache.get(key)
    if use_cache and hit and time.time() - hit[0] < SCAN_TTL:
        return hit[1]
    if not _slots.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="Server sedang sibuk, coba lagi sebentar")
    try:
        try:
            result = analyze(url)
        except UnsafeURL as e:
            raise HTTPException(status_code=400, detail=str(e))
        except (ValueError, httpx.InvalidURL):
            raise HTTPException(status_code=400, detail="URL tidak valid")
        except httpx.HTTPError:
            raise HTTPException(
                status_code=400,
                detail="Gagal mengakses target (timeout atau koneksi ditolak)")
        result["ip_info"], result["virustotal"] = enrich(result["url"])
    finally:
        _slots.release()
    if len(_scan_cache) >= 200:
        _scan_cache.clear()
    _scan_cache[key] = (time.time(), result)
    return result


@app.api_route("/", methods=["GET", "HEAD"])
def read_root():
    index = BASE_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "Selamat datang di HeaderHawk API!"}


@app.get("/app.js")
def app_js():
    return FileResponse(BASE_DIR / "app.js", media_type="application/javascript")


@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    return {"status": "ok"}


@app.get("/scan")
def scan_url(url: str, request: Request):
    check_rate_limit(client_ip(request))
    r = run_scan(url)
    return {
        "url": r["url"],
        "score": r["score"],
        "grade": r["grade"],
        "ip_info": r["ip_info"],
        "virustotal": r["virustotal"],
        "found_headers": r["found"],
        "missing_headers": r["missing"],
        "weak_headers": r["weak"],
        "status_code": r.get("status_code"),
        "reliability_warning": r.get("reliability_warning"),
        "findings": r.get("findings", []),
        "plugin_errors": r.get("plugin_errors", []),
        "status_code": r.get("status_code"),
        "reliability_warning": r.get("reliability_warning"),
        "findings": r.get("findings", []),
        "plugin_errors": r.get("plugin_errors", []),
        "cookie_issues": r["cookie_issues"],
        "leaked_info": r["leaked_info"],
    }


@app.get("/explain")
def explain_url(url: str, request: Request):
    ip = client_ip(request)
    require_ai_password(request, ip)  # cek password dulu, sebelum kuota AI terpakai
    check_ai_limit(ip)
    r = run_scan(url, use_cache=True)
    data = {
        "url": r["url"],
        "score": r["score"],
        "grade": r["grade"],
        "ip_info": r["ip_info"],
        "virustotal": r["virustotal"],
        "missing_headers": r["missing"],
        "weak_headers": r["weak"],
        "cookie_issues": r["cookie_issues"],
        "leaked_info": r["leaked_info"],
    }
    return {"explanation": analyze_with_ai(data)}
