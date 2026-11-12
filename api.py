import time
from collections import defaultdict, deque
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse

from ai_engine import analyze_with_ai
from intel import enrich
from scanner import UnsafeURL, analyze

BASE_DIR = Path(__file__).parent
app = FastAPI(title="HeaderHawk API")

RATE_LIMIT = 10        # /scan per menit per IP
RATE_WINDOW = 60
AI_LIMIT = 3           # /explain per menit per IP
AI_DAILY_CAP = 200     # /explain total per hari
_hits = defaultdict(deque)
_ai_hits = defaultdict(deque)
_ai_day = {"date": "", "count": 0}


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check(bucket, ip: str, limit: int, msg: str) -> None:
    now = time.time()
    q = bucket[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail=msg)
    q.append(now)


def check_rate_limit(ip: str) -> None:
    _check(_hits, ip, RATE_LIMIT, "Terlalu banyak permintaan, coba lagi sebentar")


def check_ai_limit(ip: str) -> None:
    today = time.strftime("%Y-%m-%d")
    if _ai_day["date"] != today:
        _ai_day["date"], _ai_day["count"] = today, 0
    if _ai_day["count"] >= AI_DAILY_CAP:
        raise HTTPException(status_code=429, detail="Kuota AI hari ini habis, coba lagi besok")
    _check(_ai_hits, ip, AI_LIMIT, "Terlalu banyak permintaan AI, coba lagi sebentar")
    _ai_day["count"] += 1


def run_scan(url: str) -> dict:
    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL terlalu panjang")
    try:
        result = analyze(url)
    except UnsafeURL as e:
        raise HTTPException(status_code=400, detail=str(e))
    except httpx.HTTPError:
        raise HTTPException(
            status_code=400,
            detail="Gagal mengakses target (timeout atau koneksi ditolak)")
    result["ip_info"], result["virustotal"] = enrich(result["url"])
    return result


@app.get("/")
def read_root():
    index = BASE_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "Selamat datang di HeaderHawk API!"}


@app.get("/health")
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
        "cookie_issues": r["cookie_issues"],
        "leaked_info": r["leaked_info"],
    }


@app.get("/explain")
def explain_url(url: str, request: Request):
    check_ai_limit(client_ip(request))
    r = run_scan(url)
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
