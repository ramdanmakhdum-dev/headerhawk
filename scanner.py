import ipaddress
import json
import socket
from urllib.parse import urljoin, urlparse

from plugins import ScanContext, run_all

import httpx
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

app = typer.Typer()
console = Console()

# Bobot total = 100. Header ada tapi salah konfigurasi dapat setengah poin.
SECURITY_HEADERS = {
    "content-security-policy": 25,
    "strict-transport-security": 20,
    "x-frame-options": 10,
    "x-content-type-options": 10,
    "referrer-policy": 10,
    "permissions-policy": 10,
    "cross-origin-opener-policy": 8,
    "cross-origin-resource-policy": 7,
}
LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]
GRADES = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]
MAX_REDIRECTS = 5
HSTS_MIN_AGE = 15552000  # 180 hari
COOKIE_PENALTY_EACH, COOKIE_PENALTY_CAP = 3, 15


class UnsafeURL(ValueError):
    """URL ditolak: skema salah atau mengarah ke jaringan internal."""


# ---------- Keamanan URL (SSRF) ----------

def normalize_url(url: str) -> str:
    url = url.strip()
    return url if "://" in url else "https://" + url


ALLOWED_PORTS = {80, 443, 8080, 8443}
USER_AGENT = "HeaderHawk/2.0 (+https://github.com/ramdanmakhdum-dev/headerhawk)"


def ensure_public(url: str) -> str:
    """Validasi URL, resolve DNS SEKALI, kembalikan IP publik yang dipakai konek."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeURL("Hanya http/https yang diizinkan")
    if parsed.username or parsed.password:
        raise UnsafeURL("URL dengan kredensial tidak diizinkan")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise UnsafeURL("Port tidak valid")
    if port not in ALLOWED_PORTS:
        raise UnsafeURL("Port tidak diizinkan")
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UnsafeURL("Domain tidak ditemukan")
    ips = [i[4][0].split("%")[0] for i in infos]
    if not ips or not all(ipaddress.ip_address(ip).is_global for ip in ips):
        raise UnsafeURL("Alamat internal/privat tidak diizinkan")
    return ips[0]


def fetch_headers(url: str):
    """Tiap hop: validasi, resolve sekali, konek langsung ke IP itu (anti DNS rebinding).
    Hanya header yang dibaca; body tidak pernah diunduh."""
    with httpx.Client(timeout=10, follow_redirects=False,
                      headers={"User-Agent": USER_AGENT}) as client:
        for _ in range(MAX_REDIRECTS + 1):
            ip = ensure_public(url)
            p = urlparse(url)
            host = f"[{ip}]" if ":" in ip else ip
            target = p._replace(netloc=host + (f":{p.port}" if p.port else "")).geturl()
            with client.stream("GET", target, headers={"Host": p.netloc},
                               extensions={"sni_hostname": p.hostname}) as resp:
                loc = resp.headers.get("location")
                if resp.is_redirect and loc:
                    url = urljoin(url, loc)
                    continue
                return resp.headers, url, resp.status_code
    raise UnsafeURL("Terlalu banyak redirect")


def probe_with_headers(url: str, ip: str, extra_headers: dict):
    """Permintaan GET tambahan, read-only, ke IP yang SAMA yang sudah divalidasi
    (dipanggil setelah fetch_headers). Tidak mengikuti redirect. Dipakai plugin
    pasif, misal menguji refleksi header CORS dengan Origin custom — ini
    permintaan normal seperti browser kirim, bukan payload serangan."""
    p = urlparse(url)
    host = f"[{ip}]" if ":" in ip else ip
    target = p._replace(netloc=host + (f":{p.port}" if p.port else "")).geturl()
    headers = {"User-Agent": USER_AGENT, "Host": p.netloc, **extra_headers}
    with httpx.Client(timeout=8, follow_redirects=False,
                      headers={"User-Agent": USER_AGENT}) as client:
        with client.stream("GET", target, headers=headers,
                           extensions={"sni_hostname": p.hostname}) as resp:
            return resp.headers


def probe_path(url: str, ip: str, path: str):
    """HEAD read-only ke path tetap (mis. /.env) di host & IP yang sama, untuk
    cek keberadaan berkas sensitif TANPA mengambil isinya. Tidak mengikuti
    redirect, tidak pernah mengubah state di server (metode HEAD)."""
    p = urlparse(url)
    host = f"[{ip}]" if ":" in ip else ip
    target = p._replace(path=path, query="", netloc=host + (f":{p.port}" if p.port else "")).geturl()
    with httpx.Client(timeout=6, follow_redirects=False,
                      headers={"User-Agent": USER_AGENT}) as client:
        with client.stream("HEAD", target, headers={"Host": p.netloc},
                           extensions={"sni_hostname": p.hostname}) as resp:
            return resp.headers, resp.status_code


# ---------- Pengecekan kualitas header ----------

def parse_csp(value: str) -> dict:
    """'default-src 'self'; img-src *' -> {'default-src': ["'self'"], ...}"""
    directives = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tokens[1:])
    return directives


def check_csp(value: str) -> list:
    issues = []
    d = parse_csp(value)
    script = d.get("script-src") or d.get("default-src")
    if script is None:
        issues.append("Tidak ada script-src atau default-src")
    else:
        low = [s.lower() for s in script]
        strict = any(
            s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
            or s == "'strict-dynamic'"
            for s in low
        )
        if "'unsafe-inline'" in low and not strict:
            issues.append("script-src memakai 'unsafe-inline'")
        if "'unsafe-eval'" in low:
            issues.append("script-src memakai 'unsafe-eval'")
        if any(s in ("*", "http:", "data:") for s in low):
            issues.append("script-src terlalu longgar (*, http:, atau data:)")
    if "object-src" not in d and "default-src" not in d:
        issues.append("object-src tidak dibatasi")
    return issues


def check_hsts(value: str) -> list:
    max_age = None
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1].strip('"'))
            except ValueError:
                pass
    if max_age is None:
        return ["max-age tidak valid"]
    if max_age < HSTS_MIN_AGE:
        return ["max-age kurang dari 180 hari"]
    return []


def check_xfo(value: str) -> list:
    if value.strip().upper() in ("DENY", "SAMEORIGIN"):
        return []
    return ["Nilai harus DENY atau SAMEORIGIN"]


def check_xcto(value: str) -> list:
    return [] if value.strip().lower() == "nosniff" else ["Nilai harus nosniff"]


def check_referrer(value: str) -> list:
    last = value.split(",")[-1].strip().lower()
    if last in ("unsafe-url", "no-referrer-when-downgrade"):
        return [f"Kebijakan '{last}' membocorkan URL lengkap"]
    return []


def check_coop(value: str) -> list:
    if value.strip().lower() == "unsafe-none":
        return ["unsafe-none = tidak ada isolasi"]
    return []


CHECKS = {
    "content-security-policy": check_csp,
    "strict-transport-security": check_hsts,
    "x-frame-options": check_xfo,
    "x-content-type-options": check_xcto,
    "referrer-policy": check_referrer,
    "cross-origin-opener-policy": check_coop,
}


def check_cookies(headers) -> list:
    issues = []
    for raw in headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()[:40]
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        if "secure" not in attrs:
            issues.append(f"Cookie '{name}' tanpa Secure")
        if "httponly" not in attrs:
            issues.append(f"Cookie '{name}' tanpa HttpOnly")
        if not any(a.startswith("samesite=") for a in attrs):
            issues.append(f"Cookie '{name}' tanpa SameSite")
    return issues


# ---------- Analisis ----------

def analyze(url: str) -> dict:
    headers, final_url, status_code = fetch_headers(normalize_url(url))
    csp_dirs = parse_csp(headers.get("content-security-policy", ""))
    found, weak, missing = {}, {}, []
    points = 0.0

    for name, weight in SECURITY_HEADERS.items():
        value = headers.get(name)
        if value is None:
            if name == "x-frame-options" and "frame-ancestors" in csp_dirs:
                found[name] = "(dilindungi via CSP frame-ancestors)"
                points += weight
            else:
                missing.append(name)
            continue
        found[name] = value
        issues = CHECKS[name](value) if name in CHECKS else []
        if issues:
            weak[name] = issues
            points += weight / 2
        else:
            points += weight

    cookie_issues = check_cookies(headers)
    penalty = min(COOKIE_PENALTY_CAP, COOKIE_PENALTY_EACH * len(cookie_issues))
    final = max(0, int(points - penalty))
    grade = next(g for limit, g in GRADES if final >= limit)
    result = {
        "url": final_url, "score": final, "grade": grade,
        "found": found, "missing": missing,
        "weak": weak, "cookie_issues": cookie_issues,
        "leaked_info": {h: headers[h] for h in LEAK_HEADERS if h in headers},
        "status_code": status_code,
        "reliability_warning": None,
        "findings": [], "plugin_errors": [],
    }
    if not (200 <= status_code < 300):
        result["reliability_warning"] = (
            f"Server merespons HTTP {status_code}, bukan halaman normal (2xx). "
            "Header di atas berasal dari halaman ini (bisa jadi halaman error/blokir "
            "bot), bukan jaminan konfigurasi situs yang sebenarnya.")

    p = urlparse(final_url)
    ip = ensure_public(final_url)  # sudah tervalidasi sebelumnya; ambil IP yang sama untuk plugin
    ctx = ScanContext(
        url=final_url, ip=ip, hostname=p.hostname, port=p.port or (443 if p.scheme == "https" else 80),
        scheme=p.scheme, status_code=status_code, headers=headers,
        probe_with_headers=lambda extra: probe_with_headers(final_url, ip, extra),
        probe_path=lambda path: probe_path(final_url, ip, path),
    )
    findings, errors = run_all(ctx)
    result["findings"] = [f.to_dict() for f in findings]
    result["plugin_errors"] = errors
    return result


@app.command()
def scan(
    url: str,
    as_json: bool = typer.Option(False, "--json", help="Output JSON"),
    fail_under: int = typer.Option(
        0, "--fail-under", help="Exit code 2 jika skor di bawah angka ini (untuk CI)"),
):
    """Scan security headers dari URL target."""
    try:
        result = analyze(url)
    except (UnsafeURL, httpx.HTTPError) as e:
        console.print(f"[bold red]Error:[/bold red] {escape(str(e))}")
        raise typer.Exit(code=1)

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        table = Table(title=f"Security Headers Report: {escape(result['url'])}")
        table.add_column("Header", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Catatan", style="green")
        for name in SECURITY_HEADERS:
            if name in result["weak"]:
                table.add_row(name, "Lemah", escape("; ".join(result["weak"][name])))
            elif name in result["found"]:
                v = result["found"][name]
                table.add_row(name, "Ada", escape(v if len(v) <= 50 else v[:50] + "..."))
            else:
                table.add_row(name, "Tidak Ada", "-")
        console.print(table)
        for issue in result["cookie_issues"]:
            console.print(f"[yellow]Cookie:[/yellow] {escape(issue)}")
        console.print(f"\n[bold]Skor:[/bold] {result['score']}/100 | "
                      f"[bold]Grade:[/bold] {result['grade']}")

    if result["score"] < fail_under:
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
