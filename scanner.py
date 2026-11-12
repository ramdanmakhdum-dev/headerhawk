import ipaddress
import json
import socket
from urllib.parse import urlparse

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


def ensure_public(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeURL("Hanya http/https yang diizinkan")
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
    except socket.gaierror:
        raise UnsafeURL("Domain tidak ditemukan")
    for info in infos:
        if not ipaddress.ip_address(info[4][0].split("%")[0]).is_global:
            raise UnsafeURL("Alamat internal/privat tidak diizinkan")


def fetch_headers(url: str):
    """Setiap redirect divalidasi ulang sebelum diikuti."""
    with httpx.Client(timeout=10, follow_redirects=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            ensure_public(url)
            resp = client.get(url)
            if resp.is_redirect and "location" in resp.headers:
                url = str(resp.url.join(resp.headers["location"]))
                continue
            return resp.headers, str(resp.url)
    raise UnsafeURL("Terlalu banyak redirect")


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
    headers, final_url = fetch_headers(normalize_url(url))
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
    return {
        "url": final_url, "score": final, "grade": grade,
        "found": found, "missing": missing,
        "weak": weak, "cookie_issues": cookie_issues,
        "leaked_info": {h: headers[h] for h in LEAK_HEADERS if h in headers},
    }


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
