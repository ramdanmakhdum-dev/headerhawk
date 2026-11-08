# HeaderHawk 🦅

CLI and API that scans a website's HTTP security headers and gives it a score and grade.

**Live demo:** https://headerhawk-r8zd.onrender.com
(Hosted on Render's free tier: the first request may take ~30s while the server wakes up.)

## Features
- Checks 6 security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Score (0-100) and grade (A-F)
- CLI with rich table output or `--json`
- REST API (FastAPI) and a simple web UI
- SSRF protection: only http/https, private/internal IPs blocked, redirects re-validated
- Basic rate limiting (10 requests/minute per IP)

## Install
    git clone https://github.com/ramdanmakhdum-dev/headerhawk
    cd headerhawk
    python -m venv venv && source venv/bin/activate
    pip install -r requirements.txt

## Usage
CLI:

    python scanner.py github.com
    python scanner.py github.com --json

API:

    uvicorn api:app --port 8000
    curl "http://localhost:8000/scan?url=github.com"

## Scoring
| Header | Weight |
|---|---|
| Strict-Transport-Security | 20 |
| Content-Security-Policy | 20 |
| X-Frame-Options | 15 |
| X-Content-Type-Options | 15 |
| Referrer-Policy | 15 |
| Permissions-Policy | 15 |

Grades: A >= 90, B >= 75, C >= 60, D >= 40, F below.

## Limitations
- Passive check only: it reads response headers, it does not test for vulnerabilities.
- The private-IP check does not fully prevent DNS rebinding.
- Rate limiting is in-memory and trusts `X-Forwarded-For`; use a proper limiter (e.g. slowapi) or a reverse proxy in production.
- Only 6 headers are scored. Cookie flags and information-leaking headers are not checked yet.

## Disclaimer
Only scan sites you own or have permission to test.

## License
MIT

![HeaderHawk scan result](Screenshot_20261017-131159.png)





![Blocked internal address](Screenshot_20261017-131213.png)
