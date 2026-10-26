# Palisight

Palisight is a local-first web security posture checker for websites you own or are authorized to assess. It produces an evidence-based report for HTTPS, security headers, cookies, redirects, mixed content, and information exposure.

## Safety boundary

- Local-only data: reports are stored in `data/scans.json`.
- No telemetry, account, cloud service, port scan, crawling, fuzzing, login attempts, or exploit payloads.
- Public snapshot mode assesses one publicly reachable page at a time, without account setup.
- The scanner only permits public `http` and `https` destinations on ports 80 and 443, blocks private and special-use IP ranges, caps redirects and response size, and uses `GET`/`HEAD` only.

## Run locally

1. Create and activate a Python 3.11+ virtual environment.
2. Install dependencies: `pip install -r backend/requirements.txt`
3. Start: `uvicorn backend.main:app --reload --port 8000`
4. Open `http://127.0.0.1:8000`

Demo data works immediately. Enter a public URL to run a bounded snapshot assessment.

## Scope

Palisight assesses observable configuration. It cannot prove a website is secure and does not perform vulnerability exploitation or authenticated testing.
