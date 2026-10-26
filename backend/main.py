from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import secrets
import socket
import ssl
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl

ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "frontend"
DATA_DIR = ROOT / "data"
SCAN_FILE = DATA_DIR / "scans.json"
MAX_REDIRECTS = 4
MAX_BODY_BYTES = 600_000
REQUEST_TIMEOUT = 10.0

app = FastAPI(title="Palisight", version="0.1.0", docs_url="/api/docs")
app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")


class ScanRequest(BaseModel):
    url: HttpUrl


def normalized_target(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(400, "Use a complete http or https URL.")
    if parsed.username or parsed.password or parsed.fragment:
        raise HTTPException(400, "Credentials and URL fragments are not accepted.")
    if parsed.port and parsed.port not in {80, 443}:
        raise HTTPException(400, "Only public web ports 80 and 443 are allowed.")
    return parsed.geturl()


def public_host(hostname: str) -> None:
    blocked_names = {"localhost", "localhost.localdomain", "metadata.google.internal"}
    if hostname.lower().rstrip(".") in blocked_names:
        raise HTTPException(400, "Local and cloud metadata destinations are blocked.")
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(400, "The hostname could not be resolved.") from exc
    addresses = {record[4][0] for record in records}
    if not addresses:
        raise HTTPException(400, "The hostname did not resolve to a public address.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise HTTPException(400, "Private, loopback, link-local, and special-use addresses are blocked.")


def validate_url(value: str) -> str:
    target = normalized_target(value)
    public_host(urlparse(target).hostname or "")
    return target


def certificate_details(hostname: str, port: int) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as tcp:
        with context.wrap_socket(tcp, server_hostname=hostname) as secured:
            certificate = secured.getpeercert()
            expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), tz=UTC)
            def name_value(parts: tuple[tuple[tuple[str, str], ...], ...]) -> str:
                return ", ".join(f"{key}={value}" for group in parts for key, value in group)

            return {
                "protocol": secured.version(),
                "expires_at": expires_at.isoformat(),
                "valid_from": certificate.get("notBefore"),
                "days_remaining": (expires_at - datetime.now(UTC)).days,
                "issuer": name_value(certificate.get("issuer", ())),
                "subject": name_value(certificate.get("subject", ())),
                "serial_number": certificate.get("serialNumber"),
            }


async def bounded_get(client: httpx.AsyncClient, target: str) -> tuple[httpx.Response, str]:
    current = validate_url(target)
    for _ in range(MAX_REDIRECTS + 1):
        async with client.stream("GET", current, follow_redirects=False) as response:
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    raise HTTPException(422, "The website returned a redirect without a destination.")
                current = validate_url(urljoin(current, location))
                continue
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > MAX_BODY_BYTES:
                    raise HTTPException(422, "Response exceeded Palisight's 600 KB safety limit.")
                chunks.append(chunk)
            response._content = b"".join(chunks)
            return response, current
    raise HTTPException(422, "Too many redirects (limit: 4).")


def finding(key: str, severity: str, title: str, evidence: str, remediation: str, category: str) -> dict:
    return {"key": key, "severity": severity, "title": title, "evidence": evidence, "remediation": remediation, "category": category}


def security_header_findings(headers: httpx.Headers) -> list[dict]:
    rules = [
        ("strict-transport-security", "high", "HSTS is missing", "Force future browser requests to stay on HTTPS."),
        ("content-security-policy", "high", "Content Security Policy is missing", "Define an enforcing CSP and deploy it in report-only mode first."),
        ("x-content-type-options", "medium", "X-Content-Type-Options is missing", "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "low", "Referrer-Policy is missing", "Use strict-origin-when-cross-origin or a stricter policy."),
        ("permissions-policy", "low", "Permissions-Policy is missing", "Restrict browser features your site does not need."),
    ]
    out = []
    for name, severity, title, remediation in rules:
        if name not in headers:
            out.append(finding(name, severity, title, "Header was not present on the final response.", remediation, "Headers"))
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp:
        out.append(finding("framing", "medium", "Framing protection is missing", "Neither X-Frame-Options nor CSP frame-ancestors was observed.", "Set frame-ancestors 'none' or an explicit allowlist.", "Headers"))
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
        out.append(finding("csp-unsafe", "medium", "CSP permits unsafe script execution", "The policy contains unsafe-inline or unsafe-eval.", "Replace unsafe allowances with nonces, hashes, or trusted sources.", "Headers"))
    return out


def cookie_findings(headers: httpx.Headers) -> list[dict]:
    out = []
    for raw in headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0]
        lower = raw.lower()
        if "secure" not in lower:
            out.append(finding(f"cookie-secure-{name}", "medium", f"Cookie {name} lacks Secure", "Observed Set-Cookie without the Secure attribute.", "Add Secure to cookies sent over HTTPS.", "Cookies"))
        if "httponly" not in lower:
            out.append(finding(f"cookie-httponly-{name}", "low", f"Cookie {name} lacks HttpOnly", "Observed Set-Cookie without the HttpOnly attribute.", "Add HttpOnly unless client-side JavaScript must read this cookie.", "Cookies"))
        if "samesite" not in lower:
            out.append(finding(f"cookie-samesite-{name}", "low", f"Cookie {name} lacks SameSite", "Observed Set-Cookie without a SameSite attribute.", "Set SameSite=Lax or Strict when compatible with the application flow.", "Cookies"))
    return out


def html_findings(content: bytes, final_url: str) -> list[dict]:
    if not content:
        return []
    html = content.decode("utf-8", errors="ignore")
    insecure = re.findall(r'''(?:src|href|action)=["'](http://[^"']+)''', html, flags=re.I)
    if urlparse(final_url).scheme == "https" and insecure:
        return [finding("mixed-content", "medium", "Insecure HTTP resource references", f"Found {len(insecure)} HTTP resource or form reference(s) in the response HTML.", "Serve all referenced resources and form endpoints over HTTPS.", "Content")]
    return []


def transport_findings(start_url: str, final_url: str, headers: httpx.Headers) -> list[dict]:
    out = []
    if urlparse(start_url).scheme == "http" and urlparse(final_url).scheme != "https":
        out.append(finding("https-redirect", "high", "HTTP does not redirect to HTTPS", f"Final URL remained {final_url}.", "Redirect HTTP requests to the HTTPS equivalent.", "Transport"))
    if urlparse(final_url).scheme == "https" and "strict-transport-security" not in headers:
        out.append(finding("hsts-transport", "medium", "HTTPS lacks HSTS", "The HTTPS response does not include Strict-Transport-Security.", "Set HSTS after confirming HTTPS works for all subdomains you include.", "Transport"))
    return out


def exposure_findings(headers: httpx.Headers) -> list[dict]:
    out = []
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        if headers.get(name):
            out.append(finding(f"exposure-{name}", "low", f"{name.title()} discloses implementation detail", f"Observed {name}: {headers[name]}", "Remove or minimize unnecessary technology-identifying response headers.", "Exposure"))
    return out


def observed_controls(headers: httpx.Headers) -> list[dict]:
    controls = []
    for name in ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"):
        value = headers.get(name)
        if value:
            controls.append({"name": name, "value": value[:240]})
    return controls


def score(findings: list[dict]) -> tuple[int, str]:
    deductions = {"high": 14, "medium": 7, "low": 3}
    result = max(0, 100 - sum(deductions.get(x["severity"], 0) for x in findings))
    return result, "Strong" if result >= 85 else "Needs attention" if result >= 60 else "At risk"


def load_scans() -> list[dict]:
    if not SCAN_FILE.exists():
        return []
    return json.loads(SCAN_FILE.read_text(encoding="utf-8"))


def save_scan(report: dict) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    scans = load_scans()
    scans.insert(0, report)
    SCAN_FILE.write_text(json.dumps(scans[:30], indent=2), encoding="utf-8")


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "mode": "local-only"}


@app.post("/api/scan")
async def scan(request: ScanRequest) -> dict:
    started_at = datetime.now(UTC)
    target = validate_url(str(request.url))
    timeout = httpx.Timeout(REQUEST_TIMEOUT)
    try:
        async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": "Palisight/0.1 (local security posture checker)"}) as client:
            response, final_url = await bounded_get(client, target)
    except httpx.RequestError as exc:
        raise HTTPException(502, "The target could not be reached within Palisight's network limits.") from exc
    findings = security_header_findings(response.headers)
    findings += cookie_findings(response.headers)
    findings += html_findings(response.content, final_url)
    findings += transport_findings(target, final_url, response.headers)
    findings += exposure_findings(response.headers)
    tls = None
    if urlparse(final_url).scheme == "https":
        try:
            parsed_final = urlparse(final_url)
            tls = await asyncio.to_thread(certificate_details, parsed_final.hostname or "", parsed_final.port or 443)
            if tls["days_remaining"] < 30:
                severity = "high" if tls["days_remaining"] < 7 else "medium"
                findings.append(finding("certificate-expiry", severity, "TLS certificate expires soon", f"Certificate expires in {tls['days_remaining']} day(s).", "Renew the certificate and confirm automated renewal is working.", "Transport"))
        except (OSError, ssl.SSLError, KeyError) as exc:
            findings.append(finding("certificate-assessment", "medium", "TLS certificate details could not be assessed", str(exc)[:160], "Check certificate validity and connectivity from the scan environment.", "Transport"))
    final_score, status = score(findings)
    categories = {"Transport": 100, "Headers": 100, "Cookies": 100, "Content": 100, "Exposure": 100}
    for item in findings:
        categories[item["category"]] = max(0, categories[item["category"]] - {"high": 28, "medium": 14, "low": 6}[item["severity"]])
    final_parsed = urlparse(final_url)
    report = {"id": secrets.token_hex(6), "target": target, "final_url": final_url, "scanned_at": datetime.now(UTC).isoformat(), "duration_ms": int((datetime.now(UTC) - started_at).total_seconds() * 1000), "score": final_score, "status": status, "categories": categories, "findings": findings, "response_status": response.status_code, "tls": tls, "observed_controls": observed_controls(response.headers), "site": {"hostname": final_parsed.hostname, "scheme": final_parsed.scheme, "port": final_parsed.port or (443 if final_parsed.scheme == "https" else 80), "server": response.headers.get("server", "Not disclosed"), "content_type": response.headers.get("content-type", "Not disclosed"), "content_length": response.headers.get("content-length", "Not disclosed"), "cookie_count": len(response.headers.get_list("set-cookie"))}, "coverage": "5 of 5 passive configuration categories assessed"}
    save_scan(report)
    return report


@app.get("/api/history")
async def history() -> list[dict]:
    return load_scans()


@app.get("/api/reports/{report_id}")
async def get_report(report_id: str) -> dict:
    for report in load_scans():
        if report["id"] == report_id:
            return report
    raise HTTPException(404, "Report not found.")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
