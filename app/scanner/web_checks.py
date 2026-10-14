"""HTTPS / TLS certificate / security-header checks."""
import socket
import ssl
from datetime import datetime, timezone

from . import net

TIMEOUT = 8.0


def _accepts_legacy_tls(domain: str) -> bool:
    """True if the server completes a handshake restricted to TLS 1.0/1.1."""
    for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Protocol probe only: certificate validity is judged by check_tls_cert.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # OpenSSL 3's default security level refuses TLS 1.0/1.1 client-side,
            # which made this probe always report "not accepted". Lower it here.
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            ctx.minimum_version = version
            ctx.maximum_version = version
            # Failure to connect is the safe outcome
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    return True
        except Exception:
            continue
    return False


def check_tls_cert(domain: str) -> dict:
    max_score = 5
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        # The server answered with a certificate browsers reject (expired,
        # self-signed, wrong hostname, incomplete chain). That is a failure,
        # not an unreachable host.
        reason = getattr(e, "verify_message", "") or "verification failed"
        return {"key": "tls-cert", "title": "TLS Certificate", "status": "fail", "score": 0,
                "max_score": max_score,
                "details": f"Certificate rejected by browsers: {reason}.",
                "issues": [f"TLS certificate is not trusted ({reason})."],
                "fixes": ["Install a valid certificate covering this hostname with its full chain "
                          "(e.g. via ACME / Let's Encrypt) and renew it before expiry."]}
    except Exception as e:
        return {"key": "tls-cert", "title": "TLS Certificate", "status": "warn", "score": 1,
                "max_score": max_score,
                "details": f"Could not complete TLS handshake on 443: {type(e).__name__}.",
                "issues": [], "fixes": []}
    try:
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (not_after - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "unknown")
    except Exception:
        days, issuer = -1, "unknown"
    if days < 0:
        return {"key": "tls-cert", "title": "TLS Certificate", "status": "fail", "score": 0,
                "max_score": max_score, "details": "Certificate is expired or invalid.",
                "issues": ["TLS certificate expired or not trusted."],
                "fixes": ["Renew the certificate immediately."]}
    issues, fixes, score, status = [], [], max_score, "pass"
    if days < 14:
        issues.append(f"Certificate expires in {days} day{'s' if days != 1 else ''}.")
        fixes.append("Renew the certificate; consider automated renewal (ACME).")
        status, score = "warn", 3
    if _accepts_legacy_tls(domain):
        issues.append("Server still accepts TLS 1.0/1.1: deprecated, vulnerable to downgrade attacks.")
        fixes.append("Disable TLS 1.0/1.1; require TLS 1.2+ on the web server.")
        if status == "pass":
            status, score = "warn", 3
        else:
            score = max(0, score - 1)
    return {"key": "tls-cert", "title": "TLS Certificate", "status": status, "score": score,
            "max_score": max_score,
            "details": f"Valid, expires in {days} days (issuer: {issuer}).",
            "issues": issues, "fixes": fixes}


SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS", 2, "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", "CSP", 1, "Deploy a Content-Security-Policy header"),
    ("x-frame-options", "X-Frame-Options", 1, "Add X-Frame-Options: DENY or SAMEORIGIN (or frame-ancestors in CSP)"),
    ("x-content-type-options", "X-Content-Type-Options", 1, "Add X-Content-Type-Options: nosniff"),
]


def check_security_headers(domain: str) -> dict:
    max_score = 5
    over_https = True
    try:
        r = net.safe_get(f"https://{domain}", timeout=TIMEOUT)
        headers = {k.lower(): v for k, v in r.headers.items()}
        over_https = r.url.scheme == "https"
    except Exception:
        try:
            r = net.safe_get(f"http://{domain}", timeout=TIMEOUT)
            headers = {k.lower(): v for k, v in r.headers.items()}
            over_https = r.url.scheme == "https"
        except Exception as e:
            return {"key": "sec-headers", "title": "Web Security Headers", "status": "warn",
                    "score": 2, "max_score": max_score,
                    "details": f"Web server unreachable: {type(e).__name__}.",
                    "issues": [], "fixes": []}
    score = 0
    missing = []
    present = []
    if not over_https:
        # Browsers ignore HSTS delivered over plain HTTP (RFC 6797 §8.1).
        headers.pop("strict-transport-security", None)
    if "frame-ancestors" in headers.get("content-security-policy", "").lower():
        headers.setdefault("x-frame-options", "csp frame-ancestors")
    for header, label, points, fix in SECURITY_HEADERS:
        if header in headers:
            score += points
            present.append(label)
        else:
            missing.append((label, fix))
    if score >= max_score - 1:
        status = "pass"
    elif score >= 3:
        status = "warn"
    else:
        status = "fail"
    return {"key": "sec-headers", "title": "Web Security Headers", "status": status, "score": score,
            "max_score": max_score,
            "details": f"Present: {', '.join(present) or 'none'}.",
            "issues": [f"Missing {label}." for label, _ in missing],
            "fixes": [fix for _, fix in missing]}
