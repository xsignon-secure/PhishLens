"""Phishing report inbox: people forward a suspicious email (as an
attachment, or the raw .eml) and PhishLens triages it: sender
authentication from the headers, every link checked with the URL checker,
one verdict. Only headers and links are kept, never the message body.

Also writes takedown requests: an abuse report for the registrar and the
hosting network of a phishing domain, with the abuse addresses looked up in
RDAP."""
import email
import ipaddress
import re
from email import policy
from html import unescape

import dns.resolver
import httpx

from . import header_analyzer, url_check
from .scanner.lookalike import split_domain

MAX_BYTES = 5 * 1024 * 1024
MAX_URLS = 10
_URL = re.compile(r"https?://[^\s\"'<>()\[\]]+", re.I)
_HREF = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.I)
VERDICT_ORDER = ("clean", "suspicious", "likely phishing", "dangerous")


class ReportError(ValueError):
    pass


def _inner(msg):
    """A forwarded-as-attachment report: analyse the attached message."""
    for part in msg.walk():
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            inner = payload[0] if isinstance(payload, list) and payload else None
            if inner is not None and inner.keys():
                return inner
            if inner is not None and str(part.get("Content-Transfer-Encoding", "")).lower() == "base64":
                # Some mail apps base64-encode the attached message.
                import base64
                try:
                    raw = base64.b64decode(inner.get_payload(), validate=False)
                    return email.message_from_bytes(raw, policy=policy.default)
                except (ValueError, TypeError):
                    pass
    return msg


def _urls(msg) -> list[str]:
    found = []
    for part in msg.walk():
        if part.get_content_maintype() != "text":
            continue
        try:
            text = part.get_content()
        except (LookupError, ValueError):
            continue
        if part.get_content_subtype() == "html":
            found += [unescape(u) for u in _HREF.findall(text)]
        found += _URL.findall(text)
    out, seen = [], set()
    for u in found:
        u = u.strip().rstrip(".,;")
        if not u.lower().startswith(("http://", "https://")) or u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def parse(raw: bytes) -> dict:
    if not raw:
        raise ReportError("Empty upload")
    if len(raw) > MAX_BYTES:
        raise ReportError("The message is too large (5 MB max)")
    msg = _inner(email.message_from_bytes(raw, policy=policy.default))
    headers = "".join(f"{k}: {v}\n" for k, v in msg.items())
    if not msg.keys():
        raise ReportError("That doesn't look like an email message (.eml)")
    return {"headers": headers, "subject": str(msg.get("Subject", ""))[:300],
            "from": str(msg.get("From", ""))[:300], "urls": _urls(msg)}


def triage(parsed: dict, check_url=url_check.check) -> dict:
    """Header analysis + link checks -> {verdict, score, header, links}."""
    try:
        header = header_analyzer.analyze(parsed["headers"])
    except ValueError:
        header = {"level": "warn", "findings": []}
    # One check per registered domain keeps it fast; the first URL stands for its domain.
    links, domains = [], set()
    for u in parsed["urls"]:
        try:
            dom = url_check.parse(u)["registered"]
        except Exception:
            continue
        if dom in domains:
            continue
        domains.add(dom)
        try:
            links.append(check_url(u))
        except Exception as exc:
            links.append({"url": u, "domain": dom, "verdict": "unknown", "risk": 0, "error": str(exc)[:200]})
        if len(links) >= MAX_URLS:
            break
    score = max([link.get("risk", 0) for link in links] or [0])
    level = header.get("level")
    score = min(100, score + (40 if level == "fail" else 10 if level == "warn" else 0))
    if any(link.get("verdict") == "dangerous" for link in links):
        verdict = "dangerous"
    elif score >= 50:
        verdict = "likely phishing"
    elif score >= 20:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return {"verdict": verdict, "score": score, "header": header,
            "links": [{k: link.get(k) for k in ("url", "domain", "verdict", "risk", "signals", "feeds", "error")}
                      for link in links]}


# ------------------------------------------------------------------ takedowns
def _rdap(url: str) -> dict | None:
    try:
        r = httpx.get(url, timeout=8, follow_redirects=True, headers={"accept": "application/rdap+json"})
        return r.json() if r.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        return None


def _emails(entity: dict) -> list[str]:
    out = []
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
            out.append(str(item[3]).lower())
    return out


def abuse_contacts(data: dict | None) -> tuple[str | None, list[str]]:
    """(name, abuse emails) from an RDAP domain or IP response."""
    if not data:
        return None, []
    name, emails = None, []

    def walk(entities):
        nonlocal name
        for e in entities or []:
            roles = e.get("roles") or []
            if "registrar" in roles and not name:
                for item in (e.get("vcardArray") or [None, []])[1]:
                    if isinstance(item, list) and item and item[0] == "fn":
                        name = name or str(item[3])
            if "abuse" in roles:
                emails.extend(_emails(e))
            walk(e.get("entities"))
    walk(data.get("entities"))
    return name or data.get("name"), sorted(dict.fromkeys(emails))


def takedown(domain: str, url: str | None, evidence: list[str], brand: str,
             rdap=_rdap, resolve=None) -> dict:
    """Abuse report drafts for the domain's registrar and hosting network."""
    domain = domain.lower().strip(".")
    registered = split_domain(domain)[0] if "." in domain else domain
    reg_name, reg_abuse = abuse_contacts(rdap(f"https://rdap.org/domain/{registered}"))
    ip = None
    try:
        answers = (resolve or (lambda n: dns.resolver.resolve(n, "A", lifetime=4)))(domain)
        ip = str(answers[0])
        ipaddress.ip_address(ip)
    except Exception:
        ip = None
    host_name, host_abuse = abuse_contacts(rdap(f"https://rdap.org/ip/{ip}")) if ip else (None, [])
    lines = [
        "Hello,",
        "",
        f"We are reporting a phishing site impersonating {brand}.",
        "",
        f"Domain: {domain}",
        *([f"URL: {url}"] if url else []),
        *([f"IP address: {ip}"] if ip else []),
        "",
        "Evidence:",
        *[f"- {e}" for e in evidence[:10]],
        "",
        f"This domain is not operated by or affiliated with {brand}. Please suspend the domain / "
        "take down the content under your acceptable use policy.",
        "",
        "Thank you.",
    ]
    return {
        "domain": domain, "ip": ip,
        "registrar": {"name": reg_name, "abuse": reg_abuse},
        "hosting": {"name": host_name, "abuse": host_abuse},
        "to": sorted(dict.fromkeys(reg_abuse + host_abuse)),
        "subject": f"Phishing report: {domain} impersonating {brand}",
        "body": "\n".join(lines),
        "also": ["Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/",
                 "Microsoft: https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site",
                 "APWG: reportphishing@apwg.org"],
    }
