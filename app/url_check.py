"""Phishing URL checker: is this link likely a phishing page?

Nothing here opens the URL. The verdict combines
- the free domain blocklists the scanner already uses (Spamhaus DBL, SURBL,
  URIBL), queried over DNS,
- the domain's age from RDAP (the registries' public WHOIS replacement),
- what the URL itself looks like (IP hosts, punycode, brand names on the wrong
  domain, login words, shorteners, ...),
- optional feeds, each off until configured: Google Safe Browsing
  (SAFE_BROWSING_API_KEY), URLhaus (URLHAUS_AUTH_KEY), the OpenPhish community
  feed (OPENPHISH_FEED=true) and VirusTotal (VIRUSTOTAL_API_KEY).
"""
import ipaddress
import logging
import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

import dns.resolver
import httpx
import idna

from .config import settings
from .scanner import dns_checks, reputation
from .scanner.lookalike import split_domain

log = logging.getLogger("phishlens.url_check")
TIMEOUT = 6.0

BRANDS = ("paypal", "microsoft", "office365", "outlook", "onedrive", "sharepoint", "apple", "icloud",
          "amazon", "google", "gmail", "facebook", "instagram", "whatsapp", "netflix", "linkedin",
          "dropbox", "docusign", "adobe", "chase", "wellsfargo", "bankofamerica", "hsbc", "barclays",
          "coinbase", "binance", "metamask", "dhl", "fedex", "ups", "usps", "royalmail", "irs", "hmrc")
LURE_WORDS = ("login", "signin", "sign-in", "verify", "verification", "account", "secure", "update",
              "password", "wallet", "invoice", "unlock", "suspended", "confirm", "billing", "auth")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
              "rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id"}
# TLDs that cheap bulk registration makes common in phishing reports.
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
              "support", "rest", "cam", "icu", "buzz", "sbs", "cfd", "lol", "quest"}
FREE_HOSTS = {"github.io", "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "netlify.app",
              "vercel.app", "glitch.me", "weebly.com", "wixsite.com", "000webhostapp.com",
              "blogspot.com", "sites.google.com", "ngrok.io", "ngrok-free.app", "repl.co"}

_cache: dict[str, tuple[float, object]] = {}
_lock = threading.Lock()


class UrlError(ValueError):
    pass


def _cached(key: str, ttl: float, fn):
    now = time.time()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    value = fn()
    with _lock:
        _cache[key] = (now, value)
    return value


def parse(raw: str) -> dict:
    raw = raw.strip()
    if "://" not in raw:
        if re.match(r"^[a-z][a-z0-9+.-]*:(?!\d)", raw, re.I):  # javascript:, data:, mailto: ...
            raise UrlError("Only http and https links can be checked")
        raw = "http://" + raw
    parts = urlsplit(raw)
    if parts.scheme.lower() not in ("http", "https"):
        raise UrlError("Only http and https links can be checked")
    try:
        port = parts.port
    except ValueError:
        raise UrlError("The link has an invalid port")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UrlError("That doesn't look like a link")
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = idna.encode(host, uts46=True).decode()
        except idna.IDNAError:
            raise UrlError("The host name isn't valid")
    name, suffix = split_domain(host) if not ip else (host, "")
    return {"url": raw, "scheme": parts.scheme.lower(), "host": host, "ip": ip,
            "registered": f"{name}.{suffix}" if suffix else host,
            "port": port, "path": unquote(parts.path or "/") + (("?" + unquote(parts.query)) if parts.query else ""),
            "userinfo": "@" in (parts.netloc or "")}


# ------------------------------------------------------------------ signals
def _words(text: str) -> set[str]:
    return {w for w in re.split(r"[^a-z0-9]+", text.lower()) if w}


def _has(words: set[str], term: str) -> bool:
    """Whole-word match, or a prefix/suffix of a longer word for terms of 5+
    letters (so "paypal-login" and "microsoftonline" match but "groups"
    doesn't match "ups")."""
    term = term.replace("-", "")
    return any(w == term or (len(term) >= 5 and (w.startswith(term) or w.endswith(term))) for w in words)


def url_signals(u: dict) -> list[dict]:
    """Things about the link itself that phishing pages tend to have."""
    out = []

    def add(points, text):
        out.append({"points": points, "text": text})

    host, reg, path = u["host"], u["registered"], u["path"].lower()
    if u["ip"]:
        add(25, "The link points at a raw IP address instead of a domain name.")
    if u["userinfo"]:
        add(25, "The link contains '@', which hides the real destination after it.")
    if any(label.startswith("xn--") for label in host.split(".")):
        add(20, "The domain uses look-alike international characters (punycode).")
    reg_name = reg.split(".")[0]
    host_words, path_words = _words(host[: -len(reg)] if host != reg else ""), _words(path)
    elsewhere = [b for b in BRANDS if _has(host_words | path_words, b) and b not in reg_name]
    # A brand plus a hyphen or an account word ("paypal-help", "appleidverify") is
    # a classic fake; brands' own longer domains (microsoftonline) have neither.
    in_reg = [b for b in BRANDS if b in reg_name and reg_name != b and _has(_words(reg_name), b)
              and ("-" in reg_name or any(w in reg_name for w in LURE_WORDS))]
    if elsewhere:
        add(30, f"It mentions {elsewhere[0]} but the site is {reg}, not the brand's own domain.")
    elif in_reg:
        add(15, f"The domain {reg} contains the brand name {in_reg[0]} with extra words.")
    lures = [w for w in LURE_WORDS if _has(_words(host) | path_words, w)]
    if lures:
        add(8, f"It uses account words often seen in phishing: {', '.join(lures[:3])}.")
        if elsewhere or in_reg:
            add(10, "It pairs a brand name with an account word, the usual shape of a credential-phishing link.")
    if reg in SHORTENERS:
        add(10, "It's a link shortener, which hides the real destination.")
    if any(host == h or host.endswith("." + h) for h in FREE_HOSTS):
        add(10, "It's hosted on a free site builder or tunnel, which phishing kits often use.")
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        add(8, f"The .{tld} ending is common in phishing reports.")
    if len(host.split(".")) - len(reg.split(".")) >= 3:
        add(10, "The domain has an unusually deep chain of subdomains.")
    if reg_name.count("-") >= 2:
        add(5, "The domain name has several hyphens.")
    if len(u["url"]) > 120:
        add(5, "The link is very long.")
    if u["port"] and u["port"] not in (80, 443):
        add(10, f"The link uses an unusual port ({u['port']}).")
    if u["scheme"] == "http":
        add(5, "The page isn't served over HTTPS.")
    return out


def domain_age_days(domain: str) -> int | None:
    """Days since registration from RDAP, or None when the registry doesn't say."""
    def fetch():
        try:
            r = httpx.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT, follow_redirects=True,
                          headers={"accept": "application/rdap+json"})
            if r.status_code != 200:
                return None
            for ev in r.json().get("events") or []:
                if ev.get("eventAction") == "registration":
                    when = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                    return (datetime.now(timezone.utc) - when).days
        except Exception as exc:
            log.info("rdap lookup for %s failed: %s", domain, type(exc).__name__)
        return None
    return _cached(f"rdap:{domain}", 86400, fetch)


def resolves(host: str) -> bool:
    try:
        dns.resolver.resolve(host, "A", lifetime=4)
        return True
    except dns.resolver.NoAnswer:
        return True
    except Exception:
        try:
            dns.resolver.resolve(host, "AAAA", lifetime=4)
            return True
        except Exception:
            return False


def blocklists(domain: str) -> list[str]:
    return [bl for bl in dns_checks.DOMAIN_BLS if dns_checks._dnsbl_listed(f"{domain}.{bl}", True)]


# ------------------------------------------------------------------ optional feeds
def safe_browsing(url: str) -> bool | None:
    if not settings.SAFE_BROWSING_API_KEY:
        return None
    body = {"client": {"clientId": "phishlens", "clientVersion": "1"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": url}]}}
    try:
        r = httpx.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                       params={"key": settings.SAFE_BROWSING_API_KEY}, json=body, timeout=TIMEOUT)
        return bool(r.json().get("matches")) if r.status_code == 200 else None
    except Exception:
        return None


def urlhaus(url: str) -> bool | None:
    if not settings.URLHAUS_AUTH_KEY:
        return None
    try:
        r = httpx.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=TIMEOUT,
                       headers={"Auth-Key": settings.URLHAUS_AUTH_KEY})
        return r.json().get("query_status") == "ok" if r.status_code == 200 else None
    except Exception:
        return None


def _openphish_set() -> set[str]:
    def fetch():
        try:
            r = httpx.get("https://openphish.com/feed.txt", timeout=15)
            if r.status_code == 200:
                return {line.strip().rstrip("/") for line in r.text.splitlines() if line.strip()}
        except Exception:
            pass
        return set()
    return _cached("openphish", 3600, fetch)


def openphish(url: str) -> bool | None:
    if not settings.OPENPHISH_FEED:
        return None
    feed = _openphish_set()
    return url.rstrip("/") in feed if feed else None


# ------------------------------------------------------------------ verdict
def check(raw: str) -> dict:
    u = parse(raw)
    signals = url_signals(u)
    feeds = []

    def feed(name, hit):
        if hit is not None:
            feeds.append({"source": name, "listed": bool(hit)})

    if not u["ip"]:
        listed = blocklists(u["registered"])
        feeds.append({"source": "Spamhaus DBL, SURBL, URIBL", "listed": bool(listed), "lists": listed})
        if not resolves(u["host"]):
            signals.append({"points": 0, "text": "The host doesn't resolve in DNS: the site is down or was taken offline."})
        if settings.URL_CHECK_RDAP:
            age = domain_age_days(u["registered"])
            if age is not None:
                if age < 30:
                    signals.append({"points": 25, "text": f"{u['registered']} was registered {age} days ago."})
                elif age < 180:
                    signals.append({"points": 10, "text": f"{u['registered']} is under six months old ({age} days)."})
                else:
                    signals.append({"points": -10, "text": f"{u['registered']} has been registered for {age // 365 or 1}+ years."})
        vt = reputation.lookup(u["registered"])
        if vt:
            feeds.append({"source": "VirusTotal", "listed": vt["verdict"] == "malicious",
                          "detail": f"{vt['malicious']}/{vt['total']} vendors flag it", "url": vt.get("url")})
    feed("Google Safe Browsing", safe_browsing(u["url"]))
    feed("URLhaus", urlhaus(u["url"]))
    feed("OpenPhish", openphish(u["url"]))

    score = max(0, min(100, sum(s["points"] for s in signals)))
    if any(f["listed"] for f in feeds):
        verdict, score = "dangerous", 100
    elif score >= 50:
        verdict = "likely phishing"
    elif score >= 20:
        verdict = "suspicious"
    else:
        verdict = "no known threat"
    return {"url": u["url"], "host": u["host"], "domain": u["registered"], "verdict": verdict,
            "risk": score, "signals": sorted(signals, key=lambda s: -s["points"]), "feeds": feeds,
            "note": "PhishLens doesn't open the link. A clean result isn't a guarantee: new phishing "
                    "pages appear before any list catches them."}
