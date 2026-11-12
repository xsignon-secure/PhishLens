"""Exposure checks: dangling DNS (subdomain takeover) and post-quantum TLS.

Dangling DNS
------------
A record that points at something which no longer exists can be claimed by
anyone: a CNAME to a deleted S3 bucket, GitHub Pages site or Heroku app, an
MX host or nameserver on a domain that has expired. Whoever claims it serves
pages, receives mail, or answers DNS for the victim's own (sub)domain, which
is ideal for phishing. The check looks at common subdomain names plus any
names the caller already knows (for example from Certificate Transparency),
the MX hosts and the nameservers.

Post-quantum readiness
----------------------
"Harvest now, decrypt later": TLS sessions recorded today can be decrypted
once quantum computers break classical key exchange. Browsers and large CDNs
already negotiate hybrid X25519MLKEM768. The check reports whether the web
server accepts it, using OpenSSL 3.5+ through the standard ssl module when
available. It is informational and doesn't change the grade.
"""
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

from ..config import settings
from . import dns_checks, net

TIMEOUT = dns_checks.TIMEOUT

COMMON_SUBDOMAINS = (
    "www", "mail", "webmail", "blog", "shop", "store", "docs", "help", "support",
    "status", "cdn", "static", "assets", "img", "images", "media", "app", "portal",
    "dev", "staging", "test", "beta", "api", "news", "events", "careers", "jobs",
    "go", "info", "landing", "promo", "community", "forum", "kb", "email", "click",
    "links", "track", "autodiscover", "files", "download", "marketing", "pages",
)
MAX_NAMES = 80

# Services where a dangling record can be claimed by someone else.
# (label, hostname suffixes, HTTP body fingerprint or None when NXDOMAIN is the signal)
SERVICES = (
    ("AWS S3", (".s3.amazonaws.com", ".s3-website", "s3.amazonaws.com"), "NoSuchBucket"),
    ("AWS Elastic Beanstalk", (".elasticbeanstalk.com",), None),
    ("Azure", (".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net",
               ".blob.core.windows.net", ".azureedge.net", ".azurefd.net", ".azurecontainer.io",
               ".azure-api.net", ".azurestaticapps.net"), None),
    ("GitHub Pages", (".github.io",), "There isn't a GitHub Pages site here"),
    ("Heroku", (".herokuapp.com", ".herokudns.com", ".herokussl.com"), "no-such-app"),
    ("Shopify", (".myshopify.com",), "Sorry, this shop is currently unavailable"),
    ("Fastly", (".fastly.net",), "Fastly error: unknown domain"),
    ("Pantheon", (".pantheonsite.io",), "The gods are wise"),
    ("Surge", (".surge.sh",), "project not found"),
    ("Tumblr", ("domains.tumblr.com",), "Whatever you were looking for doesn't currently exist at this address"),
    ("Ghost", (".ghost.io",), "Domain error"),
    ("Help Scout", (".helpscoutdocs.com",), "No settings were found for this company"),
    ("ReadMe", (".readme.io",), "Project doesnt exist"),
    ("Zendesk", (".zendesk.com",), "Help Center Closed"),
    ("Bitbucket", (".bitbucket.io",), "Repository not found"),
    ("Netlify", (".netlify.app", ".netlify.com"), "Not Found - Request ID"),
    ("Unbounce", (".unbouncepages.com",), "The requested URL was not found on this server"),
    ("Webflow", ("proxy.webflow.com", "proxy-ssl.webflow.com"), "The page you are looking for doesn't exist or has been moved"),
    ("Strikingly", (".strikinglydns.com",), "page not found"),
    ("Agile CRM", (".agilecrm.com",), "Sorry, this page is no longer available"),
    ("Cargo", (".cargocollective.com",), "404 Not Found"),
)


def _service(target: str):
    t = target.lower().rstrip(".")
    for label, suffixes, fp in SERVICES:
        if any(t.endswith(s) or t == s.lstrip(".") for s in suffixes):
            return label, fp
    return None, None


def _state(name: str) -> str:
    """'nx' (the name doesn't exist), 'ok' (it exists), or 'error'."""
    for rtype in ("A", "AAAA"):
        try:
            dns_checks._resolver.resolve(name, rtype, lifetime=TIMEOUT)
            return "ok"
        except dns.resolver.NXDOMAIN:
            return "nx"
        except dns.resolver.NoAnswer:
            continue
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            return "error"
        except Exception:
            return "error"
    return "ok"  # the name exists, it just has no address records


def _cname_chain(name: str, depth: int = 5) -> list[str]:
    chain, cur = [], name
    for _ in range(depth):
        try:
            ans = dns_checks._resolver.resolve(cur, "CNAME", lifetime=TIMEOUT)
        except Exception:
            break
        rec = list(ans)[0]
        target = str(getattr(rec, "target", rec)).rstrip(".").lower()
        if not target or target in chain:
            break
        chain.append(target)
        cur = target
    return chain


def _registrable(host: str) -> str:
    """Registered domain of a host. Two labels, or three under a two-letter
    second level such as co.uk; good enough to tell 'host gone' from
    'whole domain unregistered'."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in ("co", "com", "net", "org", "ac", "gov", "edu", "ne", "or"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _domain_unregistered(host: str) -> bool:
    reg = _registrable(host)
    try:
        dns_checks._resolver.resolve(reg, "NS", lifetime=TIMEOUT)
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


def _body_matches(name: str, fingerprint: str) -> bool:
    for scheme in ("https", "http"):
        try:
            _, head = net.safe_fetch_head(f"{scheme}://{name}", timeout=6, limit=32768)
        except Exception:
            continue
        return fingerprint.lower() in head.decode("utf-8", errors="replace").lower()
    return False


def _inspect_name(name: str) -> dict | None:
    chain = _cname_chain(name)
    if not chain:
        return None
    target = chain[-1]
    service, fp = _service(target)
    if not service:
        for hop in chain:
            service, fp = _service(hop)
            if service:
                break
    state = _state(target)
    if state == "nx":
        unregistered = _domain_unregistered(target)
        if service or unregistered:
            why = (f"{target} is on a domain nobody has registered" if unregistered
                   else f"the {service} resource it names no longer exists")
            return {"name": name, "target": target, "service": service, "severity": "high",
                    "issue": f"{name} points to {target}, but {why}: anyone who claims it controls {name}."}
        return {"name": name, "target": target, "service": None, "severity": "low",
                "issue": f"{name} points to {target}, which doesn't exist."}
    if state == "ok" and fp and _body_matches(name, fp):
        return {"name": name, "target": target, "service": service, "severity": "high",
                "issue": f"{name} points to an unclaimed {service} resource ({target}): anyone can claim it and serve pages on {name}."}
    return None


def _host_records(domain: str, rtype: str) -> list[str]:
    try:
        ans = dns_checks._resolver.resolve(domain, rtype, lifetime=TIMEOUT)
    except Exception:
        return []
    out = []
    for r in ans:
        host = getattr(r, "exchange", None) or getattr(r, "target", None) or r
        out.append(str(host).rstrip(".").lower())
    return [h for h in out if h]


def check_dangling(domain: str, extra_names: list[str] | None = None) -> dict:
    # Informational like the mail_checks: the 0-100 grade keeps its weights,
    # but a takeover risk still fails (High in Top risks, and a monitor alert).
    max_score = 0
    domain = domain.lower().rstrip(".")
    names = [domain] + [f"{s}.{domain}" for s in COMMON_SUBDOMAINS]
    for n in extra_names or []:
        n = n.lower().lstrip("*.").rstrip(".")
        if n.endswith("." + domain) and n not in names:
            names.append(n)
    names = names[:MAX_NAMES]
    with ThreadPoolExecutor(max_workers=16) as pool:
        found = [f for f in pool.map(_inspect_name, names) if f]

    # MX hosts and nameservers on expired domains can be registered by anyone.
    for kind, rtype in (("MX host", "MX"), ("nameserver", "NS")):
        for host in _host_records(domain, rtype):
            if host.endswith("." + domain) or host == domain:
                continue
            if _state(host) == "nx":
                if _domain_unregistered(host):
                    found.append({"name": domain, "target": host, "service": None, "severity": "high",
                                  "issue": f"The {kind} {host} is on a domain nobody has registered: "
                                           f"whoever registers {_registrable(host)} can "
                                           + ("receive this domain's mail." if rtype == "MX" else "answer DNS for this domain.")})
                else:
                    found.append({"name": domain, "target": host, "service": None, "severity": "low",
                                  "issue": f"The {kind} {host} doesn't exist."})

    high = [f for f in found if f["severity"] == "high"]
    low = [f for f in found if f["severity"] == "low"]
    checked = f"Checked {len(names)} names, the MX hosts and the nameservers. Not counted in the score."
    if not found:
        return {"key": "dangling", "title": "Dangling DNS", "status": "pass", "score": max_score,
                "max_score": max_score, "details": f"No records point at missing resources. {checked}",
                "issues": [], "fixes": [], "findings": []}
    fixes = []
    for f in high + low:
        if f["target"] and f["name"] != domain:
            fixes.append(f"Delete the CNAME record for {f['name']} (it points to {f['target']}), "
                         f"or re-create the resource at {f['target']} first.")
        else:
            fixes.append(f"Remove {f['target']} from this domain's DNS, or renew {_registrable(f['target'])} "
                         "if it's still yours.")
    status, score = ("fail", 0) if high else ("warn", 0)
    return {"key": "dangling", "title": "Dangling DNS", "status": status, "score": score,
            "max_score": max_score,
            "details": f"{len(high)} takeover risk(s), {len(low)} broken record(s). {checked}",
            "issues": [f["issue"] for f in high + low], "fixes": fixes,
            "findings": [{k: f[k] for k in ("name", "target", "service", "severity")} for f in high + low]}


# ------------------------------------------------------------------ PQC
PQC_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")


def _set_groups(ctx: ssl.SSLContext, groups: str) -> bool:
    setter = getattr(ctx, "set_groups", None)  # Python 3.15+
    if setter is None:
        return False
    try:
        setter(groups)
        return True
    except Exception:
        return False


def _pqc_handshake(host: str, port: int = 443) -> str | None:
    """'pqc' if a hybrid ML-KEM group was negotiated, 'classic' if only classic
    groups work, None when this server's OpenSSL can't test it."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if not _set_groups(ctx, ":".join(PQC_GROUPS)):
        return None
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                # Only hybrid groups were offered, so a completed handshake
                # means one was chosen; group() (Python 3.15+) confirms it.
                group = getattr(s, "group", lambda: None)() or "MLKEM"
                return "pqc" if "MLKEM" in group.upper() else "classic"
    except ssl.SSLError:
        return "classic"
    except OSError:
        raise


def check_pqc(domain: str) -> dict:
    title = "Post-quantum readiness"
    info = " Not counted in the score."
    if not settings.PQC_CHECK:
        return {"key": "pqc", "title": title, "status": "pass", "score": 0, "max_score": 0,
                "details": "Not checked (turned off on this server)." + info, "issues": [], "fixes": []}
    if not net.is_public_host(domain):
        return {"key": "pqc", "title": title, "status": "warn", "score": 0, "max_score": 0,
                "details": "Website not reachable." + info, "issues": [], "fixes": []}
    try:
        res = _pqc_handshake(domain)
    except OSError as e:
        return {"key": "pqc", "title": title, "status": "warn", "score": 0, "max_score": 0,
                "details": f"Website not reachable over HTTPS ({type(e).__name__})." + info,
                "issues": [], "fixes": []}
    if res is None:
        return {"key": "pqc", "title": title, "status": "pass", "score": 0, "max_score": 0,
                "details": "Not checked: this server's TLS library can't offer post-quantum key exchange." + info,
                "issues": [], "fixes": []}
    if res == "pqc":
        return {"key": "pqc", "title": title, "status": "pass", "score": 0, "max_score": 0,
                "details": "The website accepts hybrid post-quantum key exchange (ML-KEM)." + info,
                "issues": [], "fixes": [], "pqc": True}
    return {"key": "pqc", "title": title, "status": "warn", "score": 0, "max_score": 0,
            "details": "The website only accepts classic key exchange." + info,
            "issues": ["HTTPS traffic recorded today could be decrypted once quantum computers can break classic key exchange."],
            "fixes": ["Turn on hybrid post-quantum key exchange (X25519MLKEM768): it's on by default in OpenSSL 3.5+, "
                      "recent nginx/Apache builds linked against it, and at CDNs such as Cloudflare."],
            "pqc": False}
