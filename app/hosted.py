"""Hosted DMARC, SPF, MTA-STS, TLS-RPT and BIMI.

The customer delegates once:
    _dmarc.example.com     CNAME  example.com.<tag>._dmarc.<HOSTED_ZONE>
    example.com            TXT    "v=spf1 include:example.com.<tag>._spf.<HOSTED_ZONE> -all"
    _mta-sts.example.com   CNAME  example.com.<tag>._mta-sts.<HOSTED_ZONE>
    mta-sts.example.com    CNAME  <MTA_STS_TARGET>
    _smtp._tls.example.com CNAME  example.com.<tag>._smtp._tls.<HOSTED_ZONE>
    default._bimi.example.com CNAME example.com.<tag>._bimi.<HOSTED_ZONE>
and from then on every policy change (p=none -> reject, a new email
provider, MTA-STS testing -> enforce) is a click in PhishLens instead of a
DNS ticket. Hosted SPF is flattened to IP addresses, which keeps the domain
under SPF's 10-lookup limit however many services it uses; scheduled rescans
re-flatten it as providers change their IPs.

<tag> is per hosted record, so two accounts can never write each other's
records even if both configure the same domain.
"""
import hashlib
import ipaddress
import re
import secrets
from datetime import datetime

import dns.resolver
import httpx

from . import bimi, dns_providers, models
from .config import settings

KINDS = ("dmarc", "spf", "mta_sts", "tls_rpt", "bimi")
_EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")
SPF_CHUNK = 420           # characters per hosted SPF record (well under the 512-byte UDP answer)
SPF_LOOKUP_BUDGET = 40    # DNS queries spent flattening one domain
_SPF_TERM = re.compile(r"^(?:[+~?-]?)(include:[a-z0-9._-]+|ip4:[0-9./]+|ip6:[0-9a-f:./]+|a|mx|"
                       r"a:[a-z0-9._-]+|mx:[a-z0-9._-]+)$", re.I)


class HostedError(Exception):
    pass


def configured() -> bool:
    return bool(settings.HOSTED_ZONE and settings.HOSTED_CLOUDFLARE_TOKEN
                and settings.HOSTED_CLOUDFLARE_ZONE_ID)


def provider(transport=None) -> dns_providers.Cloudflare:
    return dns_providers.Cloudflare(settings.HOSTED_CLOUDFLARE_TOKEN, transport=transport)


def mta_sts_target() -> str:
    if settings.MTA_STS_TARGET:
        return settings.MTA_STS_TARGET.rstrip(".")
    return httpx.URL(settings.APP_URL).host


def _tag(rec: models.HostedRecord) -> str:
    return hashlib.sha256(f"{rec.tenant_id}:{rec.domain}".encode()).hexdigest()[:8]


def hosted_name(rec: models.HostedRecord) -> str:
    label = {"dmarc": "_dmarc", "spf": "_spf", "mta_sts": "_mta-sts",
             "tls_rpt": "_smtp._tls", "bimi": "_bimi"}[rec.kind]
    return f"{rec.domain}.{_tag(rec)}.{label}.{settings.HOSTED_ZONE}"


# ------------------------------------------------------------------ config validation
def clean_config(kind: str, cfg: dict, domain: str) -> dict:
    if kind == "dmarc":
        p = cfg.get("p", "none")
        if p not in ("none", "quarantine", "reject"):
            raise HostedError("p must be none, quarantine or reject")
        sp = cfg.get("sp") or None
        if sp not in (None, "none", "quarantine", "reject"):
            raise HostedError("sp must be none, quarantine or reject")
        np_ = cfg.get("np") or None
        if np_ not in (None, "none", "quarantine", "reject"):
            raise HostedError("np must be none, quarantine or reject")
        # RFC 9989 replaced pct with t=y (testing); an old pct below 100 maps to it.
        testing = bool(cfg.get("t"))
        if "pct" in cfg:
            try:
                testing = testing or int(cfg["pct"]) < 100
            except (TypeError, ValueError):
                raise HostedError("pct must be a number")
        rua = [a.strip().lower().removeprefix("mailto:") for a in (cfg.get("rua") or []) if a.strip()]
        if not rua and settings.HOSTED_DMARC_RUA:
            rua = [settings.HOSTED_DMARC_RUA.lower().removeprefix("mailto:")]
        for a in rua:
            if not _EMAIL.fullmatch(a):
                raise HostedError(f"Invalid report address: {a}")
        align = {k: cfg.get(k, "r") for k in ("adkim", "aspf")}
        if any(v not in ("r", "s") for v in align.values()):
            raise HostedError("adkim/aspf must be r or s")
        return {"p": p, "sp": sp, "np": np_, "t": testing, "rua": rua[:3], **align}
    if kind == "spf":
        sources = [s.strip() for s in (cfg.get("sources") or []) if s.strip()]
        if not sources:
            raise HostedError("Add at least one sender, e.g. include:_spf.google.com")
        for s in sources:
            if not _SPF_TERM.match(s):
                raise HostedError(f"Not a supported SPF term: {s}")
            if s.lower().startswith(("ip4:", "ip6:")):
                try:
                    ipaddress.ip_network(s.split(":", 1)[1], strict=False)
                except ValueError:
                    raise HostedError(f"Invalid IP range: {s}")
        all_ = cfg.get("all", "-all")
        if all_ not in ("-all", "~all"):
            raise HostedError("all must be -all or ~all")
        return {"sources": sources[:30], "all": all_}
    if kind == "mta_sts":
        mode = cfg.get("mode", "testing")
        if mode not in ("testing", "enforce", "none"):
            raise HostedError("mode must be testing, enforce or none")
        mx = [m.strip().lower().rstrip(".") for m in (cfg.get("mx") or []) if m.strip()]
        if not mx:
            raise HostedError("List your MX hosts (e.g. *.mail.protection.outlook.com)")
        for m in mx:
            if not re.fullmatch(r"(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+", m):
                raise HostedError(f"Invalid MX pattern: {m}")
        try:
            max_age = int(cfg.get("max_age", 604800))
        except (TypeError, ValueError):
            raise HostedError("max_age must be a number")
        return {"mode": mode, "mx": mx[:10], "max_age": max(86400, min(max_age, 31557600))}
    if kind == "tls_rpt":
        rua = []
        for a in (cfg.get("rua") or []):
            a = a.strip()
            if not a:
                continue
            if a.lower().startswith("https://"):
                if not re.fullmatch(r"https://[a-z0-9.-]+(:\d+)?(/[\w./%~+-]*)?", a, re.I):
                    raise HostedError(f"Invalid report URL: {a}")
                rua.append(a)
                continue
            a = a.lower().removeprefix("mailto:")
            if not _EMAIL.fullmatch(a):
                raise HostedError(f"Invalid report address: {a}")
            rua.append("mailto:" + a)
        default = settings.HOSTED_TLSRPT_RUA or settings.HOSTED_DMARC_RUA
        if not rua and default:
            rua = ["mailto:" + default.lower().removeprefix("mailto:")]
        if not rua:
            raise HostedError("Add a report address (an email address or https:// URL)")
        return {"rua": rua[:3]}
    if kind == "bimi":
        svg = (cfg.get("svg") or "").strip()
        if not svg:
            raise HostedError("Upload your logo as an SVG file")
        result = bimi.check_svg(svg)
        if not result["ok"]:
            raise HostedError("The logo isn't valid SVG Tiny PS: " + " ".join(result["errors"]))
        if not settings.APP_URL.startswith("https://"):
            raise HostedError("Hosted BIMI needs PhishLens served over HTTPS")
        cert = (cfg.get("certificate_url") or "").strip()
        if cert and not re.fullmatch(r"https://[a-z0-9.-]+(:\d+)?/[\w./%~+-]*", cert, re.I):
            raise HostedError("The certificate (VMC/CMC) URL must be an https:// link to a .pem file")
        return {"svg": svg, "certificate_url": cert or None}
    raise HostedError("Unknown record kind")


# ------------------------------------------------------------------ values
def dmarc_value(cfg: dict) -> str:
    parts = ["v=DMARC1", f"p={cfg['p']}"]
    if cfg.get("sp"):
        parts.append(f"sp={cfg['sp']}")
    if cfg.get("np"):
        parts.append(f"np={cfg['np']}")
    if cfg.get("t") or cfg.get("pct", 100) != 100:  # pct: configs saved before RFC 9989
        parts.append("t=y")
    if cfg.get("rua"):
        parts.append("rua=" + ",".join(f"mailto:{a}" for a in cfg["rua"]))
    if cfg.get("adkim") == "s":
        parts.append("adkim=s")
    if cfg.get("aspf") == "s":
        parts.append("aspf=s")
    return "; ".join(parts)


def tls_rpt_value(cfg: dict) -> str:
    return "v=TLSRPTv1; rua=" + ",".join(cfg["rua"])


def bimi_logo_url(rec: models.HostedRecord) -> str:
    # The policy id changes with each new logo, so inboxes refetch it.
    return f"{settings.APP_URL.rstrip('/')}/bimi/{rec.id}/{rec.policy_id or 'logo'}.svg"


def bimi_value(rec: models.HostedRecord) -> str:
    return f"v=BIMI1; l={bimi_logo_url(rec)}; a={rec.config.get('certificate_url') or ''}"


def _resolve(name: str, rtype: str, resolver) -> list:
    try:
        return list(resolver.resolve(name, rtype, lifetime=5))
    except Exception:
        return []


def flatten_spf(sources: list[str], domain: str, resolver=None) -> list[str]:
    """Expand include/a/mx terms into ip4/ip6 terms. Terms that can't be
    expanded (unresolvable include, lookup budget spent) are kept as-is."""
    from .scanner.dns_checks import _resolver as default_resolver

    resolver = resolver or default_resolver
    budget = [SPF_LOOKUP_BUDGET]
    out: list[str] = []

    def addrs(host: str) -> list[str]:
        ips = []
        for rtype, pre in (("A", "ip4:"), ("AAAA", "ip6:")):
            if budget[0] <= 0:
                break
            budget[0] -= 1
            ips += [pre + r.to_text() for r in _resolve(host, rtype, resolver)]
        return ips

    def expand(term: str, depth: int, seen: set) -> list[str] | None:
        t = term.lstrip("+")
        low = t.lower()
        if low.startswith(("ip4:", "ip6:")):
            return [t]
        if budget[0] <= 0 or depth > 8:
            return None
        if low.startswith("include:"):
            target = t.split(":", 1)[1].rstrip(".").lower()
            if target in seen:
                return []
            seen.add(target)
            budget[0] -= 1
            txts = [b"".join(r.strings).decode("utf-8", "replace") for r in _resolve(target, "TXT", resolver)]
            spf = [x for x in txts if x.lower().startswith("v=spf1")]
            if len(spf) != 1:
                return None
            got: list[str] = []
            for sub in spf[0].split()[1:]:
                sl = sub.lower()
                if sl.endswith("all") or sl.startswith(("redirect=", "exp=", "-", "~", "?")):
                    continue  # only pass terms authorise mail
                r = expand(sub, depth + 1, seen)
                if r is None:
                    return None
                got += r
            return got
        if low == "a" or low.startswith("a:"):
            return addrs(t.split(":", 1)[1] if ":" in t else domain)
        if low == "mx" or low.startswith("mx:"):
            host = t.split(":", 1)[1] if ":" in t else domain
            budget[0] -= 1
            ips = []
            for r in _resolve(host, "MX", resolver)[:10]:
                ips += addrs(str(r.exchange).rstrip("."))
            return ips
        return None

    for term in sources:
        r = expand(term, 0, set())
        out += r if r is not None else [term]
    return list(dict.fromkeys(out))


def spf_records(rec: models.HostedRecord, terms: list[str]) -> dict[str, str]:
    """Split the flattened terms over a chain of hosted TXT records."""
    base = hosted_name(rec)
    chunks: list[list[str]] = [[]]
    for t in terms:
        if len(" ".join(["v=spf1", *chunks[-1], t])) + 40 > SPF_CHUNK:
            chunks.append([])
        chunks[-1].append(t)
    names = [base] + [f"{i}.{base}" for i in range(1, len(chunks))]
    out = {}
    for i, (name, chunk) in enumerate(zip(names, chunks)):
        parts = ["v=spf1", *chunk]
        if i + 1 < len(names):
            parts.append(f"include:{names[i + 1]}")
        out[name] = " ".join(parts)
    return out


def desired_records(rec: models.HostedRecord, resolver=None) -> dict[str, str]:
    """Every TXT record PhishLens must publish in its zone for `rec`."""
    if rec.kind == "dmarc":
        out = {hosted_name(rec): dmarc_value(rec.config)}
        # External reporting authorisation (RFC 9990) for rua mailboxes
        # inside the hosted zone: otherwise receivers drop the reports.
        for addr in rec.config.get("rua", []):
            host = addr.rsplit("@", 1)[1]
            if host == settings.HOSTED_ZONE or host.endswith("." + settings.HOSTED_ZONE):
                out[f"{rec.domain}._report._dmarc.{host}"] = "v=DMARC1"
        return out
    if rec.kind == "spf":
        return spf_records(rec, flatten_spf(rec.config["sources"], rec.domain, resolver))
    if rec.kind == "mta_sts":
        return {hosted_name(rec): f"v=STSv1; id={rec.policy_id}"}
    if rec.kind == "tls_rpt":
        return {hosted_name(rec): tls_rpt_value(rec.config)}
    if rec.kind == "bimi":
        return {hosted_name(rec): bimi_value(rec)}
    raise HostedError("Unknown record kind")


def customer_records(rec: models.HostedRecord) -> list[dict]:
    """The one-time delegation the customer publishes in their own DNS."""
    d = rec.domain
    if rec.kind == "dmarc":
        return [{"name": f"_dmarc.{d}", "type": "CNAME", "value": hosted_name(rec),
                 "note": "Delete any existing TXT record at this name first."}]
    if rec.kind == "spf":
        return [{"name": d, "type": "TXT",
                 "value": f"v=spf1 include:{hosted_name(rec)} {rec.config['all']}",
                 "note": "Replace your existing v=spf1 record (keep other TXT records)."}]
    if rec.kind in ("tls_rpt", "bimi"):
        name = f"_smtp._tls.{d}" if rec.kind == "tls_rpt" else f"default._bimi.{d}"
        return [{"name": name, "type": "CNAME", "value": hosted_name(rec),
                 "note": "Delete any existing TXT record at this name first."}]
    return [
        {"name": f"_mta-sts.{d}", "type": "CNAME", "value": hosted_name(rec),
         "note": "Delete any existing TXT record at this name first."},
        {"name": f"mta-sts.{d}", "type": "CNAME", "value": mta_sts_target(),
         "note": "PhishLens serves your policy file at https://mta-sts." + d + "/.well-known/mta-sts.txt"},
    ]


def mta_sts_policy(cfg: dict) -> str:
    lines = ["version: STSv1", f"mode: {cfg['mode']}"]
    lines += [f"mx: {m}" for m in cfg["mx"]]
    lines.append(f"max_age: {cfg['max_age']}")
    return "\r\n".join(lines) + "\r\n"


def new_policy_id() -> str:
    return datetime.utcnow().strftime("%Y%m%d%H%M%S") + secrets.token_hex(2)


# ------------------------------------------------------------------ publishing
def publish(rec: models.HostedRecord, cf: dns_providers.Cloudflare | None = None,
            resolver=None) -> dict:
    """Push rec's records to the hosted zone and remove ones no longer needed."""
    if not configured():
        raise HostedError("Hosted records aren't set up on this server")
    cf = cf or provider()
    zone = settings.HOSTED_CLOUDFLARE_ZONE_ID
    want = desired_records(rec, resolver)
    for name, value in want.items():
        cf.upsert(zone, name, "TXT", value, match_prefix=value.split()[0].rstrip(";"))
    for stale in set(rec.published or {}) - set(want):
        cf.delete(zone, stale, "TXT")
    rec.published = want
    rec.updated_at = datetime.utcnow()
    return want


def unpublish(rec: models.HostedRecord, cf: dns_providers.Cloudflare | None = None) -> None:
    if not configured():
        return
    cf = cf or provider()
    for name in rec.published or {}:
        cf.delete(settings.HOSTED_CLOUDFLARE_ZONE_ID, name, "TXT")
    rec.published = {}


def verify_delegation(rec: models.HostedRecord, resolver=None) -> list[dict]:
    """Has the customer published the delegation records yet?"""
    from .scanner.dns_checks import _resolver as default_resolver

    resolver = resolver or default_resolver
    out = []
    for want in customer_records(rec):
        if want["type"] == "CNAME":
            got = [str(r.target).rstrip(".").lower() for r in _resolve(want["name"], "CNAME", resolver)]
            ok = want["value"].lower() in got
        else:
            txts = [b"".join(r.strings).decode("utf-8", "replace") for r in _resolve(want["name"], "TXT", resolver)]
            ok = any(f"include:{hosted_name(rec)}".lower() in t.lower() for t in txts)
            got = [t for t in txts if t.lower().startswith("v=spf1")]
        out.append({**want, "ok": ok, "found": got[:3]})
    return out


def serving_record(db, domain: str, resolver=None) -> models.HostedRecord | None:
    """The MTA-STS record to serve for `domain`: the one the domain's
    _mta-sts CNAME actually delegates to, so only the real owner's policy is
    ever served."""
    recs = (db.query(models.HostedRecord)
            .filter(models.HostedRecord.domain == domain, models.HostedRecord.kind == "mta_sts").all())
    if len(recs) <= 1:
        return recs[0] if recs else None
    from .scanner.dns_checks import _resolver as default_resolver

    targets = {str(r.target).rstrip(".").lower()
               for r in _resolve(f"_mta-sts.{domain}", "CNAME", resolver or default_resolver)}
    return next((r for r in recs if hosted_name(r).lower() in targets), None)


def add_render_domain(host: str) -> bool:
    """Ask Render to serve (and issue a certificate for) mta-sts.<domain>."""
    if not (settings.RENDER_API_KEY and settings.RENDER_SERVICE_ID):
        return False
    try:
        r = httpx.post(f"https://api.render.com/v1/services/{settings.RENDER_SERVICE_ID}/custom-domains",
                       json={"name": host}, timeout=15,
                       headers={"Authorization": f"Bearer {settings.RENDER_API_KEY}"})
    except httpx.HTTPError:
        return False
    return r.status_code in (200, 201, 409)  # 409: already added
