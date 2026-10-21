"""Deterministic DNS-based email security checks. No AI, no external APIs.

Every check returns a dict:
    {key, title, status: pass|warn|fail, score, max_score, details, issues[], fixes[]}
`fixes` contains exact DNS records / actions the domain owner can apply.
"""
import base64
import smtplib
import socket

import dns.exception
import dns.resolver

from . import net

TIMEOUT = 6.0

_resolver = dns.resolver.Resolver(configure=True)
_resolver.lifetime = TIMEOUT
_resolver.timeout = TIMEOUT


class DnsLookupError(Exception):
    """The DNS query itself failed (timeout / no server answered). Distinct from
    "no such record": reporting it as a missing record would grade a domain F,
    and fire false drift alerts, whenever a nameserver is briefly slow."""


def _txt(name: str) -> list[str]:
    try:
        answers = _resolver.resolve(name, "TXT", lifetime=TIMEOUT)
        out = []
        for r in answers:
            out.append(b"".join(r.strings).decode("utf-8", errors="replace"))
        return out
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        raise DnsLookupError(f"DNS lookup for {name} failed: {type(exc).__name__}") from exc


def _parse_tag_list(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


# ------------------------------------------------------------------ SPF
SPF_LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists", "redirect")
SPF_LOOKUP_LIMIT = 10


def _spf_record(name: str) -> str | None:
    recs = [t for t in _txt(name) if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]
    return recs[0] if len(recs) == 1 else None


def _spf_terms(record: str) -> list[str]:
    return record.split()[1:]


def _spf_target(term: str) -> str | None:
    """Domain argument of include:/redirect= (None if absent or macro-expanded)."""
    t = term.lstrip("+-~?")
    sep = ":" if t.lower().startswith("include:") else "=" if t.lower().startswith("redirect=") else None
    if not sep:
        return None
    target = t.split(sep, 1)[1].strip().rstrip(".")
    return None if (not target or "%" in target) else target


def _spf_count_lookups(record: str, depth: int = 0, seen: set | None = None) -> int:
    """RFC 7208 §4.6.4: count DNS-querying terms, recursing into include/redirect.

    Stops recursing once the limit is exceeded (the result is already a permerror)
    and guards against include loops."""
    seen = seen if seen is not None else set()
    count = 0
    for term in _spf_terms(record):
        t = term.lower().lstrip("+-~?")
        mech = t.split(":")[0].split("/")[0].split("=")[0]
        if mech not in SPF_LOOKUP_MECHANISMS:
            continue
        count += 1
        target = _spf_target(term) if mech in ("include", "redirect") else None
        # Once over the limit the record is already a permerror: keep counting
        # this level's terms, but stop issuing DNS queries for nested records.
        if target and depth < 10 and count <= SPF_LOOKUP_LIMIT and target.lower() not in seen:
            seen.add(target.lower())
            child = _spf_record(target)
            if child:
                count += _spf_count_lookups(child, depth + 1, seen)
    return count


def check_spf(domain: str) -> dict:
    max_score = 15
    records = [t for t in _txt(domain) if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]
    if not records:
        return {
            "key": "spf", "title": "SPF", "status": "fail", "score": 0, "max_score": max_score,
            "details": "No SPF record published.",
            "issues": ["No SPF record: anyone can send mail claiming to be this domain."],
            "fixes": [f'Add TXT record at {domain}: "v=spf1 -all" (then add your real senders before enforcing)'],
        }
    if len(records) > 1:
        return {
            "key": "spf", "title": "SPF", "status": "fail", "score": 2, "max_score": max_score,
            "details": f"{len(records)} SPF records found; only one is allowed (permerror).",
            "issues": ["Multiple SPF records cause a permanent error; receivers ignore SPF."],
            "fixes": ["Merge into a single TXT record starting with v=spf1."],
        }
    record = records[0]
    terms = _spf_terms(record)
    lookups = _spf_count_lookups(record, seen={domain.lower()})
    has_ptr = False
    open_cidr = False
    for term in terms:
        t = term.lower()
        if t.startswith(("-", "~", "?")):
            continue  # only pass (+/implicit) terms authorize senders
        t = t.lstrip("+")
        mech = t.split(":")[0].split("/")[0].split("=")[0]
        if mech == "ptr":
            has_ptr = True
        if t.startswith("ip4:") and t.endswith("/0") or t.startswith("ip6:") and t.endswith("/0"):
            open_cidr = True
    issues, fixes = [], []
    all_mech = next((t for t in terms if t.lower().lstrip("+-~?") == "all"), None)
    if all_mech is None:
        # No "all": the policy's default comes from a redirect= target (RFC 7208 §6.1),
        # otherwise the implicit result is neutral.
        redirect = next((_spf_target(t) for t in terms if t.lower().startswith("redirect=")), None)
        target_rec = _spf_record(redirect) if redirect else None
        if target_rec:
            all_mech = next((t for t in _spf_terms(target_rec) if t.lower().lstrip("+-~?") == "all"), None)
    if all_mech is None:
        qualifier = "?"
    else:
        qualifier = all_mech[0] if all_mech[0] in "+-~?" else "+"  # bare "all" means +all
    if open_cidr:
        issues.append("SPF authorizes 0.0.0.0/0: the entire internet may send as this domain.")
        fixes.append("Remove the /0 entry and list only your real sending IPs.")
        status, score = "fail", 2
    elif lookups > SPF_LOOKUP_LIMIT:
        issues.append(f"SPF causes {lookups} DNS lookups (limit is 10) -> permerror on many receivers.")
        fixes.append("Flatten includes or use an SPF flattening/hosting service to stay under 10 lookups.")
        status, score = "fail", 3
    elif qualifier == "-":
        status, score = "pass", max_score
    elif qualifier == "~":
        issues.append("SPF ends in ~all (softfail): spoofed mail is accepted but marked.")
        fixes.append("After verifying legitimate senders, change ~all to -all.")
        status, score = "warn", 11
    elif qualifier == "+":
        issues.append("SPF ends in +all: explicitly authorizes the whole internet.")
        fixes.append("Replace +all with -all immediately.")
        status, score = "fail", 2
    else:
        issues.append("SPF ends in ?all (neutral): provides almost no protection.")
        fixes.append("Change ?all to -all once legitimate senders are included.")
        status, score = "warn", 7
    if has_ptr:
        issues.append("SPF uses the ptr mechanism: deprecated, slow, and unreliable — receivers may skip it.")
        fixes.append("Replace ptr with explicit ip4/ip6 entries or includes.")
        if status == "pass":
            status, score = "warn", 12
        else:
            score = max(0, score - 2)
    details = f"Record: {record} ({lookups}/{SPF_LOOKUP_LIMIT} DNS lookups, includes followed)"
    return {
        "key": "spf", "title": "SPF", "status": status, "score": score, "max_score": max_score,
        "details": details, "issues": issues, "fixes": fixes,
    }


# ------------------------------------------------------------------ DMARC
def check_dmarc(domain: str) -> dict:
    max_score = 20
    records = [t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not records:
        return {
            "key": "dmarc", "title": "DMARC", "status": "fail", "score": 0, "max_score": max_score,
            "details": "No DMARC record published.",
            "issues": ["No DMARC policy: receivers take no action on spoofed mail."],
            "fixes": [f'Add TXT at _dmarc.{domain}: "v=DMARC1; p=none; rua=mailto:dmarc@{domain}" then move to quarantine -> reject.'],
        }
    if len(records) > 1:
        return {
            "key": "dmarc", "title": "DMARC", "status": "fail", "score": 0, "max_score": max_score,
            "details": f"{len(records)} DMARC records found; receivers ignore DMARC when more than one exists.",
            "issues": ["Multiple DMARC records: the policy is not applied at all (RFC 7489 §6.6.3)."],
            "fixes": [f"Delete all but one TXT record at _dmarc.{domain}."],
        }
    tags = _parse_tag_list(records[0])
    policy = tags.get("p", "none").lower()
    pct = int(tags.get("pct", "100")) if tags.get("pct", "100").isdigit() else 100
    pct = min(pct, 100)
    issues, fixes = [], []
    if policy == "reject":
        status, score = "pass", max_score
    elif policy == "quarantine":
        issues.append("Policy is quarantine: spoofed mail is filtered, not rejected.")
        fixes.append("Move to p=reject once legitimate senders are aligned.")
        status, score = "warn", 12
    else:
        issues.append("Policy is none: DMARC only monitors, takes no enforcement action.")
        fixes.append("Move to p=quarantine, then p=reject.")
        status, score = "warn", 5
    if pct < 100:
        issues.append(f"Policy applies to only {pct}% of mail.")
        fixes.append("Raise pct to 100 when ready to fully enforce.")
        score = max(0, score - 3)
    if "rua" not in tags:
        issues.append("No rua tag: you receive no aggregate reports about who sends as your domain.")
        fixes.append(f'Add rua=mailto:dmarc@{domain} to the DMARC record.')
        score = max(0, score - 2)
    # --- advanced signals (no score change unless noted) ---
    detail_bits = [f"p={policy}", f"pct={pct}", f"rua={'set' if 'rua' in tags else 'missing'}"]
    sp = tags.get("sp")
    if sp:
        detail_bits.append(f"sp={sp}")
        if sp.lower() == "none" and policy in ("quarantine", "reject"):
            issues.append("Subdomain policy (sp=none) is weaker than the organizational policy: subdomains remain spoofable.")
            fixes.append("Set sp= to match p (or omit it to inherit).")
    for tag, name in (("adkim", "DKIM"), ("aspf", "SPF")):
        if tags.get(tag, "r").lower() == "s":
            detail_bits.append(f"{tag}=strict")
    if "ruf" in tags:
        detail_bits.append("ruf=set")
    return {
        "key": "dmarc", "title": "DMARC", "status": status, "score": score, "max_score": max_score,
        "details": "Policy: " + "; ".join(detail_bits),
        "issues": issues, "fixes": fixes,
    }


# ------------------------------------------------------------------ DKIM
COMMON_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "dkim",
    "mail", "email", "s1", "s2", "cm", "mandrill", "everlytickey", "mxvault",
]


def _dkim_key_bits(pub_b64: str) -> int | None:
    """True RSA modulus bit-length of a DKIM p= key.

    Real-world DKIM keys (RFC 6376 §3.6.1, what `openssl rsa -pubout` and every
    mail provider publish) are DER SubjectPublicKeyInfo; some publish a bare
    PKCS#1 RSAPublicKey. `cryptography` parses both. Keys too small for the
    library to load fall back to reading the PKCS#1 modulus length directly.
    """
    try:
        raw = base64.b64decode("".join(pub_b64.split()), validate=True)
    except Exception:
        return None
    if not raw:
        return None
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = serialization.load_der_public_key(raw)
        if isinstance(key, rsa.RSAPublicKey):
            return key.key_size
        return None
    except Exception:
        pass
    try:
        if len(raw) < 4 or raw[0] != 0x30:  # SEQUENCE
            return None
        i = 1
        if raw[i] & 0x80:  # long-form length
            n = raw[i] & 0x7F
            i += 1 + n
        else:
            i += 1
        if raw[i] != 0x02:  # INTEGER (modulus)
            return None
        i += 1
        if raw[i] & 0x80:
            n = raw[i] & 0x7F
            mod_len = int.from_bytes(raw[i + 1:i + 1 + n], "big")
            i += 1 + n
        else:
            mod_len = raw[i]
            i += 1
        modulus = raw[i:i + mod_len].lstrip(b"\x00")
        return len(modulus) * 8 or None
    except Exception:
        return None


def check_dkim(domain: str) -> dict:
    max_score = 15
    found = []
    for sel in COMMON_SELECTORS:
        for t in _txt(f"{sel}._domainkey.{domain}"):
            if "v=dkim1" in t.lower().replace(" ", "") or "p=" in t:
                tags = _parse_tag_list(t)
                p = "".join(tags.get("p", "").split())
                if p and p != "*":
                    found.append((sel, p, tags))
                break
        if found:
            break
    if not found:
        return {
            "key": "dkim", "title": "DKIM", "status": "fail", "score": 0, "max_score": max_score,
            "details": f"No DKIM key found under {len(COMMON_SELECTORS)} common selectors.",
            "issues": ["No discoverable DKIM key: mail cannot be cryptographically signed."],
            "fixes": ["Publish a DKIM TXT record from your mail provider (usually {selector}._domainkey) with a 2048-bit key."],
        }
    sel, p, tags = found[0]
    key_type = tags.get("k", "rsa").lower()
    bits = _dkim_key_bits(p) if key_type == "rsa" else None
    issues, fixes = [], []
    flags = tags.get("t", "")
    notes = []
    if "y" in flags:
        notes.append("Selector is in testing mode (t=y): signatures may be ignored.")
    if "s" in flags:
        notes.append("Strict domain matching (t=s): key cannot sign subdomains.")
    if key_type == "ed25519":
        status, score = "pass", max_score
        details = f"Selector '{sel}' with an Ed25519 key (RFC 8463)."
    elif bits and bits >= 2048:
        status, score = "pass", max_score
        details = f"Selector '{sel}' with {bits}-bit key."
    elif bits and bits >= 1024:
        status, score = "warn", 8
        details = f"Selector '{sel}' with {bits}-bit key (1024-bit is the minimum; 2048 recommended)."
        issues.append("1024-bit DKIM keys are the bare minimum; factorable with enough resources.")
        fixes.append("Rotate to a 2048-bit DKIM key.")
    elif bits:
        status, score = "fail", 2
        details = f"Selector '{sel}' with {bits}-bit key — below the 1024-bit minimum."
        issues.append(f"{bits}-bit DKIM key is cryptographically weak.")
        fixes.append("Rotate to a 2048-bit DKIM key immediately.")
    else:
        status, score = "warn", 8
        details = f"Selector '{sel}' found; key length could not be determined."
    if notes:
        details += " " + " ".join(notes)
    return {
        "key": "dkim", "title": "DKIM", "status": status, "score": score, "max_score": max_score,
        "details": details, "issues": issues, "fixes": fixes,
    }


# ------------------------------------------------------------------ MTA-STS / TLS-RPT / BIMI
def _parse_sts_policy(body: str) -> tuple[dict[str, str], list[str]]:
    """RFC 8461 §3.2 policy file: one "key: value" per line; mx may repeat."""
    tags: dict[str, str] = {}
    mx: list[str] = []
    for line in body.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if k == "mx":
            if v:
                mx.append(v.rstrip(".").lower())
        elif k:
            tags[k] = v
    return tags, mx


def _mx_matches(pattern: str, host: str) -> bool:
    """RFC 8461 §4.1: "*.example.com" matches exactly one extra leftmost label."""
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and "." not in host[: -len(suffix)]
    return pattern == host


def check_mta_sts(domain: str) -> dict:
    max_score = 10

    sts_txt = [t for t in _txt(f"_mta-sts.{domain}") if "v=sts" in t.lower().replace(" ", "")]
    if not sts_txt:
        return {
            "key": "mta-sts", "title": "MTA-STS", "status": "fail", "score": 0, "max_score": max_score,
            "details": "No MTA-STS record.",
            "issues": ["Mail can be downgraded to plaintext by an active attacker."],
            "fixes": [f'Add TXT at _mta-sts.{domain}: "v=STSv1; id=1", then serve a policy at https://mta-sts.{domain}/.well-known/mta-sts.txt'],
        }
    try:
        # RFC 8461 §3.3: policy is fetched over validated HTTPS, redirects not followed.
        host = f"mta-sts.{domain}"
        if not net.is_public_host(host):
            raise ValueError("policy host is not public")
        import httpx
        r = httpx.get(f"https://{host}/.well-known/mta-sts.txt", timeout=TIMEOUT, follow_redirects=False)
        body = r.text[:65536] if r.status_code == 200 else ""
    except Exception:
        body = ""
    tags, policy_mx_list = _parse_sts_policy(body)
    if tags.get("version", "").lower() != "stsv1":
        tags = {}
    mode = tags.get("mode", "").lower()
    issues, fixes = [], []
    if mode == "enforce":
        status, score = "pass", max_score
        details = "MTA-STS policy published with mode=enforce."
    elif mode == "none":
        status, score = "warn", 2
        details = "MTA-STS policy published with mode=none (policy withdrawn)."
        issues, fixes = ["Policy mode is none; receivers will not enforce TLS."], ["Change mode to enforce."]
    elif mode == "testing":
        status, score = "warn", 4
        details = "MTA-STS policy in testing mode (no enforcement)."
        issues, fixes = ["Policy is testing-only; downgrade attacks still possible."], ["Change mode to enforce."]
    else:
        status, score = "warn", 4
        details = "MTA-STS DNS record exists but policy file is unreachable or invalid."
        issues = ["Policy file missing or invalid; receivers cannot enforce TLS."]
        fixes = [f"Serve a valid policy at https://mta-sts.{domain}/.well-known/mta-sts.txt with mode: enforce"]
    if mode in ("enforce", "testing"):
        # --- advanced: policy must name the real MX hosts, or mail breaks ---
        if not tags.get("max_age", "").isdigit():
            issues.append("Policy has no valid max_age: receivers won't cache it.")
            fixes.append("Add max_age (e.g. 86400 or higher) to the policy file.")
            score = max(0, score - 2)
            if status == "pass":
                status = "warn"
        policy_mx = set(policy_mx_list)
        try:
            real_mx = {str(r.exchange).rstrip(".").lower()
                       for r in _resolver.resolve(domain, "MX", lifetime=TIMEOUT)} - {""}
        except Exception:
            real_mx = set()
        uncovered = sorted(h for h in real_mx if not any(_mx_matches(p, h) for p in policy_mx))
        if not policy_mx:
            issues.append("Policy lists no mx: entries; senders enforcing it cannot deliver mail.")
            fixes.append("List every real MX hostname in the policy's mx: entries.")
            score = max(0, score - 3)
            status = "warn"
        elif real_mx and uncovered:
            matched_none = len(uncovered) == len(real_mx)
            issues.append(
                f"Policy MX ({', '.join(sorted(policy_mx)[:3])}) "
                + ("matches none of the real MX hosts: mail may be rejected."
                   if matched_none else f"does not cover {', '.join(uncovered[:3])}.")
            )
            fixes.append("List every real MX hostname in the policy's mx: entries.")
            score = max(0, score - (3 if matched_none else 1))
            status = "warn"
    return {
        "key": "mta-sts", "title": "MTA-STS", "status": status, "score": score, "max_score": max_score,
        "details": details, "issues": issues if mode in ("enforce", "testing", "none") else ["Policy file missing or invalid; receivers cannot enforce TLS."],
        "fixes": fixes if mode in ("enforce", "testing", "none") else [f"Serve a valid policy at https://mta-sts.{domain}/.well-known/mta-sts.txt with mode: enforce"],
    }


def check_tls_rpt(domain: str) -> dict:
    max_score = 3
    records = [t for t in _txt(f"_smtp._tls.{domain}") if "v=tlsrpt" in t.lower().replace(" ", "")]
    if records:
        return {"key": "tls-rpt", "title": "TLS-RPT", "status": "pass", "score": max_score,
                "max_score": max_score, "details": "TLS-RPT record published; delivery failures are reported.",
                "issues": [], "fixes": []}
    return {"key": "tls-rpt", "title": "TLS-RPT", "status": "warn", "score": 0, "max_score": max_score,
            "details": "No TLS-RPT record: TLS delivery problems go unreported.",
            "issues": ["No visibility into TLS failures on inbound mail."],
            "fixes": [f'Add TXT at _smtp._tls.{domain}: "v=TLSRPTv1; rua=mailto:tls@{domain}"']}


def check_bimi(domain: str) -> dict:
    max_score = 2
    records = [t for t in _txt(f"default._bimi.{domain}") if "v=bimi1" in t.lower().replace(" ", "")]
    if not records:
        return {"key": "bimi", "title": "BIMI", "status": "warn", "score": 0, "max_score": max_score,
                "details": "No BIMI record (requires DMARC enforcement first).",
                "issues": [], "fixes": ["After reaching p=quarantine/reject, publish a BIMI record to display your logo in inboxes."]}
    tags = _parse_tag_list(records[0])
    logo = tags.get("l", "")
    if not logo:
        return {"key": "bimi", "title": "BIMI", "status": "warn", "score": 1, "max_score": max_score,
                "details": "BIMI record published but has no logo URL.",
                "issues": ["BIMI record has no logo URL."],
                "fixes": ["Add l= with your SVG logo URL and a VMC certificate."]}
    # Verify the logo actually exists and is an SVG (size-capped fetch).
    try:
        if not logo.lower().startswith("https://"):
            raise ValueError("BIMI logos must be served over HTTPS")
        status_code, head = net.safe_fetch_head(logo, timeout=TIMEOUT)
        # SVG files commonly start with an XML declaration or comment before <svg
        is_svg = b"<svg" in head.lower()
        ok = status_code == 200 and is_svg
    except Exception:
        ok = False
    if ok:
        return {"key": "bimi", "title": "BIMI", "status": "pass", "score": max_score,
                "max_score": max_score, "details": "BIMI record published; logo URL serves a valid SVG.",
                "issues": [], "fixes": []}
    return {"key": "bimi", "title": "BIMI", "status": "warn", "score": 1, "max_score": max_score,
            "details": "BIMI record published, but the logo URL is unreachable or not an SVG.",
            "issues": ["Logo URL does not serve a valid SVG; inboxes will not display it."],
            "fixes": ["Host a valid SVG Tiny PS logo at the l= URL over HTTPS."]}


# ------------------------------------------------------------------ CAA
def check_caa(domain: str) -> dict:
    """Certificate Authority Authorization: restrict which CAs may issue for the domain."""
    max_score = 5
    # RFC 8659 §3: the relevant CAA set is the first one found climbing toward the root.
    records, found_at = [], domain
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        try:
            answers = _resolver.resolve(name, "CAA", lifetime=TIMEOUT)
            records = [f'{r.flags} {r.tag.decode()} "{r.value.decode()}"' for r in answers]
        except Exception:
            records = []
        if records:
            found_at = name
            break
    if not records:
        return {"key": "caa", "title": "CAA", "status": "warn", "score": 2, "max_score": max_score,
                "details": "No CAA records: any public CA may issue certificates for this domain.",
                "issues": ["Without CAA, a compromised or tricked CA can issue a valid cert for your domain."],
                "fixes": [f'Add CAA records at {domain}: 0 issue "letsencrypt.org" (plus your real CAs).']}
    tags = [r.split()[1].lower().rstrip(";") for r in records]
    if "issue" not in tags and "issuewild" not in tags:
        return {"key": "caa", "title": "CAA", "status": "warn", "score": 3, "max_score": max_score,
                "details": f"CAA records exist but restrict nothing ({len(records)} record(s), no issue tag).",
                "issues": ["CAA records present but no issue/issuewild restriction."],
                "fixes": ['Add an "issue" tag naming your CA, e.g. 0 issue "letsencrypt.org".']}
    inherited = f", inherited from {found_at}" if found_at != domain else ""
    return {"key": "caa", "title": "CAA", "status": "pass", "score": max_score, "max_score": max_score,
            "details": f"CAA restricts issuance ({len(records)} record(s){inherited}).",
            "issues": [], "fixes": []}


# ------------------------------------------------------------------ MX / SMTP TLS / DNSBL (existing below)
def check_mx(domain: str) -> dict:
    max_score = 5
    try:
        answers = _resolver.resolve(domain, "MX", lifetime=TIMEOUT)
        hosts = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in answers])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        hosts = []
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        raise DnsLookupError(f"MX lookup failed: {type(exc).__name__}") from exc
    if not hosts:
        return {"key": "mx", "title": "MX", "status": "fail", "score": 0, "max_score": max_score,
                "details": "No MX records: domain cannot receive mail.",
                "issues": ["No MX records published."],
                "fixes": ["Add MX records pointing at your mail provider."]}
    # Null MX (RFC 7505): "." means "this domain accepts no mail" — legitimate.
    if len(hosts) == 1 and hosts[0][1] == "":
        return {"key": "mx", "title": "MX", "status": "pass", "score": max_score,
                "max_score": max_score,
                "details": "Null MX published: domain explicitly accepts no mail (RFC 7505).",
                "issues": [], "fixes": []}
    issues, fixes = [], []
    # MX targets must not be CNAMEs (RFC 2181 §10.3) — some receivers penalize it.
    for _, h in hosts:
        try:
            _resolver.resolve(h, "CNAME", lifetime=3)
            issues.append(f"MX target {h} is a CNAME: RFC 2181 forbids aliases as mail exchangers.")
            fixes.append(f"Point the MX at the canonical hostname instead of {h}.")
            break
        except Exception:
            continue
    status, score = ("warn", 3) if issues else ("pass", max_score)
    return {"key": "mx", "title": "MX", "status": status, "score": score, "max_score": max_score,
            "details": f"{len(hosts)} MX record(s): {', '.join(h for _, h in hosts[:3])}",
            "issues": issues, "fixes": fixes}


def check_smtp_tls(domain: str) -> dict:
    max_score = 5
    try:
        answers = _resolver.resolve(domain, "MX", lifetime=TIMEOUT)
        hosts = [h for _, h in sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)]
    except Exception:
        hosts = []
    if hosts == [""]:  # null MX (RFC 7505): no mail server exists to test
        return {"key": "smtp-tls", "title": "SMTP TLS", "status": "pass", "score": 0,
                "max_score": 0, "details": "Not applicable: domain publishes a null MX.",
                "issues": [], "fixes": []}
    hosts = [h for h in hosts if h]
    if not hosts:
        return {"key": "smtp-tls", "title": "SMTP TLS", "status": "warn", "score": 0,
                "max_score": max_score, "details": "No MX host to test.", "issues": [], "fixes": []}
    host = next((h for h in hosts[:3] if net.is_public_host(h)), None)
    if host is None:
        return {"key": "smtp-tls", "title": "SMTP TLS", "status": "warn", "score": 0,
                "max_score": max_score,
                "details": "MX hosts do not resolve to public addresses; cannot test STARTTLS.",
                "issues": ["MX hosts point at private or unresolvable addresses."],
                "fixes": ["Point MX records at publicly reachable mail servers."]}
    smtp = smtplib.SMTP(timeout=TIMEOUT)
    try:
        smtp.connect(host, 25)
    except OSError as e:
        # Most cloud hosts block outbound port 25, so a refused/timed-out connect
        # says more about the scanner's network than the domain: leave it unscored.
        smtp.close()
        return {"key": "smtp-tls", "title": "SMTP TLS", "status": "warn", "score": 0,
                "max_score": 0,
                "details": f"Not tested: could not connect to {host} on port 25 from the scanner "
                           f"({type(e).__name__}). Not counted in the score.",
                "issues": [], "fixes": []}
    try:
        with smtp:
            smtp.ehlo("phishlens.scan")
            if smtp.has_extn("starttls"):
                smtp.starttls()
                smtp.ehlo("phishlens.scan")
                return {"key": "smtp-tls", "title": "SMTP TLS", "status": "pass", "score": max_score,
                        "max_score": max_score, "details": f"{host} supports STARTTLS.",
                        "issues": [], "fixes": []}
            return {"key": "smtp-tls", "title": "SMTP TLS", "status": "fail", "score": 0,
                    "max_score": max_score, "details": f"{host} does not advertise STARTTLS.",
                    "issues": ["Mail server accepts unencrypted connections."],
                    "fixes": ["Enable STARTTLS on the mail server."]}
    except Exception as e:
        return {"key": "smtp-tls", "title": "SMTP TLS", "status": "warn", "score": 2,
                "max_score": max_score, "details": f"Could not complete SMTP handshake: {type(e).__name__}.",
                "issues": [], "fixes": []}


DNSBLS = ["zen.spamhaus.org", "bl.spamcop.net", "psbl.surriel.com", "bl.mailspike.net"]
# Domain blocklists list the domain itself (seen in spam/phishing URLs or as a
# sender), independent of which servers send its mail.
DOMAIN_BLS = ["dbl.spamhaus.org", "multi.surbl.org"]


def _dnsbl_listed(query: str, domain_list: bool = False) -> bool:
    """True only for a genuine listing.

    Blocklists answer 127.0.0.2-127.0.0.255 for listed IPs. Spamhaus answers
    127.255.255.x when it refuses the query (public/open resolver, rate limit),
    and some ISP resolvers rewrite NXDOMAIN to an ad server's IP — neither is a
    listing, and counting them would flag every domain. Spamhaus DBL lists
    domains as 127.0.1.2-127.0.1.99 (127.0.1.255 is an error code)."""
    try:
        answers = _resolver.resolve(query, "A", lifetime=3)
    except Exception:
        return False
    for r in answers:
        ip = str(r)
        if domain_list and query.endswith(".dbl.spamhaus.org"):
            if ip.startswith("127.0.1."):
                try:
                    if 2 <= int(ip.rsplit(".", 1)[1]) <= 99:
                        return True
                except ValueError:
                    pass
            continue
        if ip.startswith("127.0.0.") and ip != "127.0.0.1":
            return True
    return False


def check_dnsbl(domain: str) -> dict:
    from concurrent.futures import ThreadPoolExecutor

    max_score = 5
    try:
        answers = _resolver.resolve(domain, "MX", lifetime=TIMEOUT)
        hosts = [str(r.exchange).rstrip(".") for r in answers]
    except Exception:
        hosts = []
    queries = []  # (query, label, is_domain_list)
    for host in [h for h in hosts if h][:3]:
        try:
            ip = socket.gethostbyname(host)
        except (socket.gaierror, UnicodeError):
            continue
        rev = ".".join(reversed(ip.split(".")))
        queries += [(f"{rev}.{bl}", f"{ip} on {bl}", False) for bl in DNSBLS]
    queries += [(f"{domain}.{bl}", f"{domain} on {bl}", True) for bl in DOMAIN_BLS]
    with ThreadPoolExecutor(max_workers=8) as pool:
        hits = list(pool.map(lambda q: _dnsbl_listed(q[0], q[2]), queries))
    listed = list(dict.fromkeys(label for (_, label, _), hit in zip(queries, hits) if hit))
    if listed:
        domain_hit = any(label.startswith(domain + " ") for label in listed)
        fixes = ["Request delisting via the blocklist's process and fix the underlying spam/misconfig issue."]
        if domain_hit:
            fixes.append("A domain listing usually means the domain appeared in spam or phishing: check for "
                         "compromised accounts, hacked web pages, or a sending service abusing your domain.")
        return {"key": "dnsbl", "title": "Blacklists", "status": "fail", "score": 0, "max_score": max_score,
                "details": "Domain or mail server IP found on blocklists.",
                "issues": [f"Listed: {x}" for x in listed],
                "fixes": fixes}
    return {"key": "dnsbl", "title": "Blacklists", "status": "pass", "score": max_score,
            "max_score": max_score,
            "details": f"Domain and mail server IPs not found on {len(DNSBLS) + len(DOMAIN_BLS)} major blocklists.",
            "issues": [], "fixes": []}


def check_dnssec(domain: str) -> dict:
    max_score = 5
    # Find the zone that actually serves this name, then look for its DS record
    # in the parent. Walking up blindly would credit e.g. example.co.uk with the
    # DS record of the (signed) public suffix co.uk.
    try:
        zone = dns.resolver.zone_for_name(domain, resolver=_resolver, lifetime=TIMEOUT)
        zone_name = zone.to_text(omit_final_dot=True)
    except Exception:
        zone_name = domain
    ds_found = False
    if "." in zone_name:  # never credit a TLD's own DS
        try:
            _resolver.resolve(zone_name, "DS", lifetime=3)
            ds_found = True
        except Exception:
            ds_found = False
    if ds_found:
        return {"key": "dnssec", "title": "DNSSEC", "status": "pass", "score": max_score,
                "max_score": max_score, "details": "DS record found: zone is DNSSEC-signed.",
                "issues": [], "fixes": []}
    return {"key": "dnssec", "title": "DNSSEC", "status": "warn", "score": 0, "max_score": max_score,
            "details": "No DS record found: DNS responses for this domain can be spoofed.",
            "issues": ["Zone is not DNSSEC-signed."],
            "fixes": ["Enable DNSSEC at your registrar/DNS provider and publish DS records."]}
