"""Mail-server checks that internet.nl and the paid tools run: DANE (TLSA),
reverse DNS (PTR / FCrDNS), IPv6 reachability and, optionally, RPKI.

They are informational (max_score 0): they show what to improve without
changing the 0-100 grade, which stays comparable with earlier scans.
"""
import ipaddress

import dns.resolver
import dns.reversename
import httpx

from ..config import settings
from . import dns_checks

TIMEOUT = dns_checks.TIMEOUT
INFO = " Not counted in the score."


def _mx_hosts(domain: str, limit: int = 3) -> list[str] | None:
    """MX hosts by preference; None for a null MX."""
    try:
        answers = dns_checks._resolver.resolve(domain, "MX", lifetime=TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception as exc:
        raise dns_checks.DnsLookupError(f"MX lookup failed: {type(exc).__name__}") from exc
    hosts = [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda r: r.preference)]
    if hosts == [""]:
        return None
    return [h for h in hosts if h][:limit]


def _addrs(host: str, rtype: str) -> list[str]:
    try:
        return [str(r) for r in dns_checks._resolver.resolve(host, rtype, lifetime=TIMEOUT)]
    except Exception:
        return []


def _result(key, title, status, details, issues=(), fixes=()):
    return {"key": key, "title": title, "status": status, "score": 0, "max_score": 0,
            "details": details + INFO, "issues": list(issues), "fixes": list(fixes)}


def _no_mail(key, title, hosts):
    if hosts is None:
        return _result(key, title, "pass", "Not applicable: domain publishes a null MX.")
    return _result(key, title, "warn", "No MX hosts to test.")


# ------------------------------------------------------------------ DANE
def _zone_signed(host: str) -> bool:
    try:
        zone = dns.resolver.zone_for_name(host, resolver=dns_checks._resolver, lifetime=TIMEOUT)
        name = zone.to_text(omit_final_dot=True)
        if "." not in name:
            return False
        dns_checks._resolver.resolve(name, "DS", lifetime=3)
        return True
    except Exception:
        return False


def check_dane(domain: str) -> dict:
    """RFC 7672: TLSA records at _25._tcp.<mx> pin the mail server's
    certificate, so a man-in-the-middle can't strip or fake STARTTLS."""
    hosts = _mx_hosts(domain)
    if not hosts:
        return _no_mail("dane", "DANE (TLSA)", hosts)
    with_tlsa, issues, fixes = [], [], []
    for host in hosts:
        try:
            recs = list(dns_checks._resolver.resolve(f"_25._tcp.{host}", "TLSA", lifetime=TIMEOUT))
        except Exception:
            recs = []
        if not recs:
            continue
        with_tlsa.append(host)
        if not _zone_signed(host):
            issues.append(f"{host} has TLSA records but its zone isn't DNSSEC-signed, so senders ignore them.")
            fixes.append(f"Enable DNSSEC for the zone of {host}.")
        for r in recs:
            if r.usage in (0, 1):
                issues.append(f"{host}: TLSA usage {r.usage} (PKIX) isn't used for SMTP (RFC 7672 §3.1.3).")
                fixes.append("Use usage 3 (DANE-EE) or 2 (DANE-TA), e.g. \"3 1 1 <sha256 of the public key>\".")
                break
    if not with_tlsa:
        provider_hint = ("Your mail provider hosts these servers: ask whether it supports DANE "
                         "(Microsoft 365 and many European providers do).")
        return _result("dane", "DANE (TLSA)", "warn",
                       f"No TLSA records for {', '.join(hosts)}.",
                       ["Mail servers don't publish DANE, so STARTTLS can be downgraded by an attacker in the path."],
                       ["DANE needs DNSSEC on the MX host's zone, then a TLSA record such as "
                        f"_25._tcp.{hosts[0]} TLSA 3 1 1 <sha256 of the server's public key>. " + provider_hint])
    missing = [h for h in hosts if h not in with_tlsa]
    if missing:
        issues.append(f"No TLSA for {', '.join(missing)}: mail can be delivered there without DANE.")
    status = "pass" if not issues else "warn"
    return _result("dane", "DANE (TLSA)", status,
                   f"TLSA published for {', '.join(with_tlsa)}.", issues, fixes)


# ------------------------------------------------------------------ PTR / FCrDNS
def _ptr(ip: str) -> list[str]:
    try:
        return [str(r).rstrip(".").lower() for r in
                dns_checks._resolver.resolve(dns.reversename.from_address(ip), "PTR", lifetime=TIMEOUT)]
    except Exception:
        return []


def check_ptr(domain: str) -> dict:
    """Reverse DNS for each mail server IP, forward-confirmed (FCrDNS): the
    PTR name must resolve back to the same IP. Google and Yahoo require it of
    sending servers; many receivers reject mail from IPs without it."""
    hosts = _mx_hosts(domain)
    if not hosts:
        return _no_mail("ptr", "Reverse DNS (PTR)", hosts)
    issues, fixes, good = [], [], []
    for host in hosts:
        for ip in (_addrs(host, "A") + _addrs(host, "AAAA"))[:2]:
            names = _ptr(ip)
            if not names:
                issues.append(f"{ip} ({host}) has no PTR record.")
                fixes.append(f"Ask whoever owns {ip} (your hosting or mail provider) to set its PTR to {host}.")
                continue
            confirmed = any(ip in (_addrs(n, "A") + _addrs(n, "AAAA")) for n in names[:2])
            if confirmed:
                good.append(f"{ip} → {names[0]}")
            else:
                issues.append(f"{ip} ({host}) has PTR {names[0]}, which doesn't resolve back to {ip}.")
                fixes.append(f"Make {names[0]} resolve to {ip}, or change the PTR to a name that does.")
    if not issues and not good:
        return _result("ptr", "Reverse DNS (PTR)", "warn", "MX hosts have no addresses to check.")
    status = "pass" if not issues else "warn"
    details = ("Forward-confirmed reverse DNS: " + "; ".join(good[:4])) if good else "Reverse DNS problems found."
    return _result("ptr", "Reverse DNS (PTR)", status, details, issues, list(dict.fromkeys(fixes)))


# ------------------------------------------------------------------ IPv6
def check_ipv6(domain: str) -> dict:
    hosts = _mx_hosts(domain)
    mx_v6 = {h: bool(_addrs(h, "AAAA")) for h in (hosts or [])}
    web_v6 = bool(_addrs(domain, "AAAA") or _addrs(f"www.{domain}", "AAAA"))
    issues, fixes = [], []
    if hosts and not any(mx_v6.values()):
        issues.append("No mail server is reachable over IPv6.")
        fixes.append("Ask your mail provider for IPv6 MX hosts, or add AAAA records for your own servers.")
    if not web_v6:
        issues.append(f"{domain} and www.{domain} have no IPv6 (AAAA) address.")
        fixes.append(f"Add an AAAA record for {domain} (most CDNs and hosts provide one).")
    bits = []
    if hosts:
        bits.append(f"mail IPv6: {sum(mx_v6.values())}/{len(mx_v6)} MX hosts")
    bits.append(f"web IPv6: {'yes' if web_v6 else 'no'}")
    return _result("ipv6", "IPv6", "pass" if not issues else "warn", "; ".join(bits) + ".", issues, fixes)


# ------------------------------------------------------------------ RPKI (opt-in)
RIPESTAT = "https://stat.ripe.net/data"


def _rpki_status(ip: str) -> tuple[str, str] | None:
    """(status, prefix) via RIPEstat, or None if unknown. Calls an external
    API, so it only runs when RPKI_CHECK is enabled."""
    with httpx.Client(timeout=8) as c:
        info = c.get(f"{RIPESTAT}/network-info/data.json", params={"resource": ip}).json().get("data", {})
        prefix, asns = info.get("prefix"), info.get("asns") or []
        if not prefix or not asns:
            return None
        res = c.get(f"{RIPESTAT}/rpki-validation/data.json",
                    params={"resource": f"AS{asns[0]}", "prefix": prefix}).json().get("data", {})
        return res.get("status", "unknown"), prefix


def check_rpki(domain: str) -> dict:
    """Are the routes to the mail servers covered by valid RPKI ROAs? Protects
    against BGP hijacks that redirect mail."""
    if not settings.RPKI_CHECK:
        return _result("rpki", "RPKI", "pass", "Not checked (RPKI_CHECK is off on this server).")
    hosts = _mx_hosts(domain)
    if not hosts:
        return _no_mail("rpki", "RPKI", hosts)
    seen, issues, good = set(), [], []
    for host in hosts:
        for ip in _addrs(host, "A")[:1]:
            try:
                res = _rpki_status(ip)
            except (httpx.HTTPError, ValueError):
                res = None
            if not res or res[1] in seen:
                continue
            seen.add(res[1])
            status, prefix = res
            (good if status == "valid" else issues).append(
                f"{prefix} ({host}): {status}" if status != "valid" else f"{prefix} valid")
    if not seen:
        return _result("rpki", "RPKI", "warn", "RPKI status unavailable for the mail servers.")
    fixes = ["Ask the network that hosts your mail servers to publish ROAs (RPKI) for their prefixes."] if issues else []
    return _result("rpki", "RPKI", "pass" if not issues else "warn",
                   "Mail server routes: " + "; ".join(good + issues), issues, fixes)
