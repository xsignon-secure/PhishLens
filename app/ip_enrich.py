"""Who is behind a sending IP? Reverse DNS for every IP, and the country when
a GeoIP database is configured (GEOIP_DB: a free DB-IP Lite or MaxMind
GeoLite2 Country .mmdb file, read with the optional `maxminddb` package)."""
import ipaddress
import logging
import time
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import dns.reversename

from .config import settings

log = logging.getLogger("phishlens.enrich")
_cache: dict[str, tuple[float, dict]] = {}
CACHE_SECONDS = 24 * 3600
_geo = None
_geo_loaded = False


def _geo_reader():
    global _geo, _geo_loaded
    if not _geo_loaded:
        _geo_loaded = True
        if settings.GEOIP_DB:
            try:
                import maxminddb
                _geo = maxminddb.open_database(settings.GEOIP_DB)
            except Exception as exc:  # missing package or file: run without countries
                log.warning("GeoIP disabled: %s", exc)
    return _geo


def _country(ip: str) -> str | None:
    reader = _geo_reader()
    if not reader:
        return None
    try:
        rec = reader.get(ip) or {}
    except ValueError:
        return None
    return (rec.get("country") or {}).get("iso_code")


def _ptr(ip: str) -> str | None:
    try:
        ans = dns.resolver.resolve(dns.reversename.from_address(ip), "PTR", lifetime=3)
        return str(ans[0]).rstrip(".").lower()
    except Exception:
        return None


def lookup(ip: str) -> dict:
    now = time.time()
    hit = _cache.get(ip)
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "ptr": None, "country": None}
    info = {"ip": ip, "ptr": _ptr(ip), "country": _country(ip)}
    if len(_cache) > 50_000:
        _cache.clear()
    _cache[ip] = (now, info)
    return info


def lookup_many(ips: list[str], limit: int = 60) -> dict[str, dict]:
    ips = list(dict.fromkeys(i for i in ips if i))[:limit]
    with ThreadPoolExecutor(max_workers=10) as pool:
        return {i["ip"]: i for i in pool.map(lookup, ips)}


def enrich_summary(summary: dict) -> dict:
    """Add reverse DNS / country to each sender's sample IPs, and a hint for
    senders the report alone couldn't name."""
    ips = [ip for row in summary.get("senders", []) for ip in row.get("sample_ips", [])]
    info = lookup_many(ips)
    for row in summary.get("senders", []):
        row["sources"] = [info.get(ip, {"ip": ip, "ptr": None, "country": None}) for ip in row.get("sample_ips", [])]
        if row["sender"].startswith("Unknown"):
            names = [s["ptr"] for s in row["sources"] if s["ptr"]]
            if names:
                row["hint"] = "Reverse DNS: " + ", ".join(dict.fromkeys(".".join(n.split(".")[-2:]) for n in names))
    return summary
