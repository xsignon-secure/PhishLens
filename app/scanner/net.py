"""Outbound-connection guard shared by the scanner checks.

The domain under scan is attacker-controllable input, and so is everything it
publishes (MX hosts, BIMI logo URLs, HTTP redirects). Every host the scanner
connects to must resolve only to globally routable addresses, otherwise a
scan could be used to probe the server's internal network (SSRF).
"""
import ipaddress
import socket
import urllib.parse

import httpx

MAX_REDIRECTS = 5


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def is_public_host(host: str) -> bool:
    """True if `host` resolves, and every address it resolves to is public."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    ips = {info[4][0] for info in infos}
    return bool(ips) and all(is_public_ip(ip) for ip in ips)


def safe_get(url: str, timeout: float, **kwargs) -> httpx.Response:
    """GET that follows redirects manually, refusing any hop to a non-public host."""
    for _ in range(MAX_REDIRECTS + 1):
        parts = urllib.parse.urlparse(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError("unsupported URL scheme")
        if not is_public_host(parts.hostname or ""):
            raise ValueError(f"refusing to fetch non-public host {parts.hostname!r}")
        r = httpx.get(url, timeout=timeout, follow_redirects=False, **kwargs)
        if r.is_redirect and "location" in r.headers:
            url = urllib.parse.urljoin(url, r.headers["location"])
            continue
        return r
    raise ValueError("too many redirects")


def safe_fetch_head(url: str, timeout: float, limit: int = 4096) -> tuple[int, bytes]:
    """Like safe_get, but streams and keeps only the first `limit` bytes of the body."""
    for _ in range(MAX_REDIRECTS + 1):
        parts = urllib.parse.urlparse(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError("unsupported URL scheme")
        if not is_public_host(parts.hostname or ""):
            raise ValueError(f"refusing to fetch non-public host {parts.hostname!r}")
        with httpx.stream("GET", url, timeout=timeout, follow_redirects=False) as r:
            if r.is_redirect and "location" in r.headers:
                url = urllib.parse.urljoin(url, r.headers["location"])
                continue
            head = b""
            for chunk in r.iter_bytes(4096):
                head += chunk
                if len(head) >= limit:
                    break
            return r.status_code, head[:limit]
    raise ValueError("too many redirects")
