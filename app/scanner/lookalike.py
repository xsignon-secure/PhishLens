"""Lookalike (typosquat) domain detection.

Generates the spellings an attacker would register to impersonate a brand
(missing / doubled / swapped letters, keyboard slips, look-alike characters,
hyphens, other TLDs) and checks which of them exist in DNS. A lookalike with
MX records can send and receive mail, so it is the one to act on first.

DNS lookups only: nothing connects to the candidate domains.
"""
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

MAX_CANDIDATES = 400
WORKERS = 32
LOOKUP_TIMEOUT = 2.5

# Second-level public suffixes common enough to matter. A full Public Suffix
# List would be more exact, but would add a dependency for little gain here.
_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "co.nz", "org.nz", "co.in", "net.in", "org.in",
    "co.jp", "ne.jp", "com.br", "com.mx", "com.sg", "com.my", "co.za", "com.tr",
    "com.cn", "com.hk", "co.kr", "com.ar", "com.co", "co.id", "com.ph", "com.vn",
    "com.pk", "com.ng", "co.il", "com.sa", "com.eg", "co.th", "com.tw",
}

ALT_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "us", "app", "online",
            "site", "xyz", "top", "shop", "live", "support", "cloud", "email", "me"]

_KEYBOARD = {
    "q": "wa", "w": "qeas", "e": "wrsd", "r": "etdf", "t": "ryfg", "y": "tugh",
    "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol", "a": "qwsz", "s": "awedxz",
    "d": "serfcx", "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "j": "huikmn",
    "k": "jiolm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
    "1": "2q", "2": "13w", "3": "24e", "4": "35r", "5": "46t", "6": "57y",
    "7": "68u", "8": "79i", "9": "80o", "0": "9p",
}

# ASCII look-alikes. Unicode homoglyphs (Cyrillic "а" etc.) register as
# punycode xn-- names and are covered by most registries' IDN rules.
_HOMOGLYPHS = {
    "a": ["4"], "b": ["d", "6"], "d": ["b", "cl"], "e": ["3"], "g": ["q", "9"],
    "i": ["1", "l"], "l": ["1", "i"], "m": ["rn", "nn"], "n": ["m", "r"],
    "o": ["0"], "q": ["g"], "s": ["5"], "t": ["7"], "u": ["v"], "v": ["u"],
    "w": ["vv"], "z": ["2"], "0": ["o"], "1": ["l", "i"],
}
_MULTI_GLYPHS = {"rn": "m", "vv": "w", "cl": "d", "nn": "m"}

_VOWELS = "aeiou"


def split_domain(domain: str) -> tuple[str, str]:
    """("example", "co.uk") for example.co.uk; subdomains are dropped."""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return labels[0], ""


def _label_ok(label: str) -> bool:
    if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
        return False
    if "--" in label[2:4]:  # reserved for xn-- style labels
        return False
    return all(c.isalnum() or c == "-" for c in label) and label.isascii()


def _label_variants(name: str) -> dict[str, str]:
    """Variant label -> technique that produced it."""
    out: dict[str, str] = {}

    def add(label: str, kind: str):
        if label != name and _label_ok(label) and label not in out:
            out[label] = kind

    n = len(name)
    for i in range(n):
        add(name[:i] + name[i + 1:], "omission")
        add(name[:i] + name[i] + name[i:], "repetition")
        for c in _KEYBOARD.get(name[i], ""):
            add(name[:i] + c + name[i + 1:], "keyboard typo")
            add(name[:i] + c + name[i:], "insertion")
        for g in _HOMOGLYPHS.get(name[i], []):
            add(name[:i] + g + name[i + 1:], "homoglyph")
        if name[i] in _VOWELS:
            for v in _VOWELS:
                add(name[:i] + v + name[i + 1:], "vowel swap")
        if i < n - 1:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:], "transposition")
        if 0 < i < n:
            add(name[:i] + "-" + name[i:], "hyphenation")
    for multi, single in _MULTI_GLYPHS.items():
        if multi in name:
            add(name.replace(multi, single), "homoglyph")
    for word in ("login", "secure", "mail", "support", "account", "verify", "my", "online"):
        add(f"{name}-{word}", "brand + keyword")
        add(f"{word}-{name}", "brand + keyword")
        add(f"{name}{word}", "brand + keyword")
    return out


def generate(domain: str, limit: int = MAX_CANDIDATES) -> list[dict]:
    """Candidate lookalikes, most convincing techniques first."""
    name, suffix = split_domain(domain)
    if not suffix:
        return []
    original = f"{name}.{suffix}"
    seen = {original}
    out: list[dict] = []

    def push(candidate: str, kind: str):
        if candidate not in seen and len(candidate) <= 253:
            seen.add(candidate)
            out.append({"domain": candidate, "technique": kind})

    order = ["homoglyph", "omission", "transposition", "repetition", "hyphenation",
             "vowel swap", "keyboard typo", "brand + keyword", "insertion"]
    variants = _label_variants(name)
    for tld in ALT_TLDS:
        if tld != suffix:
            push(f"{name}.{tld}", "other TLD")
    for kind in order:
        for label, k in variants.items():
            if k == kind:
                push(f"{label}.{suffix}", kind)
    push(f"{name}{suffix.replace('.', '')}.com", "TLD in name")
    push(f"www{name}.{suffix}", "missing dot")
    return out[:limit]


def _resolve(resolver, name: str, rtype: str) -> list[str]:
    try:
        return [r.to_text() for r in resolver.resolve(name, rtype, lifetime=LOOKUP_TIMEOUT)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.name.LabelTooLong, dns.name.EmptyLabel, ValueError):
        return []
    except Exception:
        return []


def _probe(resolver, candidate: dict) -> dict | None:
    name = candidate["domain"]
    ns = _resolve(resolver, name, "NS")
    a = _resolve(resolver, name, "A")
    if not ns and not a:
        return None
    mx = _resolve(resolver, name, "MX")
    mx_hosts = sorted({m.split()[-1].rstrip(".") for m in mx if m.split()})
    # A null MX ("0 .") explicitly refuses mail.
    mx_hosts = [h for h in mx_hosts if h]
    risk = "high" if mx_hosts else "medium" if a else "low"
    return {**candidate, "registered": True, "has_web": bool(a), "mx": mx_hosts[:3],
            "ips": a[:3], "risk": risk}


def scan(domain: str, resolver=None, limit: int = MAX_CANDIDATES) -> dict:
    """Probe candidate lookalikes; returns the registered ones, riskiest first."""
    from .dns_checks import _resolver as default_resolver

    resolver = resolver or default_resolver
    candidates = generate(domain, limit)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        found = [r for r in pool.map(lambda c: _probe(resolver, c), candidates) if r]
    rank = {"high": 0, "medium": 1, "low": 2}
    found.sort(key=lambda r: (rank[r["risk"]], r["domain"]))
    return {"domain": domain, "checked": len(candidates), "registered": found,
            "high_risk": sum(1 for r in found if r["risk"] == "high")}
