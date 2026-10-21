"""Email header analyzer: paste a message's headers, see whether it is genuine.

Reads the receiving server's Authentication-Results (SPF / DKIM / DMARC), the
DKIM signature, the Received chain, and the From / Reply-To / Return-Path
identities, then flags the patterns phishing relies on. Nothing is stored.
"""
import re
from email import policy
from email.parser import HeaderParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

MAX_HEADER_BYTES = 256 * 1024

_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)", re.I)
_DKIM_D_RE = re.compile(r"\bheader\.d\s*=\s*([^\s;]+)", re.I)
_DKIM_I_RE = re.compile(r"\bheader\.i\s*=\s*@?([^\s;]+)", re.I)
_SMTP_MAILFROM_RE = re.compile(r"\bsmtp\.mailfrom\s*=\s*([^\s;]+)", re.I)
_FROM_HOST_RE = re.compile(r"^\s*from\s+(\S+)(?:\s+\(([^)]*)\))?", re.I)
_BY_HOST_RE = re.compile(r"\bby\s+(\S+)", re.I)
_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]*:[0-9a-f:]+)\]?", re.I)


def _domain_of(address: str) -> str:
    addr = parseaddr(address or "")[1]
    return addr.rsplit("@", 1)[-1].lower().strip(">").rstrip(".") if "@" in addr else ""


def _org(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _parse_auth_results(values: list[str]) -> dict:
    """Use the topmost Authentication-Results header: it is the one added by
    the recipient's own server. Lower ones can be forged by the sender."""
    out = {"spf": None, "dkim": None, "dmarc": None, "arc": None,
           "dkim_domain": None, "mailfrom": None, "raw": None}
    if not values:
        return out
    top = " ".join(values[0].split())
    out["raw"] = top[:1000]
    for key, val in _RESULT_RE.findall(top):
        key = key.lower()
        if out[key] is None or (key == "dkim" and val.lower() == "pass"):
            out[key] = val.lower()
    m = _DKIM_D_RE.search(top) or _DKIM_I_RE.search(top)
    if m:
        out["dkim_domain"] = m.group(1).lower().rstrip(".")
    m = _SMTP_MAILFROM_RE.search(top)
    if m:
        out["mailfrom"] = m.group(1).lower().rsplit("@", 1)[-1]
    return out


def _dkim_signatures(values: list[str]) -> list[dict]:
    sigs = []
    for v in values[:5]:
        tags = {}
        for part in " ".join(v.split()).split(";"):
            if "=" in part:
                k, _, val = part.strip().partition("=")
                tags[k.strip().lower()] = val.strip()
        sigs.append({"domain": tags.get("d", "").lower(), "selector": tags.get("s", ""),
                     "algorithm": tags.get("a", "")})
    return sigs


def _hops(received: list[str]) -> list[dict]:
    hops = []
    # Received headers are prepended, so the list runs newest-first; reverse
    # it to show the path the message actually took.
    for raw in reversed(received[:40]):
        text = " ".join(raw.split())
        stamp = None
        if ";" in text:
            try:
                stamp = parsedate_to_datetime(text.rsplit(";", 1)[1].strip())
            except (TypeError, ValueError, IndexError):
                stamp = None
        m_from, m_by = _FROM_HOST_RE.search(text), _BY_HOST_RE.search(text)
        ip = None
        if m_from and m_from.group(2):
            m_ip = _IP_RE.search(m_from.group(2))
            ip = m_ip.group(1) if m_ip else None
        hops.append({"from": m_from.group(1) if m_from else None,
                     "by": m_by.group(1) if m_by else None, "ip": ip,
                     "at": stamp.isoformat() if stamp else None, "_ts": stamp})
    prev = None
    for h in hops:
        ts = h.pop("_ts")
        delay = None
        if ts and prev:
            try:
                delay = int((ts - prev).total_seconds())
            except TypeError:  # naive vs aware timestamps
                delay = None
        h["delay_seconds"] = delay
        prev = ts or prev
    return hops


def analyze(raw: str) -> dict:
    if not raw or not raw.strip():
        raise ValueError("Paste the message headers first")
    if len(raw.encode("utf-8", "ignore")) > MAX_HEADER_BYTES:
        raise ValueError("That's too long for headers (256 KB max)")
    # Pasted text often has the body too: headers end at the first blank line.
    text = raw.replace("\r\n", "\n").lstrip("\n")
    head = text.split("\n\n", 1)[0]
    msg = HeaderParser(policy=policy.compat32).parsestr(head + "\n\n", headersonly=True)
    if not msg.keys():
        raise ValueError("No email headers found in that text")

    from_hdr = str(msg.get("From", ""))
    from_name, from_addr = parseaddr(from_hdr)
    from_domain = _domain_of(from_hdr)
    reply_to = [a for _, a in getaddresses(msg.get_all("Reply-To", []))]
    return_path = str(msg.get("Return-Path", "")).strip()
    rp_domain = _domain_of(return_path)
    auth = _parse_auth_results(msg.get_all("Authentication-Results", []))
    sigs = _dkim_signatures(msg.get_all("DKIM-Signature", []))
    hops = _hops(msg.get_all("Received", []))

    findings = []

    def add(level, text):
        findings.append({"level": level, "text": text})

    if auth["raw"] is None:
        add("warn", "No Authentication-Results header: the receiving server's SPF/DKIM/DMARC "
                    "verdict isn't in what you pasted. Copy the full original headers.")
    else:
        dmarc = auth["dmarc"]
        if dmarc == "pass":
            add("pass", f"DMARC passed: the message really came from a sender authorised by {from_domain}.")
        elif dmarc in ("fail", "permerror"):
            add("fail", f"DMARC failed: this message was not sent by an authorised sender for "
                        f"{from_domain}. Treat it as spoofed.")
        elif dmarc in (None, "none", "bestguesspass"):
            add("warn", f"No DMARC verdict: {from_domain or 'the sender'} has no enforced DMARC policy, "
                        "so a forged From address would not be caught.")
        for key in ("spf", "dkim"):
            val = auth[key]
            if val in ("fail", "softfail", "permerror", "temperror"):
                add("warn", f"{key.upper()} result: {val}.")
            elif val is None:
                add("warn", f"No {key.upper()} result recorded.")
        if auth["dkim"] == "pass" and auth["dkim_domain"] and from_domain \
                and _org(auth["dkim_domain"]) != _org(from_domain):
            add("warn", f"DKIM passed for {auth['dkim_domain']}, not for {from_domain}: the signature "
                        "doesn't vouch for the visible sender.")

    for addr in reply_to:
        rd = addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""
        if rd and from_domain and _org(rd) != _org(from_domain):
            add("fail", f"Reply-To goes to {addr}, a different domain from the sender ({from_domain}). "
                        "Replies would reach someone else: a classic phishing setup.")
    if rp_domain and from_domain and _org(rp_domain) != _org(from_domain):
        add("info", f"Bounce address (Return-Path) is at {rp_domain}. Normal for mailing services; "
                    "suspicious if the sender claims to be writing personally.")
    embedded = re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", from_name or "")
    if any(e.lower() != from_addr.lower() for e in embedded):
        add("fail", f"The display name shows an address ({embedded[0]}) that isn't the real sender "
                    f"({from_addr}). This hides the true sender in most mail apps.")
    if from_domain.startswith("xn--") or ".xn--" in from_domain:
        add("warn", f"Sender domain {from_domain} uses international characters (punycode); "
                    "check it isn't imitating a familiar name.")
    slow = [h for h in hops if (h["delay_seconds"] or 0) > 3600]
    if slow:
        add("info", f"{len(slow)} hop(s) took over an hour. Usually greylisting or a queue, not an attack.")

    level = "pass"
    if any(f["level"] == "fail" for f in findings):
        level = "fail"
    elif any(f["level"] == "warn" for f in findings):
        level = "warn"
    verdict = {"pass": "Looks authentic", "warn": "Could not be fully verified",
               "fail": "Likely spoofed or phishing"}[level]
    return {
        "verdict": verdict, "level": level,
        "from": {"name": from_name, "address": from_addr, "domain": from_domain},
        "reply_to": reply_to, "return_path": return_path or None,
        "subject": str(msg.get("Subject", ""))[:300], "date": str(msg.get("Date", "")) or None,
        "message_id": str(msg.get("Message-ID", "")) or None,
        "authentication": {k: auth[k] for k in ("spf", "dkim", "dmarc", "arc", "dkim_domain", "mailfrom")},
        "dkim_signatures": sigs, "hops": hops, "findings": findings,
    }
