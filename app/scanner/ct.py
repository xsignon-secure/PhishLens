"""Certificate Transparency monitoring through crt.sh.

Every public TLS certificate is logged in CT logs. Two things are worth an
alert for a monitored domain:

- a certificate for the domain (or a subdomain) from a certificate authority
  it has never used before: possibly a mis-issued or attacker-obtained
  certificate (CAA records stop this);
- a certificate for a registered lookalike domain: someone is putting a
  phishing site on HTTPS.

The first check records a baseline; later checks alert only on new
certificates."""
from datetime import datetime

import httpx

CRT_SH = "https://crt.sh/"
TIMEOUT = 25
MAX_LOOKALIKES = 10


class CtError(Exception):
    pass


def _issuer(raw: str) -> str:
    """The organisation (O=) or common name (CN=) of an issuer DN."""
    parts = dict(p.strip().split("=", 1) for p in raw.split(",") if "=" in p)
    return parts.get("O") or parts.get("CN") or raw.strip()


def fetch(query: str, transport: httpx.BaseTransport | None = None) -> list[dict]:
    """Unexpired certificates crt.sh knows for `query` (e.g. "%.example.com")."""
    try:
        with httpx.Client(timeout=TIMEOUT, transport=transport, follow_redirects=True,
                          headers={"User-Agent": "PhishLens CT monitor"}) as c:
            r = c.get(CRT_SH, params={"q": query, "output": "json", "exclude": "expired"})
    except httpx.HTTPError as exc:
        raise CtError(f"crt.sh unreachable: {exc}") from exc
    if r.status_code != 200:
        raise CtError(f"crt.sh returned HTTP {r.status_code}")
    try:
        rows = r.json() if r.content else []
    except ValueError:
        raise CtError("crt.sh returned something that isn't JSON")
    out = {}
    for row in rows if isinstance(rows, list) else []:
        cid = row.get("id")
        if not isinstance(cid, int) or cid in out:
            continue
        out[cid] = {"id": cid, "issuer": _issuer(row.get("issuer_name") or ""),
                    "names": sorted({n.strip().lower() for n in (row.get("name_value") or "").split("\n")
                                     if n.strip()})[:20],
                    "not_before": row.get("not_before"), "not_after": row.get("not_after")}
    return sorted(out.values(), key=lambda c: c["id"])


def check(domain: str, state: dict | None, lookalikes: list[str] | None,
          transport: httpx.BaseTransport | None = None) -> tuple[dict, list[str]]:
    """Compare CT logs with the saved state. Returns (new state, alert
    messages). state = {issuers: [...], max_id: int, lookalike_max_id: {domain: int}}."""
    first = not state
    state = dict(state or {})
    issuers = set(state.get("issuers") or [])
    messages = []
    own = fetch(f"%.{domain}", transport) + fetch(domain, transport)
    max_id = state.get("max_id") or 0
    new_own = [c for c in own if c["id"] > max_id]
    unexpected = {}
    for c in new_own:
        if not first and issuers and c["issuer"] not in issuers:
            unexpected.setdefault(c["issuer"], []).extend(c["names"])
        issuers.add(c["issuer"])
    for issuer, names in unexpected.items():
        names = sorted(set(names))
        messages.append(f"{domain}: certificate issued by {issuer}, a certificate authority this domain hasn't "
                        f"used before, for {', '.join(names[:5])}{' and more' if len(names) > 5 else ''}. "
                        "If you didn't request it, revoke it and add a CAA record.")
    state["issuers"] = sorted(issuers)
    state["max_id"] = max([max_id] + [c["id"] for c in own])
    seen = dict(state.get("lookalike_max_id") or {})
    for look in (lookalikes or [])[:MAX_LOOKALIKES]:
        try:
            certs = fetch(look, transport)
        except CtError:
            continue
        prev = seen.get(look)
        newest = max([c["id"] for c in certs] or [prev or 0])
        if prev is not None and any(c["id"] > prev for c in certs):
            messages.append(f"{domain}: a TLS certificate was issued for lookalike domain {look}: "
                            "a phishing site may be going live on it. Consider a takedown request.")
        seen[look] = newest
    state["lookalike_max_id"] = seen
    state["checked_at"] = datetime.utcnow().isoformat() + "Z"
    return state, messages
