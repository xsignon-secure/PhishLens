"""DNS provider API clients for one-click fixes: Cloudflare, DigitalOcean and
deSEC. Each needs only a token that can edit DNS records.

Providers share the record-matching logic in `Provider.upsert`: for TXT, only
the record that starts like the new value (e.g. "v=DMARC1") is replaced, so
unrelated TXT records at the same name (site verification, etc.) are kept."""
import httpx

PROVIDERS = ("cloudflare", "digitalocean", "desec")
LABELS = {"cloudflare": "Cloudflare", "digitalocean": "DigitalOcean", "desec": "deSEC"}


class DnsProviderError(Exception):
    pass


def _txt_content(value: str) -> str:
    return value.strip().strip('"')


def _same(rtype: str, current: str, content: str) -> bool:
    if rtype == "TXT":
        return _txt_content(current) == content
    return current.rstrip(".").lower() == content.rstrip(".").lower()


class Provider:
    name = "DNS provider"
    api = ""

    def __init__(self, token: str, transport: httpx.BaseTransport | None = None):
        self._client = httpx.Client(base_url=self.api, timeout=15, transport=transport,
                                    headers=self._headers(token))

    def _headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def _call(self, method: str, path: str, **kw) -> dict:
        try:
            r = self._client.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise DnsProviderError(f"{self.name} unreachable: {exc}") from exc
        try:
            body = r.json() if r.content else {}
        except ValueError:
            body = {}
        self._check(r, body)
        return body

    def _check(self, r: httpx.Response, body) -> None:
        if r.status_code >= 400:
            msg = body.get("message") or body.get("detail") if isinstance(body, dict) else None
            raise DnsProviderError(f"{self.name}: {msg or f'HTTP {r.status_code}'}")

    # Subclasses implement these. Records are dicts with "id" and "content".
    def verify(self) -> bool: raise NotImplementedError
    def zone_for(self, name: str) -> tuple[str, str]: raise NotImplementedError
    def records(self, zone_id: str, name: str, rtype: str) -> list[dict]: raise NotImplementedError
    def _create(self, zone_id: str, name: str, rtype: str, content: str) -> None: raise NotImplementedError
    def _update(self, zone_id: str, rec: dict, name: str, rtype: str, content: str) -> None: raise NotImplementedError
    def _delete(self, zone_id: str, rec: dict, name: str, rtype: str) -> None: raise NotImplementedError

    def _zone_walk(self, name: str, exists) -> tuple[str, str]:
        labels = name.rstrip(".").lower().split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            zone_id = exists(candidate)
            if zone_id:
                return zone_id, candidate
        raise DnsProviderError(f"No zone for {name} in this {self.name} account (or the token can't see it)")

    def upsert(self, zone_id: str, name: str, rtype: str, content: str,
               match_prefix: str | None = None) -> str:
        """Create or replace one record. Returns "created", "updated" or "unchanged"."""
        if rtype == "TXT":
            content = _txt_content(content)
        existing = self.records(zone_id, name, rtype)
        if rtype == "TXT":
            prefix = (match_prefix or content.split(";")[0].split()[0]).lower()
            existing = [r for r in existing if _txt_content(r.get("content", "")).lower().startswith(prefix)]
        if existing:
            if _same(rtype, existing[0].get("content", ""), content) and len(existing) == 1:
                return "unchanged"
            self._update(zone_id, existing[0], name, rtype, content)
            for extra in existing[1:]:  # e.g. two SPF records: keep exactly one
                self._delete(zone_id, extra, name, rtype)
            return "updated"
        self._create(zone_id, name, rtype, content)
        return "created"

    def delete(self, zone_id: str, name: str, rtype: str) -> int:
        recs = self.records(zone_id, name, rtype)
        for rec in recs:
            self._delete(zone_id, rec, name, rtype)
        return len(recs)


class Cloudflare(Provider):
    name = "Cloudflare"
    api = "https://api.cloudflare.com/client/v4"

    def _check(self, r, body) -> None:
        if r.status_code >= 400 or not body.get("success", False):
            errors = body.get("errors") or [{"message": f"HTTP {r.status_code}"}]
            raise DnsProviderError("Cloudflare: " + "; ".join(str(e.get("message")) for e in errors))

    def verify(self) -> bool:
        return self._call("GET", "/user/tokens/verify").get("result", {}).get("status") == "active"

    def zone_for(self, name: str) -> tuple[str, str]:
        def exists(candidate):
            zones = self._call("GET", "/zones", params={"name": candidate}).get("result") or []
            return zones[0]["id"] if zones else None
        return self._zone_walk(name, exists)

    def records(self, zone_id, name, rtype):
        return self._call("GET", f"/zones/{zone_id}/dns_records",
                          params={"name": name, "type": rtype, "per_page": 100}).get("result") or []

    def _body(self, name, rtype, content):
        body = {"type": rtype, "name": name, "content": content, "ttl": 300}
        if rtype == "CNAME":
            body["proxied"] = False
        return body

    def _create(self, zone_id, name, rtype, content):
        self._call("POST", f"/zones/{zone_id}/dns_records", json=self._body(name, rtype, content))

    def _update(self, zone_id, rec, name, rtype, content):
        self._call("PUT", f"/zones/{zone_id}/dns_records/{rec['id']}", json=self._body(name, rtype, content))

    def _delete(self, zone_id, rec, name, rtype):
        self._call("DELETE", f"/zones/{zone_id}/dns_records/{rec['id']}")


class DigitalOcean(Provider):
    """DigitalOcean DNS. Record names are relative to the domain ("@" = apex)."""
    name = "DigitalOcean"
    api = "https://api.digitalocean.com/v2"

    def verify(self) -> bool:
        return self._call("GET", "/account").get("account", {}).get("status") == "active"

    def zone_for(self, name):
        def exists(candidate):
            try:
                self._call("GET", f"/domains/{candidate}")
                return candidate
            except DnsProviderError:
                return None
        return self._zone_walk(name, exists)

    @staticmethod
    def _rel(zone, name):
        name = name.rstrip(".").lower()
        return "@" if name == zone else name[: -len(zone) - 1]

    def records(self, zone_id, name, rtype):
        recs = self._call("GET", f"/domains/{zone_id}/records",
                          params={"name": name.rstrip("."), "type": rtype, "per_page": 200}).get("domain_records") or []
        return [{"id": r["id"], "content": r.get("data", "")} for r in recs]

    def _body(self, zone_id, name, rtype, content):
        data = content if rtype == "TXT" else content.rstrip(".") + "."
        return {"type": rtype, "name": self._rel(zone_id, name), "data": data, "ttl": 300}

    def _create(self, zone_id, name, rtype, content):
        self._call("POST", f"/domains/{zone_id}/records", json=self._body(zone_id, name, rtype, content))

    def _update(self, zone_id, rec, name, rtype, content):
        self._call("PUT", f"/domains/{zone_id}/records/{rec['id']}", json=self._body(zone_id, name, rtype, content))

    def _delete(self, zone_id, rec, name, rtype):
        self._call("DELETE", f"/domains/{zone_id}/records/{rec['id']}")


class Desec(Provider):
    """deSEC (free, DNSSEC by default). It stores RRsets, so a record's "id" is
    its value and changes rewrite the whole set."""
    name = "deSEC"
    api = "https://desec.io/api/v1"

    def _headers(self, token):
        return {"Authorization": f"Token {token}"}

    def verify(self) -> bool:
        self._call("GET", "/domains/")
        return True

    def zone_for(self, name):
        def exists(candidate):
            try:
                self._call("GET", f"/domains/{candidate}/")
                return candidate
            except DnsProviderError:
                return None
        return self._zone_walk(name, exists)

    @staticmethod
    def _sub(zone, name):
        name = name.rstrip(".").lower()
        return "" if name == zone else name[: -len(zone) - 1]

    def _rrset(self, zone, name, rtype) -> list[str]:
        try:
            return self._call("GET", f"/domains/{zone}/rrsets/{self._sub(zone, name) or '@'}/{rtype}/").get("records") or []
        except DnsProviderError as exc:
            if "404" in str(exc) or "Not found" in str(exc):
                return []
            raise

    def _put(self, zone, name, rtype, values: list[str]) -> None:
        self._call("PUT", f"/domains/{zone}/rrsets/", json=[
            {"subname": self._sub(zone, name), "type": rtype, "ttl": 3600, "records": values}])

    @staticmethod
    def _fmt(rtype, content):
        return f'"{content}"' if rtype == "TXT" else content.rstrip(".") + "."

    def records(self, zone_id, name, rtype):
        return [{"id": v, "content": v} for v in self._rrset(zone_id, name, rtype)]

    def _create(self, zone_id, name, rtype, content):
        self._put(zone_id, name, rtype, self._rrset(zone_id, name, rtype) + [self._fmt(rtype, content)])

    def _update(self, zone_id, rec, name, rtype, content):
        vals = [self._fmt(rtype, content) if v == rec["id"] else v for v in self._rrset(zone_id, name, rtype)]
        self._put(zone_id, name, rtype, vals)

    def _delete(self, zone_id, rec, name, rtype):
        self._put(zone_id, name, rtype, [v for v in self._rrset(zone_id, name, rtype) if v != rec["id"]])


def client(provider: str, token: str, transport: httpx.BaseTransport | None = None) -> Provider:
    cls = {"cloudflare": Cloudflare, "digitalocean": DigitalOcean, "desec": Desec}.get(provider)
    if not cls:
        raise DnsProviderError(f"Unsupported DNS provider: {provider}")
    return cls(token, transport)
