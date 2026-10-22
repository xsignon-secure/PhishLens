"""DNS provider API clients. Cloudflare only for now (it's the provider most
small and mid-size customers use, and its API tokens can be scoped to one
zone with DNS:Edit, which is all this needs)."""
import httpx

API = "https://api.cloudflare.com/client/v4"


class DnsProviderError(Exception):
    pass


def _txt_content(value: str) -> str:
    return value.strip().strip('"')


class Cloudflare:
    def __init__(self, token: str, transport: httpx.BaseTransport | None = None):
        self._client = httpx.Client(base_url=API, timeout=15, transport=transport,
                                    headers={"Authorization": f"Bearer {token}"})

    def _call(self, method: str, path: str, **kw) -> dict:
        try:
            r = self._client.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise DnsProviderError(f"Cloudflare unreachable: {exc}") from exc
        try:
            body = r.json()
        except ValueError:
            body = {}
        if r.status_code >= 400 or not body.get("success", False):
            errors = body.get("errors") or [{"message": f"HTTP {r.status_code}"}]
            raise DnsProviderError("Cloudflare: " + "; ".join(str(e.get("message")) for e in errors))
        return body

    def verify(self) -> bool:
        return self._call("GET", "/user/tokens/verify").get("result", {}).get("status") == "active"

    def zone_for(self, name: str) -> tuple[str, str]:
        """(zone id, zone name) of the zone that holds `name`."""
        labels = name.rstrip(".").lower().split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            zones = self._call("GET", "/zones", params={"name": candidate}).get("result") or []
            if zones:
                return zones[0]["id"], zones[0]["name"]
        raise DnsProviderError(f"No zone for {name} in this Cloudflare account (or the token can't see it)")

    def records(self, zone_id: str, name: str, rtype: str) -> list[dict]:
        return self._call("GET", f"/zones/{zone_id}/dns_records",
                          params={"name": name, "type": rtype, "per_page": 100}).get("result") or []

    def upsert(self, zone_id: str, name: str, rtype: str, content: str,
               match_prefix: str | None = None) -> str:
        """Create or replace one record. For TXT, `match_prefix` (e.g.
        "v=DMARC1") picks which existing TXT record to replace, so unrelated
        TXT records at the same name (site verification, etc.) are kept.
        Returns "created", "updated" or "unchanged"."""
        if rtype == "TXT":
            content = _txt_content(content)
        existing = self.records(zone_id, name, rtype)
        if rtype == "TXT":
            prefix = (match_prefix or content.split(";")[0].split()[0]).lower()
            existing = [r for r in existing if _txt_content(r.get("content", "")).lower().startswith(prefix)]
        body = {"type": rtype, "name": name, "content": content, "ttl": 300}
        if rtype == "CNAME":
            body["proxied"] = False
        if existing:
            rec = existing[0]
            current = rec.get("content", "")
            same = (_txt_content(current) == content if rtype == "TXT"
                    else current.rstrip(".").lower() == content.rstrip(".").lower())
            if same and len(existing) == 1:
                return "unchanged"
            self._call("PUT", f"/zones/{zone_id}/dns_records/{rec['id']}", json=body)
            for extra in existing[1:]:  # e.g. two SPF records: keep exactly one
                self._call("DELETE", f"/zones/{zone_id}/dns_records/{extra['id']}")
            return "updated"
        self._call("POST", f"/zones/{zone_id}/dns_records", json=body)
        return "created"

    def delete(self, zone_id: str, name: str, rtype: str) -> int:
        recs = self.records(zone_id, name, rtype)
        for rec in recs:
            self._call("DELETE", f"/zones/{zone_id}/dns_records/{rec['id']}")
        return len(recs)
