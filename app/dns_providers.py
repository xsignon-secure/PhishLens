"""DNS provider API clients for one-click fixes: Cloudflare, DigitalOcean,
deSEC, GoDaddy and Amazon Route 53. Each needs only a credential that can edit
DNS records (GoDaddy and Route 53 take "KEY:SECRET").

Providers share the record-matching logic in `Provider.upsert`: for TXT, only
the record that starts like the new value (e.g. "v=DMARC1") is replaced, so
unrelated TXT records at the same name (site verification, etc.) are kept."""
import hashlib
import hmac
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import httpx

PROVIDERS = ("cloudflare", "digitalocean", "desec", "godaddy", "route53")
LABELS = {"cloudflare": "Cloudflare", "digitalocean": "DigitalOcean", "desec": "deSEC",
          "godaddy": "GoDaddy", "route53": "Amazon Route 53"}


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


class RRsetProvider(Provider):
    """Providers that store whole RRsets: a record's "id" is its value, and every
    change rewrites the set at that name and type."""

    def _rrset(self, zone, name, rtype) -> list[str]: raise NotImplementedError
    def _put(self, zone, name, rtype, values: list[str]) -> None: raise NotImplementedError

    @staticmethod
    def _fmt(rtype, content):
        if rtype != "TXT":
            return content.rstrip(".") + "."
        # DNS strings are at most 255 bytes; longer TXT values go in several.
        return " ".join(f'"{content[i:i + 255]}"' for i in range(0, max(len(content), 1), 255))

    def records(self, zone_id, name, rtype):
        return [{"id": v, "content": v} for v in self._rrset(zone_id, name, rtype)]

    def _create(self, zone_id, name, rtype, content):
        self._put(zone_id, name, rtype, self._rrset(zone_id, name, rtype) + [self._fmt(rtype, content)])

    def _update(self, zone_id, rec, name, rtype, content):
        vals = [self._fmt(rtype, content) if v == rec["id"] else v for v in self._rrset(zone_id, name, rtype)]
        self._put(zone_id, name, rtype, vals)

    def _delete(self, zone_id, rec, name, rtype):
        self._put(zone_id, name, rtype, [v for v in self._rrset(zone_id, name, rtype) if v != rec["id"]])

    @staticmethod
    def _sub(zone, name):
        name = name.rstrip(".").lower()
        return "" if name == zone else name[: -len(zone) - 1]

    def _domain_exists(self, path):
        def exists(candidate):
            try:
                self._call("GET", path.format(candidate))
                return candidate
            except DnsProviderError:
                return None
        return exists


class Desec(RRsetProvider):
    """deSEC (free, DNSSEC by default)."""
    name = "deSEC"
    api = "https://desec.io/api/v1"

    def _headers(self, token):
        return {"Authorization": f"Token {token}"}

    def verify(self) -> bool:
        self._call("GET", "/domains/")
        return True

    def zone_for(self, name):
        return self._zone_walk(name, self._domain_exists("/domains/{}/"))

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


class GoDaddy(RRsetProvider):
    """GoDaddy. Credential is "API_KEY:API_SECRET". GoDaddy only opens its DNS API
    to accounts with 10+ domains (or a Discount Domain Club plan)."""
    name = "GoDaddy"
    api = "https://api.godaddy.com/v1"

    def _headers(self, token):
        return {"Authorization": f"sso-key {token}"}

    def _check(self, r, body) -> None:
        if r.status_code == 403:
            raise DnsProviderError("GoDaddy refused API access. GoDaddy only allows its DNS API "
                                   "for accounts with 10 or more domains.")
        super()._check(r, body)

    @staticmethod
    def _fmt(rtype, content):
        return content if rtype == "TXT" else content.rstrip(".")

    def verify(self) -> bool:
        self._call("GET", "/domains", params={"limit": 1})
        return True

    def zone_for(self, name):
        return self._zone_walk(name, self._domain_exists("/domains/{}"))

    def _rrset(self, zone, name, rtype):
        recs = self._call("GET", f"/domains/{zone}/records/{rtype}/{self._sub(zone, name) or '@'}")
        return [r.get("data", "") for r in recs] if isinstance(recs, list) else []

    def _put(self, zone, name, rtype, values):
        sub = self._sub(zone, name) or "@"
        if not values:
            self._call("DELETE", f"/domains/{zone}/records/{rtype}/{sub}")
            return
        self._call("PUT", f"/domains/{zone}/records/{rtype}/{sub}",
                   json=[{"data": v, "ttl": 600} for v in values])


R53_NS = "{https://route53.amazonaws.com/doc/2013-04-01/}"


def sigv4_headers(method: str, url: str, body: bytes, key_id: str, secret: str,
                  region: str = "us-east-1", service: str = "route53",
                  now: datetime | None = None) -> dict:
    """AWS Signature Version 4 for one request (host and x-amz-date signed)."""
    t = now or datetime.now(timezone.utc)
    amz_date, day = t.strftime("%Y%m%dT%H%M%SZ"), t.strftime("%Y%m%d")
    parts = urlsplit(url)
    query = "&".join(sorted(
        f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}"
        for k, _, v in (p.partition("=") for p in parts.query.split("&") if p)))
    canonical = "\n".join([method, quote(parts.path or "/", safe="/-_.~"), query,
                           f"host:{parts.netloc}\nx-amz-date:{amz_date}\n", "host;x-amz-date",
                           hashlib.sha256(body).hexdigest()])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = ("AWS4" + secret).encode()
    for part in (day, region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    return {"x-amz-date": amz_date,
            "Authorization": f"AWS4-HMAC-SHA256 Credential={key_id}/{scope}, "
                             f"SignedHeaders=host;x-amz-date, Signature={sig}"}


class Route53(RRsetProvider):
    """Amazon Route 53. Credential is "ACCESS_KEY_ID:SECRET_ACCESS_KEY" for an IAM
    user allowed route53:ListHostedZones*, ListResourceRecordSets and
    ChangeResourceRecordSets."""
    name = "Route 53"
    api = "https://route53.amazonaws.com"

    def __init__(self, token, transport=None):
        self._key, _, self._secret = token.partition(":")
        if not self._key or not self._secret:
            raise DnsProviderError('Route 53 needs "ACCESS_KEY_ID:SECRET_ACCESS_KEY"')
        self._client = httpx.Client(timeout=15, transport=transport)

    def _xml(self, method, path, params: dict | None = None, body: bytes = b""):
        qs = "&".join(f"{quote(k, safe='-_.~')}={quote(str(v), safe='-_.~')}" for k, v in (params or {}).items())
        url = f"{self.api}/2013-04-01{path}" + (f"?{qs}" if qs else "")
        headers = sigv4_headers(method, url, body, self._key, self._secret)
        if body:
            headers["Content-Type"] = "application/xml"
        try:
            r = self._client.request(method, url, content=body or None, headers=headers)
        except httpx.HTTPError as exc:
            raise DnsProviderError(f"Route 53 unreachable: {exc}") from exc
        try:
            root = ET.fromstring(r.content) if r.content else None
        except ET.ParseError:
            root = None
        if r.status_code >= 400:
            msg = root.findtext(f".//{R53_NS}Message") if root is not None else None
            raise DnsProviderError(f"Route 53: {msg or f'HTTP {r.status_code}'}")
        return root

    def verify(self) -> bool:
        self._xml("GET", "/hostedzone", {"maxitems": 1})
        return True

    def zone_for(self, name):
        def exists(candidate):
            root = self._xml("GET", "/hostedzonesbyname", {"dnsname": candidate, "maxitems": 1})
            for z in root.iter(f"{R53_NS}HostedZone"):
                if z.findtext(f"{R53_NS}Name", "").rstrip(".").lower() == candidate:
                    return z.findtext(f"{R53_NS}Id", "").rsplit("/", 1)[-1]
            return None
        return self._zone_walk(name, exists)

    def _rrset(self, zone, name, rtype):
        fqdn = name.rstrip(".").lower() + "."
        root = self._xml("GET", f"/hostedzone/{zone}/rrset", {"name": fqdn, "type": rtype, "maxitems": 1})
        for rs in root.iter(f"{R53_NS}ResourceRecordSet"):
            if rs.findtext(f"{R53_NS}Name", "").lower() == fqdn and rs.findtext(f"{R53_NS}Type") == rtype:
                return [v.text or "" for v in rs.iter(f"{R53_NS}Value")]
        return []

    def _put(self, zone, name, rtype, values):
        fqdn = name.rstrip(".").lower() + "."
        if values:
            action, vals = "UPSERT", values
        else:
            action, vals = "DELETE", self._rrset(zone, name, rtype)
            if not vals:
                return
        req = ET.Element("ChangeResourceRecordSetsRequest", xmlns=R53_NS.strip("{}"))
        change = ET.SubElement(ET.SubElement(ET.SubElement(req, "ChangeBatch"), "Changes"), "Change")
        ET.SubElement(change, "Action").text = action
        rrs = ET.SubElement(change, "ResourceRecordSet")
        ET.SubElement(rrs, "Name").text = fqdn
        ET.SubElement(rrs, "Type").text = rtype
        ET.SubElement(rrs, "TTL").text = "300"
        recs = ET.SubElement(rrs, "ResourceRecords")
        for v in vals:
            ET.SubElement(ET.SubElement(recs, "ResourceRecord"), "Value").text = v
        self._xml("POST", f"/hostedzone/{zone}/rrset", body=ET.tostring(req, xml_declaration=True, encoding="UTF-8"))


def client(provider: str, token: str, transport: httpx.BaseTransport | None = None) -> Provider:
    cls = {"cloudflare": Cloudflare, "digitalocean": DigitalOcean, "desec": Desec,
           "godaddy": GoDaddy, "route53": Route53}.get(provider)
    if not cls:
        raise DnsProviderError(f"Unsupported DNS provider: {provider}")
    return cls(token, transport)
