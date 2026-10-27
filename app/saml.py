"""Single sign-on with SAML 2.0 (ADFS, Entra ID, Okta, Google Workspace,
OneLogin, JumpCloud, PingFederate, Shibboleth...).

SP-initiated Web SSO: HTTP-Redirect binding for the AuthnRequest, HTTP-POST
binding for the Response. The tenant gives us its IdP metadata (or entity ID,
SSO URL and signing certificate); we give the IdP our metadata URL.

Signatures are checked with signxml against the configured certificate only.
To block signature-wrapping attacks, the signature must sit directly on the
Response or on the single Assertion, and only the element the signature
actually covers is read. Encrypted assertions aren't supported: turn off
assertion encryption in the IdP (the connection is HTTPS anyway).
"""
import base64
import re
import secrets
import time
import urllib.parse
import zlib
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape, quoteattr

from cryptography import x509
from jose import jwt
from jose.exceptions import JWTError
from lxml import etree
from signxml import InvalidInput, InvalidSignature, SignatureConfiguration, XMLVerifier

from .config import settings

STATE_TTL = 600
SKEW = timedelta(minutes=3)
NS = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol", "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
      "md": "urn:oasis:names:tc:SAML:2.0:metadata", "ds": "http://www.w3.org/2000/09/xmldsig#"}
EMAIL_ATTRS = ("email", "mail", "emailaddress", "Email", "EmailAddress", "User.Email",
               "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
               "urn:oid:0.9.2342.19200300.100.1.3")
_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, remove_comments=True)


class SamlError(Exception):
    pass


def sp_entity_id() -> str:
    return f"{settings.APP_URL}/api/auth/saml/metadata"


def acs_url() -> str:
    return f"{settings.APP_URL}/api/auth/saml/acs"


def sp_metadata() -> str:
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<md:EntityDescriptor xmlns:md="{NS["md"]}" entityID={quoteattr(sp_entity_id())}>'
            f'<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
            f'protocolSupportEnumeration="{NS["samlp"]}">'
            f'<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>'
            f'<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            f'Location={quoteattr(acs_url())} index="0" isDefault="true"/>'
            f'</md:SPSSODescriptor></md:EntityDescriptor>')


def _parse(xml: bytes | str) -> etree._Element:
    try:
        return etree.fromstring(xml.encode() if isinstance(xml, str) else xml, parser=_PARSER)
    except etree.XMLSyntaxError as exc:
        raise SamlError("That isn't valid XML") from exc


def load_cert(pem_or_b64: str) -> str:
    """Normalise a certificate (PEM, or the bare base64 found in metadata) to PEM."""
    text = pem_or_b64.strip()
    if "BEGIN CERTIFICATE" not in text:
        body = "".join(text.split())
        text = "-----BEGIN CERTIFICATE-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + \
               "\n-----END CERTIFICATE-----\n"
    try:
        x509.load_pem_x509_certificate(text.encode())
    except ValueError as exc:
        raise SamlError("The signing certificate couldn't be read") from exc
    return text


def parse_metadata(xml: str) -> dict:
    """entity_id, sso_url (HTTP-Redirect) and signing certificate from IdP metadata."""
    root = _parse(xml)
    ed = root if root.tag == f"{{{NS['md']}}}EntityDescriptor" else root.find(".//md:EntityDescriptor", NS)
    if ed is None:
        raise SamlError("No EntityDescriptor in the metadata")
    idp = ed.find("md:IDPSSODescriptor", NS)
    if idp is None:
        raise SamlError("The metadata has no identity provider section")
    sso_url = next((s.get("Location") for s in idp.findall("md:SingleSignOnService", NS)
                    if s.get("Binding", "").endswith("HTTP-Redirect")), None)
    if not sso_url:
        raise SamlError("The identity provider has no HTTP-Redirect sign-in URL")
    certs = [kd.findtext(".//ds:X509Certificate", namespaces=NS) for kd in idp.findall("md:KeyDescriptor", NS)
             if kd.get("use") in (None, "signing")]
    certs = [c for c in certs if c]
    if not certs:
        raise SamlError("The metadata has no signing certificate")
    return {"entity_id": ed.get("entityID"), "sso_url": sso_url, "certificate": load_cert(certs[0])}


# ------------------------------------------------------------------ AuthnRequest
def start(tenant) -> tuple[str, str]:
    """Returns (IdP redirect URL, signed state cookie value)."""
    req_id = "_" + secrets.token_hex(20)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="{req_id}" '
           f'Version="2.0" IssueInstant="{now}" Destination={quoteattr(tenant.saml_sso_url)} '
           f'AssertionConsumerServiceURL={quoteattr(acs_url())} '
           f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
           f'<saml:Issuer>{escape(sp_entity_id())}</saml:Issuer>'
           f'<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true"/>'
           f'</samlp:AuthnRequest>')
    deflated = zlib.compress(xml.encode())[2:-4]  # raw DEFLATE
    relay = secrets.token_urlsafe(16)
    query = urllib.parse.urlencode({"SAMLRequest": base64.b64encode(deflated).decode(), "RelayState": relay})
    sep = "&" if "?" in tenant.saml_sso_url else "?"
    cookie = jwt.encode({"tid": tenant.id, "rid": req_id, "relay": relay, "typ": "saml_state",
                         "exp": int(time.time()) + STATE_TTL}, settings.SECRET_KEY, algorithm="HS256")
    return tenant.saml_sso_url + sep + query, cookie


def read_state(cookie: str | None) -> dict:
    try:
        data = jwt.decode(cookie or "", settings.SECRET_KEY, algorithms=["HS256"])
    except JWTError as exc:
        raise SamlError("Sign-in session expired: start again") from exc
    if data.get("typ") != "saml_state":
        raise SamlError("Invalid sign-in session")
    return data


# ------------------------------------------------------------------ Response
def _time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(re.sub(r"\.\d+", "", value.strip()).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SamlError("The assertion has an invalid timestamp") from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _verify(element: etree._Element, cert: str) -> etree._Element | None:
    """The element covered by a signature that is a direct child of `element`,
    or None when `element` carries no signature of its own."""
    if element.find("ds:Signature", NS) is None:
        return None
    try:
        result = XMLVerifier().verify(element, x509_cert=cert, id_attribute="ID",
                                      expect_config=SignatureConfiguration(location="./"))
    except (InvalidSignature, InvalidInput) as exc:
        raise SamlError("The identity provider's signature didn't verify") from exc
    signed = result.signed_xml
    if signed is None or signed.get("ID") != element.get("ID"):
        raise SamlError("The signature doesn't cover the expected element")
    return signed


def parse_response(saml_response: str, tenant, request_id: str, now: datetime | None = None) -> str:
    """Verify a base64 SAMLResponse and return the signed-in email address."""
    now = now or datetime.now(timezone.utc)
    try:
        raw = base64.b64decode(saml_response, validate=False)
    except ValueError as exc:
        raise SamlError("Malformed SAML response") from exc
    root = _parse(raw)
    if root.tag != f"{{{NS['samlp']}}}Response":
        raise SamlError("Not a SAML response")
    status = root.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or not status.get("Value", "").endswith(":Success"):
        raise SamlError("Your identity provider refused the sign-in")
    if root.find(".//saml:EncryptedAssertion", NS) is not None:
        raise SamlError("Encrypted assertions aren't supported: turn off assertion encryption for PhishLens")
    if len(root.findall(".//saml:Assertion", NS)) != 1:
        raise SamlError("The response must contain exactly one assertion")
    cert = tenant.saml_idp_cert

    signed_response = _verify(root, cert)
    if signed_response is not None:
        assertion = signed_response.find("saml:Assertion", NS)
        if assertion is None:
            raise SamlError("The signed response has no assertion")
        inner = _verify(assertion, cert)  # optional second signature; must be valid if present
        assertion = inner if inner is not None else assertion
    else:
        direct = root.find("saml:Assertion", NS)
        if direct is None:
            raise SamlError("The assertion must be a direct child of the response")
        assertion = _verify(direct, cert)
        if assertion is None:
            raise SamlError("The identity provider didn't sign the response or the assertion")

    if (assertion.findtext("saml:Issuer", namespaces=NS) or "").strip() != tenant.saml_entity_id:
        raise SamlError("The assertion came from a different identity provider")
    cond = assertion.find("saml:Conditions", NS)
    if cond is not None:
        nb, na = _time(cond.get("NotBefore")), _time(cond.get("NotOnOrAfter"))
        if (nb and now + SKEW < nb) or (na and now - SKEW >= na):
            raise SamlError("The sign-in assertion has expired: try again")
        audiences = [a.text.strip() for a in cond.findall(".//saml:Audience", NS) if a.text]
        if audiences and sp_entity_id() not in audiences:
            raise SamlError("The assertion is meant for a different service")
    ok = False
    for sc in assertion.findall("saml:Subject/saml:SubjectConfirmation", NS):
        if sc.get("Method") != "urn:oasis:names:tc:SAML:2.0:cm:bearer":
            continue
        data = sc.find("saml:SubjectConfirmationData", NS)
        if data is None:
            continue
        na = _time(data.get("NotOnOrAfter"))
        if (data.get("Recipient") == acs_url() and data.get("InResponseTo") == request_id
                and na is not None and now - SKEW < na):
            ok = True
    if not ok:
        raise SamlError("The assertion doesn't match this sign-in: start again")

    email = ""
    for attr in assertion.findall(".//saml:Attribute", NS):
        if attr.get("Name") in EMAIL_ATTRS or attr.get("FriendlyName") in EMAIL_ATTRS:
            email = (attr.findtext("saml:AttributeValue", namespaces=NS) or "").strip()
            if email:
                break
    if not email:
        email = (assertion.findtext("saml:Subject/saml:NameID", namespaces=NS) or "").strip()
    email = email.lower()
    if "@" not in email:
        raise SamlError("Identity provider didn't share an email address")
    if email.rsplit("@", 1)[1] != (tenant.sso_email_domain or "").lower():
        raise SamlError(f"Only @{tenant.sso_email_domain} accounts can sign in here")
    return email
