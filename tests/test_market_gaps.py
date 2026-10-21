"""Features added after the Oct 2026 competitor review: DMARC aggregate
reports, lookalike domains, email header analyzer, chat webhooks, blocklists."""
import gzip
import io
import json
import zipfile
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app import dmarc_reports, header_analyzer, models, webhooks
from app.database import Base, SessionLocal, engine as sa_engine
from app.main import app
from app.scanner import dns_checks, engine as scan_engine, lookalike


@pytest.fixture()
def db():
    Base.metadata.drop_all(bind=sa_engine)
    Base.metadata.create_all(bind=sa_engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def client(db, monkeypatch):
    monkeypatch.setattr("app.deps.assert_public_target", lambda domain: None)
    monkeypatch.setattr("app.scanner.scoring.run_all_checks", lambda domain: [{
        "key": "spf", "title": "SPF", "status": "pass", "score": 15, "max_score": 15,
        "details": "stubbed", "issues": [], "fixes": []}])
    return TestClient(app)


def _auth(client, email):
    r = client.post("/api/auth/signup", json={"email": email, "password": "correct-horse-123",
                                              "company": "Acme"})
    assert r.status_code == 201, r.text
    client.cookies.clear()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _report(domain="example.com", report_id="r-1", begin=None, days=1, p="none", rows=None):
    begin = begin or datetime.utcnow() - timedelta(days=days)
    b = int(begin.timestamp())
    rows = rows if rows is not None else [
        ("209.85.220.41", 900, "pass", "pass", "google.com"),
        ("198.51.100.7", 100, "fail", "fail", "spoofer.example"),
    ]
    recs = "".join(f"""
  <record>
    <row><source_ip>{ip}</source_ip><count>{n}</count>
      <policy_evaluated><disposition>none</disposition><dkim>{dk}</dkim><spf>{sp}</spf></policy_evaluated></row>
    <identifiers><header_from>{domain}</header_from></identifiers>
    <auth_results><dkim><domain>{sig}</domain><selector>s1</selector><result>{dk}</result></dkim>
      <spf><domain>{sig}</domain><result>{sp}</result></spf></auth_results>
  </record>""" for ip, n, dk, sp, sig in rows)
    return f"""<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata><org_name>google.com</org_name><email>noreply-dmarc-support@google.com</email>
    <report_id>{report_id}</report_id><date_range><begin>{b}</begin><end>{b + 86399}</end></date_range>
  </report_metadata>
  <policy_published><domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf><p>{p}</p><pct>100</pct></policy_published>
  {recs}
</feedback>""".encode()


# ------------------------------------------------------------------ DMARC parsing
def test_parse_plain_gzip_and_zip_reports():
    xml = _report()
    gz = gzip.compress(xml)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("google.com!example.com!1!2.xml", xml)
    for blob in (xml, gz, buf.getvalue()):
        parsed = dmarc_reports.parse(blob)
        assert parsed["domain"] == "example.com"
        assert parsed["org_name"] == "google.com"
        assert [r["count"] for r in parsed["records"]] == [900, 100]
        assert parsed["policy"]["p"] == "none"


def test_parse_rejects_dtd_and_non_reports():
    evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><feedback>&a;</feedback>'
    with pytest.raises(dmarc_reports.ReportError):
        dmarc_reports.parse(evil)
    with pytest.raises(dmarc_reports.ReportError):
        dmarc_reports.parse(b"<html><body>hi</body></html>")
    with pytest.raises(dmarc_reports.ReportError):
        dmarc_reports.parse(b"not xml at all")


def test_parse_rejects_decompression_bomb(monkeypatch):
    monkeypatch.setattr(dmarc_reports, "MAX_XML", 1000)
    with pytest.raises(dmarc_reports.ReportError, match="too large"):
        dmarc_reports.parse(gzip.compress(b"<feedback>" + b" " * 5000 + b"</feedback>"))


def test_identify_known_senders():
    rec = {"dkim_auth": [{"domain": "example.com"}], "spf_auth": [{"domain": "bounces.amazonses.com"}]}
    assert dmarc_reports.identify_sender(rec, "example.com") == "Amazon SES"
    rec = {"dkim_auth": [], "spf_auth": [{"domain": "example.com"}]}
    assert dmarc_reports.identify_sender(rec, "example.com") == "example.com (own servers)"


# ------------------------------------------------------------------ DMARC API
def test_upload_summary_and_dedupe(client):
    h = _auth(client, "dmarc@example.com")
    r = client.post("/api/dmarc/reports", content=_report(), headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["messages"] == 1000 and not r.json()["duplicate"]
    again = client.post("/api/dmarc/reports", content=gzip.compress(_report()), headers=h)
    assert again.json()["duplicate"]
    assert client.get("/api/dmarc/domains", headers=h).json() == ["example.com"]
    s = client.get("/api/dmarc/summary/example.com", headers=h).json()
    assert s["messages"] == 1000 and s["pass_rate"] == 90.0
    names = {row["sender"]: row for row in s["senders"]}
    assert names["Google Workspace"]["status"] == "pass"
    assert names["spoofer.example"]["status"] == "fail"
    assert s["verdict"]["level"] == "info"  # one day of data is not enough


def test_summary_recommends_next_policy_when_clean(client):
    h = _auth(client, "dmarc2@example.com")
    for i in range(15):
        body = _report(report_id=f"r-{i}", days=i + 1,
                       rows=[("209.85.220.41", 500, "pass", "pass", "google.com")])
        assert client.post("/api/dmarc/reports", content=body, headers=h).status_code == 201
    v = client.get("/api/dmarc/summary/example.com", headers=h).json()["verdict"]
    assert v["level"] == "pass" and "p=quarantine" in v["message"]


def test_dmarc_reports_are_tenant_scoped(client):
    a = _auth(client, "a@one.com")
    b = _auth(client, "b@two.com")
    rid = client.post("/api/dmarc/reports", content=_report(), headers=a).json()["id"]
    assert client.get("/api/dmarc/domains", headers=b).json() == []
    assert client.get("/api/dmarc/summary/example.com", headers=b).json()["messages"] == 0
    assert client.delete(f"/api/dmarc/reports/{rid}", headers=b).status_code == 404
    assert client.delete(f"/api/dmarc/reports/{rid}", headers=a).status_code == 200


def test_upload_rejects_garbage(client):
    h = _auth(client, "bad@example.com")
    assert client.post("/api/dmarc/reports", content=b"hello", headers=h).status_code == 400
    assert client.post("/api/dmarc/reports", content=b"", headers=h).status_code == 400


def test_mailbox_script_files_reports_for_monitoring_tenants(client, db):
    from email.message import EmailMessage

    from scripts import fetch_dmarc_reports as fetch

    h = _auth(client, "mbox@example.com")
    assert client.post("/api/monitors", json={"domain": "example.com"}, headers=h).status_code == 201
    msg = EmailMessage()
    msg["Subject"] = "Report domain: example.com"
    msg.set_content("report attached")
    msg.add_attachment(gzip.compress(_report()), maintype="application", subtype="gzip",
                       filename="google.com!example.com.xml.gz")
    msg.add_attachment(gzip.compress(_report(domain="unmonitored.org")), maintype="application",
                       subtype="gzip", filename="other.xml.gz")
    stored, skipped = fetch.file_message(db, msg.as_bytes())
    assert (stored, skipped) == (1, 1)
    assert db.query(models.DmarcReport).count() == 1


# ------------------------------------------------------------------ lookalikes
def test_generate_lookalikes():
    names = {c["domain"]: c["technique"] for c in lookalike.generate("paypal.com")}
    assert "paypal.com" not in names
    assert names["paypa1.com"] == "homoglyph"
    assert names["pyapal.com"] == "transposition"
    assert names["paypal.net"] == "other TLD"
    assert "paypal-login.com" in names
    assert all(len(d) <= 253 and ".." not in d for d in names)
    uk = {c["domain"] for c in lookalike.generate("www.barclays.co.uk")}
    assert "barclay.co.uk" in uk and "barclays.com" in uk


class _FakeResolver:
    def __init__(self, zone):
        self.zone = zone

    def resolve(self, name, rtype, lifetime=None):
        recs = self.zone.get(name, {}).get(rtype)
        if not recs:
            raise lookalike.dns.resolver.NXDOMAIN()
        return [type("R", (), {"to_text": (lambda self, v=v: v)})() for v in recs]


def test_scan_ranks_mail_capable_lookalikes_first():
    zone = {
        "paypa1.com": {"NS": ["ns1.evil."], "A": ["203.0.113.9"], "MX": ["10 mx.evil.net."]},
        "paypal.net": {"NS": ["ns1.paypal.com."]},
        "paypall.com": {"A": ["203.0.113.10"]},
    }
    r = lookalike.scan("paypal.com", resolver=_FakeResolver(zone))
    assert [x["domain"] for x in r["registered"]] == ["paypa1.com", "paypall.com", "paypal.net"]
    assert r["registered"][0]["risk"] == "high" and r["registered"][0]["mx"] == ["mx.evil.net"]
    assert r["high_risk"] == 1


def test_monitor_lookalike_alerts_only_on_new_registrations(db, monkeypatch):
    found = [{"domain": "paypa1.com", "mx": ["mx.evil.net"], "risk": "high"}]
    monkeypatch.setattr(lookalike, "scan", lambda d: {"registered": list(found)})
    tenant = models.Tenant(name="t")
    db.add(tenant)
    db.commit()
    mon = models.Monitor(tenant_id=tenant.id, domain="paypal.com")
    db.add(mon)
    db.commit()
    assert scan_engine.check_monitor_lookalikes(mon) == []  # baseline
    assert scan_engine.check_monitor_lookalikes(mon) == []  # nothing new
    found.append({"domain": "paypal-login.com", "mx": [], "risk": "medium"})
    alerts = scan_engine.check_monitor_lookalikes(mon)
    assert len(alerts) == 1 and "paypal-login.com" in alerts[0].message
    assert alerts[0].kind == "lookalike_registered"


def test_lookalike_endpoint_requires_login(client, monkeypatch):
    monkeypatch.setattr(lookalike, "scan", lambda d: {"domain": d, "checked": 1, "registered": [],
                                                       "high_risk": 0})
    assert client.post("/api/tools/lookalikes", json={"domain": "example.com"}).status_code == 401
    h = _auth(client, "look@example.com")
    r = client.post("/api/tools/lookalikes", json={"domain": "https://Example.com/x"}, headers=h)
    assert r.status_code == 200 and r.json()["domain"] == "example.com"


# ------------------------------------------------------------------ header analyzer
_PHISH = """Delivered-To: victim@company.com
Received: by 2002:a05:6000:1:b0:1 with SMTP id x; Tue, 21 Oct 2026 10:00:05 -0700 (PDT)
Received: from mail.evil.net (mail.evil.net. [198.51.100.7])
        by mx.google.com with ESMTPS id y; Tue, 21 Oct 2026 10:00:01 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of ceo@company.com does not designate 198.51.100.7) smtp.mailfrom=ceo@company.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=company.com
From: "ceo@company.com" <boss@evil.net>
Reply-To: payments@evil-mail.ru
Subject: Urgent wire transfer
Date: Tue, 21 Oct 2026 17:00:00 +0000

Please pay this invoice today.
"""

_GOOD = """Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id z; Tue, 21 Oct 2026 10:00:01 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@company.com header.s=s1 header.b=abc;
       spf=pass (google.com: domain of alice@company.com designates 209.85.220.41) smtp.mailfrom=alice@company.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=company.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=company.com; s=s1; h=from:to; bh=x; b=y
From: Alice <alice@company.com>
Subject: Lunch?
"""


def test_header_analyzer_flags_phishing():
    r = header_analyzer.analyze(_PHISH)
    assert r["level"] == "fail"
    assert r["authentication"]["dmarc"] == "fail" and r["authentication"]["spf"] == "fail"
    text = " ".join(f["text"] for f in r["findings"])
    assert "Reply-To" in text and "display name" in text
    assert [h["by"] for h in r["hops"]][0] == "mx.google.com"  # oldest hop first
    assert r["hops"][1]["delay_seconds"] == 4


def test_header_analyzer_passes_genuine_mail():
    r = header_analyzer.analyze(_GOOD)
    assert r["level"] == "pass", r["findings"]
    assert r["authentication"]["dkim_domain"] == "company.com"
    assert r["dkim_signatures"][0] == {"domain": "company.com", "selector": "s1",
                                       "algorithm": "rsa-sha256"}


def test_header_endpoint_is_public_and_validates(client):
    r = client.post("/api/tools/headers", json={"headers": _PHISH})
    assert r.status_code == 200 and r.json()["level"] == "fail"
    assert client.post("/api/tools/headers", json={"headers": "   "}).status_code == 400
    assert client.get("/tools/headers").status_code == 200


# ------------------------------------------------------------------ chat webhooks
def test_chat_webhook_payloads(monkeypatch):
    sent = []

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(webhooks, "url_allowed", lambda url: True)
    monkeypatch.setattr(webhooks._opener, "open",
                        lambda req, timeout=None: sent.append((req.full_url, json.loads(req.data))) or _Resp())
    event = {"event": "monitor.alert", "domain": "x.com", "score": 40, "grade": "F",
             "alerts": [{"kind": "score_drop", "message": "x.com: score dropped 80 -> 40."}]}
    webhooks.deliver("https://hooks.slack.com/services/T/B/C", "s" * 16, event)
    webhooks.deliver("https://acme.webhook.office.com/webhookb2/abc", "s" * 16, event)
    webhooks.deliver("https://discord.com/api/webhooks/1/abc", "s" * 16, event)
    webhooks.deliver("https://siem.example.com/hook", "s" * 16, event)
    slack, teams, discord, siem = (body for _, body in sent)
    assert "score dropped 80 -> 40" in slack["text"]
    assert teams["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert "x.com" in discord["content"]
    assert siem == event


# ------------------------------------------------------------------ blocklists
class _FakeMX:
    def __init__(self, host):
        self.exchange = host


def test_domain_blocklist_listing_detected(monkeypatch):
    def fake_resolve(name, rtype, lifetime=None):
        if rtype == "MX":
            return [_FakeMX("mx.x.com")]
        if name == "x.com.dbl.spamhaus.org":
            return ["127.0.1.4"]  # phishing domain
        raise Exception("NXDOMAIN")
    monkeypatch.setattr(dns_checks._resolver, "resolve", fake_resolve)
    monkeypatch.setattr(dns_checks.socket, "gethostbyname", lambda h: "203.0.113.5")
    r = dns_checks.check_dnsbl("x.com")
    assert r["status"] == "fail" and r["issues"] == ["Listed: x.com on dbl.spamhaus.org"]
    assert len(r["fixes"]) == 2


def test_dbl_error_codes_are_not_listings(monkeypatch):
    def fake_resolve(name, rtype, lifetime=None):
        if rtype == "MX":
            return []
        if name.endswith("dbl.spamhaus.org"):
            return ["127.0.1.255"]  # "IP queried against DBL" error
        raise Exception("NXDOMAIN")
    monkeypatch.setattr(dns_checks._resolver, "resolve", fake_resolve)
    assert dns_checks.check_dnsbl("x.com")["status"] == "pass"
