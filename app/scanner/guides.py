"""Step-by-step fix guides: one card per failing check, written for the person
who has to make the change, not for an email-security expert.

Each guide says what's wrong and why it matters in plain words, and lists the
exact records to add or change as separate fields (type, host, value), so the
report can show each field with its own copy button and the provider-specific
steps. Checks only describe what they found; this module turns that into
instructions, so the scanner's own `fixes` text stays as it was for the API.

    guide = {headline, problem, why, minutes, difficulty, warning, next,
             records: [{action: add|replace|delete, type, host, fqdn, value,
                        current, value_from_provider}],
             file: {url, content} | None,
             steps: [...]}           # for fixes that aren't a DNS record

`host` is the name relative to the zone ("@" for the domain itself), which is
what most DNS providers want in their Name field; `fqdn` is the full name.
"""
import re
from datetime import datetime, timezone

import dns.exception
import dns.resolver

from . import dns_checks

# Nameserver suffix -> DNS host. The report uses the key to pick the matching
# field names and click-by-click steps.
NS_HOSTS = [
    ("ns.cloudflare.com", "cloudflare", "Cloudflare"),
    ("domaincontrol.com", "godaddy", "GoDaddy"),
    ("awsdns-", "route53", "Amazon Route 53"),
    ("bdm.microsoftonline.com", "m365", "Microsoft 365"),
    ("azure-dns.", "azure", "Azure DNS"),
    ("registrar-servers.com", "namecheap", "Namecheap"),
    ("digitalocean.com", "digitalocean", "DigitalOcean"),
    ("googledomains.com", "squarespace", "Squarespace Domains"),
    ("squarespacedns.com", "squarespace", "Squarespace Domains"),
    ("dns-parking.com", "hostinger", "Hostinger"),
    ("ui-dns.", "ionos", "IONOS"),
    ("desec.io", "desec", "deSEC"),
    ("desec.org", "desec", "deSEC"),
]

# Mail provider (from MX hosts) -> the SPF include that authorizes it.
SPF_INCLUDES = [
    (("google.com", "googlemail.com"), "include:_spf.google.com", "Google Workspace"),
    (("protection.outlook.com",), "include:spf.protection.outlook.com", "Microsoft 365"),
    (("zoho.com", "zoho.eu", "zoho.in"), "include:zohomail.com", "Zoho Mail"),
    (("secureserver.net",), "include:secureserver.net", "GoDaddy email"),
    (("mail.protonmail.ch",), "include:_spf.protonmail.ch", "Proton Mail"),
    (("messagingengine.com",), "include:spf.messagingengine.com", "Fastmail"),
]

DKIM_WHERE = [
    (("google.com", "googlemail.com"), "Google Workspace",
     "In the Google Admin console go to Apps → Google Workspace → Gmail → Authenticate email, "
     "choose your domain and click Generate new record (2048-bit). Google shows the host "
     "(google._domainkey) and the value to paste."),
    (("protection.outlook.com",), "Microsoft 365",
     "In the Microsoft Defender portal go to Email & collaboration → Policies & rules → Threat policies → "
     "Email authentication settings → DKIM, select your domain and click Create DKIM keys. Microsoft "
     "shows two CNAME records (selector1._domainkey and selector2._domainkey) to add."),
    (("zoho.com", "zoho.eu", "zoho.in"), "Zoho Mail",
     "In the Zoho Mail admin console go to Domains → your domain → Email configuration → DKIM, "
     "add a selector and copy the TXT value it generates."),
]


def dns_host(domain: str) -> dict | None:
    """Who runs the domain's DNS, from its nameservers."""
    labels = domain.split(".")
    for i in range(0, max(1, len(labels) - 1)):
        name = ".".join(labels[i:])
        try:
            answers = dns_checks._resolver.resolve(name, "NS", lifetime=dns_checks.TIMEOUT)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except (dns.exception.DNSException, OSError):
            return None
        return match_nameservers(str(r.target) for r in answers)
    return None


def match_nameservers(names) -> dict:
    ns = sorted(n.rstrip(".").lower() for n in names)
    for needle, key, label in NS_HOSTS:
        if any(needle in n for n in ns):
            return {"key": key, "label": label, "nameservers": ns[:4]}
    return {"key": "other", "label": None, "nameservers": ns[:4]}


def _rec(domain, host, rtype, value, action="add", current=None, **extra):
    fqdn = domain if host == "@" else f"{host}.{domain}"
    out = {"action": action, "type": rtype, "host": host, "fqdn": fqdn, "value": value}
    if current is not None:
        out["current"] = current
    out.update(extra)
    return out


def _mail_provider(mx_hosts, table):
    for suffixes, *rest in table:
        if any(h.lower().rstrip(".").endswith(suffixes) for h in mx_hosts):
            return rest
    return None


def _tags(record: str) -> list[tuple[str, str]]:
    out = []
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out.append((k.strip().lower(), v.strip()))
    return out


def _dmarc_str(tags: list[tuple[str, str]]) -> str:
    names = {"v": "v"}
    return "; ".join(f"{names.get(k, k)}={'DMARC1' if k == 'v' else v}" for k, v in tags)


# ------------------------------------------------------------------ per check
def _spf(c, domain, ctx):
    mx = ctx["mx_hosts"]
    if c.get("records") and len(c["records"]) > 1:
        merged = _merge_spf(c["records"])
        return {
            "headline": "Merge your SPF records into one",
            "problem": f"{domain} has {len(c['records'])} SPF records. Mail servers treat that as an error and ignore SPF completely.",
            "why": "With SPF ignored, nothing stops other servers from sending mail as you.",
            "minutes": 5, "difficulty": "easy",
            "records": [_rec(domain, "@", "TXT", merged, "replace", current=" | ".join(c["records"]))],
            "warning": "Delete the old SPF records and keep only this one. Leave other TXT records (like site verification) alone.",
        }
    record = c.get("record")
    if not record:
        provider = _mail_provider(mx, SPF_INCLUDES)
        if not mx:
            value, note = "v=spf1 -all", "This domain has no mail servers, so this says it never sends email."
        elif provider:
            value, note = f"v=spf1 {provider[0]} ~all", f"Authorizes {provider[1]}, which handles your mail."
        else:
            value, note = "v=spf1 mx ~all", "Authorizes your own mail servers (your MX records)."
        return {
            "headline": f"Add an SPF record listing who may send email for {domain}",
            "problem": f"{domain} has no SPF record, so receiving servers can't tell your real mail from forgeries.",
            "why": "Without SPF, spam and phishing can use your address, and your own mail is more likely to land in junk.",
            "minutes": 5, "difficulty": "easy",
            "records": [_rec(domain, "@", "TXT", value, note=note)],
            "warning": "If you also send through other services (newsletters, invoicing, your website), add each one's include: before ~all. A domain can only have one SPF record.",
            "next": "Once your DMARC reports show all your senders pass, change ~all to -all.",
        }
    issues = " ".join(c.get("issues", [])).lower()
    terms = record.split()
    if "0.0.0.0/0" in issues:
        new = " ".join(t for t in terms if not re.fullmatch(r"\+?ip[46]:[0-9a-f.:]+/0", t, flags=re.I))
        return {
            "headline": "Remove the entry that lets the whole internet send as you",
            "problem": "Your SPF record includes a /0 address range, which covers every server on the internet.",
            "why": "Anyone can send mail that passes SPF as your domain.",
            "minutes": 2, "difficulty": "easy",
            "records": [_rec(domain, "@", "TXT", new, "replace", current=record)],
        }
    if "lookups" in issues:
        return {
            "headline": "Cut your SPF record down to 10 DNS lookups",
            "problem": "Your SPF record needs more than 10 DNS lookups to check. Receivers stop at 10 and treat SPF as broken.",
            "why": "A broken SPF record means your legitimate mail can fail authentication.",
            "minutes": 15, "difficulty": "medium",
            "steps": ["Remove include: entries for services you no longer use.",
                      "Replace an include: with the service's ip4:/ip6: ranges where they're stable.",
                      "Or let PhishLens host your SPF record: it's flattened to IP addresses automatically "
                      "(Dashboard → Hosted DMARC, SPF & MTA-STS)."],
        }
    all_term = next((t for t in terms if re.fullmatch(r"[-~?+]?all", t, flags=re.I)), None)
    no_ptr = [t for t in terms if not re.fullmatch(r"\+?ptr(:\S+)?", t, flags=re.I)]
    if all_term and all_term[0] in "+a":
        new = " ".join("-all" if t == all_term else t for t in no_ptr)
        return {
            "headline": "Stop your SPF record from allowing everyone to send as you",
            "problem": "Your SPF record ends in +all, which tells every server in the world it may send email as you.",
            "why": "This is the same as having no protection at all, and spam filters treat it as a red flag.",
            "minutes": 2, "difficulty": "easy",
            "records": [_rec(domain, "@", "TXT", new, "replace", current=record)],
            "warning": "Before saving, add an include: or ip4: entry for every service that sends your email (your mailbox "
                       "provider, newsletter, invoicing, website forms), or their mail will be rejected.",
        }
    if all_term and all_term[0] in "~?":
        new = " ".join("-all" if t == all_term else t for t in no_ptr)
        return {
            "headline": "Make your SPF record reject senders you haven't listed",
            "problem": f"Your SPF record ends in {all_term}, so mail from unknown servers is only marked as suspicious, not rejected.",
            "why": "Forged mail from your domain can still reach inboxes.",
            "minutes": 2, "difficulty": "medium",
            "records": [_rec(domain, "@", "TXT", new, "replace", current=record)],
            "warning": "First check that every service that sends your email is listed: your mailbox, newsletter, invoicing "
                       "and website forms. Your DMARC reports list them. A missing one will have its mail rejected.",
        }
    if len(no_ptr) != len(terms):
        return {
            "headline": "Remove the outdated ptr entry from your SPF record",
            "problem": "Your SPF record uses ptr, which is deprecated and which many receivers skip.",
            "why": "Mail that relies on it can fail SPF.",
            "minutes": 5, "difficulty": "medium",
            "records": [_rec(domain, "@", "TXT", " ".join(no_ptr), "replace", current=record)],
            "warning": "If ptr was the only thing covering one of your servers, add that server as ip4:<its address>.",
        }
    return None


def _merge_spf(records: list[str]) -> str:
    terms, final = [], "~all"
    for r in records:
        for t in r.split()[1:]:
            if re.fullmatch(r"[-~?+]?all", t, flags=re.I):
                final = t if t.startswith("-") else final
                continue
            if t not in terms:
                terms.append(t)
    return " ".join(["v=spf1", *terms, final])


def _dmarc(c, domain, ctx):
    rua = f"mailto:dmarc@{domain}"
    if c.get("records") and len(c["records"]) > 1:
        return {
            "headline": "Delete the extra DMARC records",
            "problem": f"_dmarc.{domain} has {len(c['records'])} DMARC records. Receivers ignore DMARC completely when there's more than one.",
            "why": "Your DMARC policy isn't being applied at all until only one record is left.",
            "minutes": 5, "difficulty": "easy",
            "records": [_rec(domain, "_dmarc", "TXT", c["records"][0], "replace", current=" | ".join(c["records"]))],
            "warning": "Keep the record shown here and delete the others at the same name.",
        }
    record = c.get("record")
    if not record:
        return {
            "headline": f"Add a DMARC record so nobody can send email pretending to be {domain}",
            "problem": f"{domain} has no DMARC record. Mail servers have no instructions for email that falsely uses your name.",
            "why": "Scammers can send invoices \"from\" your domain. Gmail, Yahoo and Microsoft also require DMARC from bulk senders.",
            "minutes": 5, "difficulty": "easy",
            "records": [_rec(domain, "_dmarc", "TXT", f"v=DMARC1; p=none; rua={rua}",
                             note="p=none only collects reports for now. Nothing gets blocked yet.")],
            "warning": "If a TXT record named _dmarc already exists, edit it instead of adding a second one. Two DMARC records cancel each other out.",
            "next": "Once the DMARC reports show only your real senders (usually after 2–4 weeks), change p=none to p=quarantine, then to p=reject.",
        }
    tags = _tags(record)
    d = dict(tags)
    policy = d.get("p", "none").lower()
    changes, out = [], []
    for k, v in tags:
        if k == "p" and policy in ("none", "quarantine"):
            v = "quarantine" if policy == "none" else "reject"
            changes.append(f"p={policy} → p={v}")
        elif k == "pct":
            changes.append("remove pct (no longer part of DMARC)")
            if v.isdigit() and int(v) < 100 and "t" not in d:
                out.append(("t", "y"))
            continue
        elif k in ("rf", "ri"):
            changes.append(f"remove {k} (no longer used)")
            continue
        elif k in ("sp", "np") and v.lower() == "none" and policy != "none":
            changes.append(f"remove {k}=none so subdomains get the same protection")
            continue
        out.append((k, v))
    if "rua" not in d:
        out.insert(2 if len(out) >= 2 else len(out), ("rua", rua))
        changes.append("add rua so you receive reports")
    if "p" not in d:
        out.insert(1, ("p", "quarantine"))
        changes.append("add p=quarantine")
    new = _dmarc_str(out)
    if new == record.strip().rstrip(";") or not changes:
        if d.get("t", "").lower() == "y":
            new = _dmarc_str([(k, v) for k, v in tags if k != "t"])
            changes = ["remove t=y to fully enforce"]
        else:
            return None
    raising = any(ch.startswith("p=") for ch in changes)
    return {
        "headline": ("Turn on DMARC protection" if policy == "none" else "Move DMARC to full protection")
                    if raising else "Tidy up your DMARC record",
        "problem": ("Your DMARC policy is p=none, so it only reports on fake mail. It doesn't stop any."
                    if policy == "none" else
                    "Your DMARC policy is p=quarantine: fake mail goes to junk, but it still gets delivered."
                    if policy == "quarantine" else "Your DMARC record has settings that weaken it or are out of date."),
        "why": "Each step up means fewer forged emails reach your customers and staff.",
        "minutes": 2, "difficulty": "medium" if raising else "easy",
        "records": [_rec(domain, "_dmarc", "TXT", new, "replace", current=record, changes=changes)],
        "warning": ("Check your DMARC reports first: every service that sends as you should pass. "
                    "Anything that fails will go to junk (quarantine) or be refused (reject).") if raising else None,
        "next": "After a few quiet weeks at p=quarantine, move to p=reject." if policy == "none" else None,
    }


def _dkim(c, domain, ctx):
    where = _mail_provider(ctx["mx_hosts"], DKIM_WHERE)
    weak = c.get("score", 0) > 0
    return {
        "headline": "Switch to a stronger DKIM key" if weak else "Turn on DKIM signing for your email",
        "problem": ("Your DKIM key is shorter than 2048 bits, which can be cracked." if weak else
                    f"No DKIM key was found for {domain}, so your mail isn't signed."),
        "why": "DKIM proves your emails weren't forged or changed on the way. DMARC needs it to protect you fully.",
        "minutes": 10, "difficulty": "medium",
        "records": [_rec(domain, "google._domainkey" if where and where[0] == "Google Workspace" else "selector._domainkey",
                         "TXT", "", value_from_provider=True)],
        "steps": [where[1] if where else
                  "In your email provider's admin settings, look for DKIM or \"email authentication\" and generate a 2048-bit key. "
                  "It shows the record name (ending in ._domainkey) and the value to paste.",
                  "Add the record it gives you in your DNS, exactly as shown.",
                  "Go back to your email provider and click Start authentication (or Enable) so it starts signing."],
    }


def _mta_sts(c, domain, ctx):
    mx = ctx["mx_hosts"] or [f"mail.{domain}"]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
    missing = c.get("score", 0) == 0 and "No MTA-STS record" in (c.get("details") or "")
    mode = "testing" if missing else "enforce"
    content = "\n".join(["version: STSv1", f"mode: {mode}", *[f"mx: {h}" for h in mx], "max_age: 604800"])
    records = [_rec(domain, "_mta-sts", "TXT", f"v=STSv1; id={stamp}",
                    "add" if missing else "replace",
                    note="Change the id whenever you change the policy file.")]
    return {
        "headline": "Make other mail servers use encryption when they deliver to you" if missing
                    else "Switch MTA-STS to enforce mode",
        "problem": ("Mail sent to you can be forced onto an unencrypted connection by an attacker." if missing else
                    "Your MTA-STS policy isn't enforced yet, or its file can't be read."),
        "why": "MTA-STS makes senders refuse to deliver your mail without encryption.",
        "minutes": 20, "difficulty": "hard",
        "records": records,
        "file": {"url": f"https://mta-sts.{domain}/.well-known/mta-sts.txt", "content": content},
        "steps": ["Publish the text file at the address shown. It needs HTTPS with a valid certificate, on the mta-sts subdomain.",
                  "No web hosting? PhishLens can host the file for you: Dashboard → Hosted DMARC, SPF & MTA-STS."],
        "warning": "Every mail server in your MX records must appear on an mx: line, or mail to you can be refused." if not missing else None,
        "next": "After a week or two in testing mode with no problems in your TLS reports, change mode: testing to mode: enforce and update the id." if missing else None,
    }


def _tls_rpt(c, domain, ctx):
    return {
        "headline": "Get reports when mail to you fails to encrypt",
        "problem": "Other mail servers have nowhere to report problems delivering encrypted mail to you.",
        "why": "Without these reports you won't know when MTA-STS or your certificates break mail delivery.",
        "minutes": 3, "difficulty": "easy",
        "records": [_rec(domain, "_smtp._tls", "TXT", f"v=TLSRPTv1; rua=mailto:tls@{domain}")],
        "warning": "Make sure the tls@ address exists, or point rua at a mailbox you already read.",
    }


def _caa(c, domain, ctx):
    recs = [_rec(domain, "@", "CAA", '0 issue "letsencrypt.org"')]
    return {
        "headline": "Limit which companies can issue certificates for your domain",
        "problem": "Any certificate authority may issue an HTTPS certificate for your domain.",
        "why": "A CAA record makes it harder for an attacker to get a fake certificate for your site.",
        "minutes": 5, "difficulty": "easy",
        "records": recs,
        "warning": "Name the company that issues your current certificate. Let's Encrypt is shown; use digicert.com, sectigo.com, pki.goog or amazon.com instead if that's yours. Add one record per company.",
    }


STEPS_ONLY = {
    "mx": ("Set up mail servers for your domain", "Your domain has no MX records, so it can't receive email.",
           "Bounces and replies to your address get lost.", 10, "medium",
           ["In your email provider's setup guide (Google Workspace, Microsoft 365, Zoho...), find the MX records it asks for.",
            "Add each MX record in your DNS with the priority it gives.",
            "If the domain should never receive mail, add a single MX record with priority 0 and host \".\" (a \"null MX\")."]),
    "smtp-tls": ("Turn on encryption on your mail server", "Your mail server doesn't offer encryption (STARTTLS).",
                 "Mail to you travels in plain text and can be read on the way.", 30, "hard",
                 ["If a provider like Google or Microsoft runs your mail, contact their support: this should already be on.",
                  "If you run your own server, enable STARTTLS with a valid certificate (Postfix: smtpd_tls_security_level = may)."]),
    "dnssec": ("Turn on DNSSEC", "Your DNS answers aren't signed, so they could be faked.",
               "DNSSEC stops attackers redirecting your mail or website through forged DNS answers.", 10, "medium",
               ["Turn on DNSSEC in your DNS provider (Cloudflare: DNS → Settings → Enable DNSSEC).",
                "If your DNS provider and registrar are different companies, copy the DS record it shows into your registrar's DNSSEC settings.",
                "Wait a few hours, then press Check again."]),
    "dnsbl": ("Get your domain or mail server off a blocklist", "Your domain or a mail server is on a spam blocklist.",
              "Mail from a listed domain or server is often rejected or sent to junk.", 30, "hard",
              ["Find and fix the cause first: a hacked mailbox, a compromised website form, or a bulk mailing to old lists.",
               "Open the blocklist's website (named under Details) and use its removal request form.",
               "Press Check again after the blocklist confirms removal."]),
    "bimi": ("Show your logo in recipients' inboxes (BIMI)", "No BIMI record, or it's incomplete.",
             "Gmail, Apple Mail and Yahoo show your logo next to verified mail, which builds trust.", 60, "hard",
             ["Your DMARC policy must be p=quarantine or p=reject first.",
              "Make an SVG Tiny PS version of your logo (most BIMI generators convert it) and host it over HTTPS.",
              "For Gmail and Apple, buy a Verified Mark Certificate (trademarked logo) or Common Mark Certificate.",
              "Use Free tools → BIMI on PhishLens to build the record, then add it at default._bimi."]),
    "ptr": ("Fix your mail server's reverse DNS", "A mail server's IP address doesn't point back to its name.",
            "Many receivers reject or junk mail from servers without matching reverse DNS.", 15, "medium",
            ["Reverse DNS is set by whoever owns the IP address (your host or mail provider), not in your own DNS.",
             "Open a support ticket with them, quoting the IP and name shown under Details."]),
    "ipv6": ("Add IPv6 support", "Your domain can't be reached over IPv6.",
             "Optional: a growing share of networks prefer IPv6.", 10, "easy",
             ["Ask your web host or mail provider for their IPv6 addresses and add AAAA records for them."]),
    "rpki": ("Ask your network provider to protect your mail servers' routes", "Routes to your mail servers aren't signed (RPKI).",
             "Optional: RPKI makes it harder to hijack the network path to your servers.", 10, "easy",
             ["Send your hosting or network provider the prefixes listed under Details and ask them to publish ROAs."]),
    "dane": ("Fix your DANE records", "Your DANE (TLSA) records have a problem.",
             "Broken DANE can stop servers that check it from delivering mail to you.", 30, "hard", None),
    "tls-cert": ("Fix your website's HTTPS certificate", "Your website's certificate is missing, invalid or expiring.",
                 "Browsers show a security warning and visitors leave.", 15, "medium",
                 ["Renew or reinstall the certificate in your hosting control panel, including the full chain.",
                  "Turn on automatic renewal (most hosts use Let's Encrypt for free)."]),
    "sec-headers": ("Add security headers to your website", "Your website is missing some browser security headers.",
                    "These headers protect visitors from clickjacking and some injection attacks.", 20, "medium", None),
}

BUILDERS = {"spf": _spf, "dmarc": _dmarc, "dkim": _dkim, "mta-sts": _mta_sts,
            "tls-rpt": _tls_rpt, "caa": _caa}


def build(check: dict, domain: str, ctx: dict) -> dict | None:
    if check.get("status") == "pass" or check.get("errored") or not check.get("fixes"):
        return None
    key = check.get("key")
    guide = None
    if key in BUILDERS:
        guide = BUILDERS[key](check, domain, ctx)
    elif key in STEPS_ONLY:
        headline, problem, why, minutes, difficulty, steps = STEPS_ONLY[key]
        guide = {"headline": headline, "problem": problem, "why": why,
                 "minutes": minutes, "difficulty": difficulty, "steps": steps or list(check["fixes"])}
    if guide is None:
        guide = {"headline": check.get("issues", [check.get("title")])[0] if check.get("issues") else check.get("title"),
                 "problem": "; ".join(check.get("issues", [])) or check.get("details", ""),
                 "steps": list(check["fixes"])}
    guide.setdefault("records", [])
    guide.setdefault("steps", [])
    guide["records"] = [r for r in guide["records"] if r]
    return {k: v for k, v in guide.items() if v not in (None, "")}


def attach(result: dict) -> dict:
    """Add a `guide` to every failing check and to each action-plan entry."""
    domain = result.get("domain", "")
    checks = result.get("checks") or []
    mx = next((c.get("hosts") for c in checks if c.get("key") == "mx" and c.get("hosts")), None)
    ctx = {"mx_hosts": [h for h in (mx or []) if h]}
    by_title = {}
    for c in checks:
        g = build(c, domain, ctx)
        if g:
            c["guide"] = g
            by_title[c.get("title")] = c
    for p in result.get("action_plan") or []:
        c = by_title.get(p.get("check"))
        if c:
            p["guide"] = c["guide"]
            p["key"] = c.get("key")
    return result
