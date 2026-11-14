"""Report-phish button: an Outlook add-in and a Gmail add-on that send the open
email to the company's phishing report inbox with one click.

Each company has one report token (only its sha256 is stored). The add-in
files are generated with the token inside, for the company's admin to deploy
to everyone (Microsoft 365 admin center, Integrated apps; Google Apps Script
deployment for Workspace). Reports land in the same inbox as dashboard
uploads, with the same triage, AI verdict and takedown drafts.

The token can only submit reports: it can't read anything back, so a leaked
token at worst lets someone add junk reports (rate limited); revoke and make
a new one in the dashboard."""
from __future__ import annotations

import hashlib
import io
import secrets
import uuid
from datetime import datetime
from xml.sax.saxutils import escape

from sqlalchemy.orm import Session

from . import models
from .config import settings

PREFIX = "plr_"
ICON_SIZES = (16, 32, 64, 80, 128)
# Outlook on the web loads the task pane in an iframe from these origins.
OUTLOOK_FRAME_ANCESTORS = ("https://outlook.office.com https://outlook.office365.com https://outlook.live.com "
                           "https://outlook.cloud.microsoft https://*.officeapps.live.com")


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def new_token(db: Session, tenant: models.Tenant) -> str:
    raw = PREFIX + secrets.token_urlsafe(32)
    tenant.report_token_hash = _hash(raw)
    tenant.report_token_created_at = datetime.utcnow()
    db.commit()
    return raw


def revoke(db: Session, tenant: models.Tenant) -> None:
    tenant.report_token_hash = None
    tenant.report_token_created_at = None
    db.commit()


def tenant_for(db: Session, raw: str | None) -> models.Tenant | None:
    if not raw or not raw.startswith(PREFIX) or len(raw) > 100:
        return None
    t = db.query(models.Tenant).filter(models.Tenant.report_token_hash == _hash(raw)).first()
    if not t or (t.status or "active") != "active":
        return None
    return t


def _base() -> str:
    return settings.APP_URL.rstrip("/")


def outlook_manifest(tenant: models.Tenant, token: str) -> str:
    """Outlook add-in manifest (XML). The task pane URL carries the token in
    the fragment, so it never reaches server logs."""
    base = _base()
    app_id = uuid.uuid5(uuid.NAMESPACE_URL, f"{base}/addins/outlook/{tenant.id}")
    name = escape(f"Report phishing ({tenant.name})"[:125])
    pane = escape(f"{base}/addins/outlook/taskpane.html#t={token}")
    host = escape(base.split("://", 1)[-1].split("/")[0])
    icon = lambda n: escape(f"{base}/addins/icon-{n}.png")  # noqa: E731
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<OfficeApp xmlns="http://schemas.microsoft.com/office/appforoffice/1.1"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:bt="http://schemas.microsoft.com/office/officeappbasictypes/1.0"
           xmlns:mailappor="http://schemas.microsoft.com/office/mailappversionoverrides/1.0"
           xsi:type="MailApp">
  <Id>{app_id}</Id>
  <Version>1.0.0.0</Version>
  <ProviderName>PhishLens</ProviderName>
  <DefaultLocale>en-US</DefaultLocale>
  <DisplayName DefaultValue="{name}"/>
  <Description DefaultValue="Report a suspicious email to your security team with one click."/>
  <IconUrl DefaultValue="{icon(64)}"/>
  <HighResolutionIconUrl DefaultValue="{icon(128)}"/>
  <SupportUrl DefaultValue="{escape(base)}/help"/>
  <AppDomains>
    <AppDomain>https://{host}</AppDomain>
  </AppDomains>
  <Hosts>
    <Host Name="Mailbox"/>
  </Hosts>
  <Requirements>
    <Sets>
      <Set Name="Mailbox" MinVersion="1.1"/>
    </Sets>
  </Requirements>
  <FormSettings>
    <Form xsi:type="ItemRead">
      <DesktopSettings>
        <SourceLocation DefaultValue="{pane}"/>
        <RequestedHeight>250</RequestedHeight>
      </DesktopSettings>
    </Form>
  </FormSettings>
  <Permissions>ReadItem</Permissions>
  <Rule xsi:type="RuleCollection" Mode="Or">
    <Rule xsi:type="ItemIs" ItemType="Message" FormType="Read"/>
  </Rule>
  <DisableEntityHighlighting>false</DisableEntityHighlighting>
  <VersionOverrides xmlns="http://schemas.microsoft.com/office/mailappversionoverrides" xsi:type="VersionOverridesV1_0">
    <Requirements>
      <bt:Sets DefaultMinVersion="1.3">
        <bt:Set Name="Mailbox"/>
      </bt:Sets>
    </Requirements>
    <Hosts>
      <Host xsi:type="MailHost">
        <DesktopFormFactor>
          <ExtensionPoint xsi:type="MessageReadCommandSurface">
            <OfficeTab id="TabDefault">
              <Group id="phishlensGroup">
                <Label resid="groupLabel"/>
                <Control xsi:type="Button" id="phishlensReport">
                  <Label resid="buttonLabel"/>
                  <Supertip>
                    <Title resid="buttonLabel"/>
                    <Description resid="buttonTip"/>
                  </Supertip>
                  <Icon>
                    <bt:Image size="16" resid="icon16"/>
                    <bt:Image size="32" resid="icon32"/>
                    <bt:Image size="80" resid="icon80"/>
                  </Icon>
                  <Action xsi:type="ShowTaskpane">
                    <SourceLocation resid="paneUrl"/>
                  </Action>
                </Control>
              </Group>
            </OfficeTab>
          </ExtensionPoint>
        </DesktopFormFactor>
      </Host>
    </Hosts>
    <Resources>
      <bt:Images>
        <bt:Image id="icon16" DefaultValue="{icon(16)}"/>
        <bt:Image id="icon32" DefaultValue="{icon(32)}"/>
        <bt:Image id="icon80" DefaultValue="{icon(80)}"/>
      </bt:Images>
      <bt:Urls>
        <bt:Url id="paneUrl" DefaultValue="{pane}"/>
      </bt:Urls>
      <bt:ShortStrings>
        <bt:String id="groupLabel" DefaultValue="PhishLens"/>
        <bt:String id="buttonLabel" DefaultValue="Report phishing"/>
      </bt:ShortStrings>
      <bt:LongStrings>
        <bt:String id="buttonTip" DefaultValue="Send this email to your security team to check for phishing."/>
      </bt:LongStrings>
    </Resources>
  </VersionOverrides>
</OfficeApp>
"""


def gmail_script(tenant: models.Tenant, token: str) -> str:
    """Google Apps Script for a Gmail add-on (Code.gs)."""
    endpoint = f"{_base()}/api/report-button/report"
    return f"""// PhishLens "Report phishing" Gmail add-on for {tenant.name}.
// Paste into a new Apps Script project (script.google.com) together with
// appsscript.json, then Deploy > Test deployments (just you) or publish it
// to your Google Workspace from the Google Cloud console.
var ENDPOINT = {endpoint!r};
var TOKEN = {token!r};  // can only submit reports; revoke it in the PhishLens dashboard

function onGmailMessageOpen(e) {{
  var action = CardService.newAction().setFunctionName('reportMessage');
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Report phishing'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(
        'Think this email is phishing? Send it to your security team. They will check the sender and the links.'))
      .addWidget(CardService.newTextButton().setText('Report this email')
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED).setOnClickAction(action)))
    .build();
}}

function reportMessage(e) {{
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var raw = GmailApp.getMessageById(e.gmail.messageId).getRawContent();
  var res = UrlFetchApp.fetch(ENDPOINT, {{
    method: 'post', contentType: 'message/rfc822', payload: raw, muteHttpExceptions: true,
    headers: {{'X-Report-Token': TOKEN, 'X-Reporter': Session.getActiveUser().getEmail()}}
  }});
  var ok = res.getResponseCode() < 300;
  var text = ok ? 'Thanks, your security team has it.' : 'Could not send the report (' + res.getResponseCode() + ').';
  if (ok) {{
    try {{ text += ' Verdict: ' + JSON.parse(res.getContentText()).verdict + '.'; }} catch (err) {{}}
  }}
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text)).build();
}}
"""


def gmail_manifest() -> str:
    """appsscript.json for the Gmail add-on."""
    host = _base().split("://", 1)[-1].split("/")[0]
    import json
    return json.dumps({
        "timeZone": "Etc/UTC",
        "exceptionLogging": "STACKDRIVER",
        "runtimeVersion": "V8",
        "oauthScopes": [
            "https://www.googleapis.com/auth/gmail.addons.execute",
            "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/script.external_request",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
        "urlFetchWhitelist": [f"https://{host}/"],
        "addOns": {
            "common": {"name": "Report phishing", "logoUrl": f"{_base()}/addins/icon-128.png"},
            "gmail": {"contextualTriggers": [{"unconditional": {}, "onTriggerFunction": "onGmailMessageOpen"}]},
        },
    }, indent=2)


def icon_png(size: int) -> bytes:
    """The PhishLens shield as a PNG (Office manifests need PNG icons)."""
    from PIL import Image, ImageDraw
    scale = 4
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    p = lambda x, y: (x / 32 * s, y / 32 * s)  # noqa: E731
    d.polygon([p(16, 2.5), p(27.5, 6.8), p(27.5, 15.2), p(23, 25), p(16, 29.5), p(9, 25), p(4.5, 15.2), p(4.5, 6.8)],
              fill=(31, 91, 216, 255))
    w = max(1, int(2.3 / 32 * s))
    d.ellipse([p(9.8, 9.4), p(20.2, 19.8)], outline="white", width=w)
    d.line([p(18.8, 18.4), p(22.4, 22)], fill="white", width=w)
    img = img.resize((size, size), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()
