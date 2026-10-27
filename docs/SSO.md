# Single sign-on (OpenID Connect or SAML 2.0)

Works with any OIDC provider: Okta, Microsoft Entra ID, Google Workspace,
Auth0, OneLogin, JumpCloud, Keycloak. SAML-only providers (ADFS, PingFederate,
Shibboleth...) use the SAML section below.

## OpenID Connect

1. In the identity provider, create a **web application** (OIDC, authorization
   code flow). Redirect URI: `https://<your app>/api/auth/sso/callback` (the
   dashboard's SSO panel shows the exact value). Scopes: `openid email profile`.
2. In PhishLens → Dashboard → Single sign-on (owner), enter the issuer URL
   (e.g. `https://acme.okta.com`, `https://login.microsoftonline.com/<tenant id>/v2.0`,
   `https://accounts.google.com`), client id, client secret and your email
   domain.
3. Test "Sign in with SSO" on the login page in a private window.
4. Optionally tick **Require SSO for members**. Owners can still sign in with
   a password, so a broken IdP can't lock you out.

People from the email domain who sign in for the first time are added as
members. Client secrets are encrypted at rest with a key derived from
`SECRET_KEY`: if you rotate `SECRET_KEY`, re-enter the secret.

## SAML 2.0

1. In the identity provider, create a SAML app:
   - **Entity ID / Audience**: `https://<your app>/api/auth/saml/metadata`
     (that URL also serves PhishLens's metadata, if your IdP can import it)
   - **ACS / Reply URL**: `https://<your app>/api/auth/saml/acs` (HTTP-POST)
   - **Name ID**: the user's email address, or send an `email` attribute
   - Sign the assertion or the response (SHA-256). Leave **assertion
     encryption off**: it isn't supported.
2. In PhishLens → Dashboard → Single sign-on, choose **SAML 2.0** and paste
   the IdP's metadata XML (or its entity ID, sign-in URL and signing
   certificate), plus your email domain.
3. Test and optionally require SSO exactly as for OpenID Connect.

The sign-in state cookie is `SameSite=None; Secure`, because the IdP posts the
response back from its own site. SAML sign-in therefore needs PhishLens on
HTTPS (any real deployment); it won't work on plain `http://localhost`.
