# Single sign-on (OpenID Connect)

Works with any OIDC provider: Okta, Microsoft Entra ID, Google Workspace,
Auth0, OneLogin, JumpCloud, Keycloak. (SAML-only providers can usually expose
an OIDC app as well.)

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
