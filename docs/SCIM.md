# SCIM user provisioning

PhishLens speaks SCIM 2.0 (RFC 7643/7644) so your identity provider can add,
update and remove team members for you. Pair it with SSO (`docs/SSO.md`) so
provisioned people sign in through the IdP.

## Turn it on

Dashboard → **Single sign-on** → SCIM provisioning (owners) → **Create SCIM
token**. Copy the token straight away; it's shown once. Creating a new token
replaces the old one, and **Turn off** deletes it.

- Base URL: `<APP_URL>/scim/v2` (for example `https://phishlens.example.com/scim/v2`)
- Authentication: HTTP header `Authorization: Bearer scim_...`

## Okta

Applications → your PhishLens app → General → App Settings → enable SCIM
provisioning. Provisioning tab:

- SCIM connector base URL: the base URL above
- Unique identifier field for users: `userName`
- Supported actions: Push New Users, Push Profile Updates
- Authentication mode: HTTP Header, paste the token

Then under To App enable Create Users, Update User Attributes and Deactivate
Users.

## Microsoft Entra ID

Enterprise applications → your PhishLens app → Provisioning → Automatic.

- Tenant URL: the base URL above
- Secret token: the token

Test Connection, keep the default user attribute mappings (`userName` from
`userPrincipalName`, `active` from `Switch([IsSoftDeleted]...)`), and turn
provisioning on. Entra's string booleans (`"False"`) are understood.

## What is synced

- **Users only.** `userName` (an email address) becomes the member's email;
  `active: false` or DELETE deactivates the member and signs them out
  everywhere. Reactivating restores access. New members join as `member`;
  change roles in PhishLens.
- **Owners** can't be changed or removed over SCIM, so a misconfigured IdP
  can't lock you out.
- `/Groups` answers with an empty list; group push isn't supported.
- Filters: `userName eq`, `emails.value eq`, `id eq` and `externalId eq`.
  Paging with `startIndex` and `count`.

Every SCIM change is in the team's audit log.
