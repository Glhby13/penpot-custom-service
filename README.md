# penpot-custom-service

`auth-service` lets AD users sign in to Penpot with their AD account, on its own sign-in page (or Penpot's own form),
without a redirect to Keycloak. Same idea as the n8n `auth-service` (Keycloak direct grant), adapted to Penpot.

## How it works

```
browser ──POST login-with-password──> ingress (exact path) ──> penpot-auth-service
                                                                 │ 1. Keycloak direct grant (client penpot-<env>)
                                                                 │ 2. role ACCESS_ROLE required (empty = any AD user)
                                                                 │ 3. Penpot backend (in cluster, not via ingress):
                                                                 │      login-with-password with the managed password;
                                                                 │      on first sign-in prepare-register-profile +
                                                                 │      register-profile (creates the profile)
browser <── Penpot's own answer + its session cookie ────────────┘
```

- The user types the AD e-mail and password. Penpot never sees the AD password.
- Penpot's own password for the profile is `HMAC-SHA256(MANAGED_PASSWORD_SEED, email)`; nobody knows or types it.
- The ingress also routes the commands that would bypass AD (register, password recovery, change password, LDAP/OIDC
  login) to this service, which refuses them with 403. Penpot's backend needs `enable-registration` internally for
  the first-time profile creation, so that flag stays on; the ingress is what keeps the public out.
- Only the Penpot login/registration RPC commands are used (no database access).

## Sign-in page

Penpot's own login screen is a route inside its single-page app (`#/auth/login`), which the server never sees, so it
cannot be restyled from outside. Instead this service is the **only entry point of the Penpot host** (like the
DrawSpace gateway): its ingress owns `/` (Prefix) and the Penpot chart's own ingress is disabled
(`ingress.enabled: false`), because ingress-nginx refuses two Ingresses with the same host and path. Everything is
proxied to the Penpot frontend Service, including uploads, event streams and WebSockets (no read/write timeouts in the
server, 100m body and 3600 s timeouts on the ingress). The sign-in and the refused commands are handled inside.

- no Penpot session -> the sign-in page (`web/`, light/dark, "Sign in with AD BTN"; the user types the AD username,
  no e-mail needed). It posts to `POST /auth-ui/login`, which does the same sign-in as below and sets Penpot's cookie.
- signed in -> the request is proxied to the Penpot frontend (`PENPOT_FRONTEND_URL`) and one `<script>` is added to
  its HTML. The script sends `#/auth/login` (session expired, sign-out) back to `/`, at most once per 10 s.
- the session check is Penpot's own `get-profile`. If it fails for any reason the request goes to Penpot, so the
  worst case is Penpot's original login screen (which still works through the same service), never a loop.

Because all Penpot traffic passes through this service it must stay available (2 replicas + PDB). **Roll back** to
the plain Penpot by setting `ingress.enabled: true` in `penpot/values-env-dev.yaml` and removing the `/` path from
this service's ingress (do both, or the webhook refuses the duplicate). Replace `web/logo.svg` with the real logo.

**Cut-over order** (both Applications are in one namespace and the webhook refuses duplicates): sync the Penpot
Application first (it removes its Ingress; Penpot is down from then), then sync `penpot-custom-auth-service-...`
right away. If Argo gave up on the second one after its retries, press Sync on it.

## Keycloak setup (per environment, by hand)

1. Client `Penpot-<Env>` (the name must equal `OIDC_CLIENT_ID`, case included): confidential, **Direct access grants
   ON**, service accounts not needed. Copy the secret.
2. **Every AD user may sign in; no role is needed for that** (`ACCESS_ROLE` is empty). The only client role is
   `penpot-admin` (Penpot administrators, later administrators; MCP uses the separate `mcp-access` role, see "MCP access by Keycloak role"); assign it
   to the admin AD group. Do not create `penpot-access` / `penpot-user`, and do **not** run
   `keycloak_require_access_role.py` (it would refuse users without a role; `--undo` removes it). To restrict
   sign-in later, set `ACCESS_ROLE` and give that role to the allowed groups.
3. "Login with email" is **not** needed. Users type their AD username on the sign-in page (`user@<EMAIL_DOMAIN>` also
   works, and is what Penpot's own form needs); the service sends the part before the `@` to Keycloak as the username
   and refuses other domains. Each user needs an e-mail in Keycloak: the Penpot profile is created from it.
4. Direct Grant flow for the client: the built-in `direct grant` works. If an OTP step is bound to the client, remove
   it (the page has no code field).
5. Check in Clients > Penpot-Dev > Client scopes > Evaluate that the access token has an `email` and, for an admin,
   `resource_access.Penpot-Dev.roles` containing `penpot-admin`.

## Break-glass local account

"Sign in with local account" on the page signs in a **Penpot-local** account (one with its own password, created by a
Penpot administrator, not through AD). It is hidden unless `LOCAL_ACCOUNTS` lists the e-mail address(es) allowed to use
it (comma separated). Only those addresses reach Penpot's login; each has the same lock-out as AD sign-in (5 failures
per 15 min) and every use is logged as `break-glass local sign-in` (warning). The user types the **full e-mail** as the
username. Penpot's own form (shown when the page is bypassed) never signs in local accounts. Create the account with
the Penpot admin console / prepl, give it a long random password kept in the password vault, and do not use an e-mail
address that also exists in AD (AD sign-in of that address would then fail).

## Cluster setup

1. Secret `penpot-auth-service-secret` in `platform-<env>` with `OIDC_CLIENT_SECRET` and `MANAGED_PASSWORD_SEED`
   (`openssl rand -hex 32`). The seed must never change.
2. Harbor project `penpot-custom-service`; Jenkins job on this repo (the Jenkinsfile bumps `image.tag` in
   `helm-values/platform-manifest/penpot-custom-service/auth-service/values-env-<env>.yaml`).
3. Register the AppProject `penpot-custom-projects` and the ApplicationSet after the first build.

## Verify against the live Penpot (not testable offline)

Open the browser dev tools on the login page and confirm:
- the form posts to `/api/rpc/command/login-with-password` or `/api/main/methods/login-with-password` (both are routed),
  with a transit+json body;
- the backend Service name and port in `PENPOT_BACKEND_URL` (`kubectl get svc | grep penpot`);
- `register-profile` returns a `Set-Cookie` (needs `disable-email-verification`, already set);
- error messages: a wrong password shows Penpot's "incorrect credentials"; a user without the role shows the
  "profile blocked" message.

## MCP access by Keycloak role

MCP uses the original Penpot MCP image. Enable the upstream `enable-mcp` flag and one MCP replica,
then configure this gateway with:

| Environment | Purpose |
|---|---|
| `MCP_ENABLED=true` | Opt-in global switch; false denies everybody |
| `MCP_ACCESS_ROLE=mcp-access` | Required **Penpot client role**, exact case; no admin bypass |
| `MCP_PUBLIC_ORIGIN=https://uxstudio.lab.local` | Allowed browser origin |
| `MCP_SERVER_URL=http://penpot-mcp:4401` | Internal official Streamable HTTP service |
| `MCP_WS_URL=http://penpot-mcp:4402` | Internal official plugin WebSocket service |

Map `/penpot/mcp-access` to the client role in Keycloak. The Penpot client's service account needs
read-only user/client lookup and effective client role-mapping lookup (`view-users`, `query-users`,
`query-clients`, `view-clients` in the lab). No user-management write permission is needed.

`GET /auth-ui/capabilities` verifies the native Penpot session and its managed identity before returning
`{ "mcp": true|false }`. Integrations and MCP entry points are hidden for users without the role;
direct token RPCs and MCP connections are independently checked server-side. Local break-glass accounts
cannot obtain MCP access because they do not have an AD-managed profile password.

The gateway protects `create-access-token` (MCP type only), `get-access-tokens`,
`get-current-mcp-token`, and `delete-access-token` on both current and legacy RPC prefixes.
Create/delete require POST without query parameters. Public email-change requests are blocked;
managed-profile ID verification also prevents an email-changing profile from impersonating a different AD identity.
Password menu and its existing backend guard remain unchanged.

Penpot MCP tokens are opaque native JWEs. The gateway wraps tokens issued/listed through it in a
versioned HMAC-authenticated envelope (`ppm1`), using a domain-separated key derived from the existing
managed-password seed. Only signed envelopes are accepted at `/mcp/stream` and `/mcp/ws`.
Their native token must still be present as an unexpired MCP token on the owner's native Penpot account.
Raw native tokens, malformed envelopes, duplicate token/session parameters, and cross-user MCP session IDs are rejected.
Returned Streamable HTTP session IDs are signed and bound to their exact MCP token.

The gateway sends MCP traffic directly to the official MCP service, avoiding native frontend query logs.
**Disable access logging for the Penpot ingress and its edge MCP locations:** upstream's protocol carries
`userToken` in the URL, which is a credential and must not appear in access logs. The MCP service is private
and must be reachable only from the gateway (NetworkPolicy); its debug/REPL ports are not exposed.

Authorization fails closed if identity/token validation is unavailable. Positive role/native-token checks
are cached for at most 15 seconds; active WebSockets are rechecked every 15 seconds and identity lookup has a
5-second deadline (revocation closes them within approximately 35 seconds). Stream HTTP requests have a
30-second maximum duration, so an already admitted request may finish within approximately 45 seconds of
revocation. Expensive checks are bounded to 16 concurrent requests, with 120 MCP/capability requests per IP
per minute per gateway replica. These limits do not apply to ordinary design/file editing traffic.

## UI customizations

The official `disable-onboarding` flag suppresses first-user onboarding. Gateway-injected, same-origin
assets hide only the Enterprise trial banner identified by its upstream container and exact heading;
current plan/renewal notices remain available. Integrations visibility is driven by server capabilities,
refreshed periodically and denied on lookup failure. No original Penpot image is modified.

## Known limits

- A Penpot profile that already exists with its own (local) password cannot be taken over automatically: the sign-in
  fails with a generic error. Delete that profile in the Penpot admin console (or rename its e-mail) and the user's
  next AD sign-in creates a fresh one. Their files belong to the old profile.
- A removed AD user keeps an existing Penpot session until it expires, as with any session cookie.
- The failed-attempt counter lives in each pod's memory (5 per user / 20 per IP per 15 min per replica).
- The "Create an account" link stays visible on Penpot's login page; it leads to a refused request.

## Local checks

```
go vet ./... && go test -race ./...
node --test internal/authservice/web/customize.test.cjs
postman collection run postman/penpot-security.postman_collection.json --insecure
node e2e/mcp_abuse.mjs
```

## Riwayat perubahan penting

- 2026-11-12 — Claude Code: sign-out now also ends the Keycloak session (refresh token kept in memory per Penpot session, revoked on `logout`; lost on pod restart, then idle timeout applies) and Penpot's stock login route (`#/auth/login`) is hidden and redirected to the custom sign-in page at once. Frontend + auth-service only, no DDL/env. Lab only, office 🟡.
- 2026-11-12 — Codex: role-based MCP gateway and native-token/session binding, security abuse tests, first-user onboarding and Enterprise banner suppression; password UI retained.

Deployment/test evidence: [validation report](docs/VALIDATION-2026-11-12.md). Go1.27.4 is required; Go CI gates run sequentially. Lab acceptance account `lab-admin` was explicitly assigned the MCP group; this is a role grant, not an admin bypass.
