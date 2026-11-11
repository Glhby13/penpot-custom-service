# Penpot MCP authorization — independent security review

Author / Agent: Codex (independent UI implementation agent reviewing MCP backend)
Timestamp: 2026-11-12 Asia/Jakarta

Status: **CONDITIONAL — local implementation reviewed; live validation pending**. This file records evidence and must be updated after final hardening and live abuse tests finish.

## Scope and method

Baseline: `fe4ef45`. Small Go gateway; high-risk change because it adds identity lookup, token wrapping and public MCP proxy authorization. Reviewed existing gateway auth boundaries, git blame of `Server.Handler`, upstream Penpot 2.18.4 profile/access-token commands, and MCP HTTP/WebSocket routing. No CodeGraph index exists; no index was created. Used `security-review` and `differential-review` instructions. Upstream image and compiled SPA bundles remain unchanged.

Attacker models: unauthenticated visitor; authenticated Penpot user without `mcp-access`; permitted role holder attempting cross-user MCP session use; previously authorized user after role removal. Trust boundaries: browser → gateway → native Penpot session/token RPC; gateway → Keycloak Admin API; gateway → official MCP HTTP/WebSocket service.

## Findings requiring closure

### F1 — High: mutable profile email can become MCP identity impersonation

Evidence: upstream `backend/src/app/rpc/commands/profile.clj`, tag `2.18.4`, lines 376–404. `request-email-change` accepts an email without the old password. With SMTP disabled, `change-email-immediately!` changes the current profile email immediately. Lab SMTP is disabled.

Concrete attack: a user without MCP role changes their Penpot email to an unused email belonging to a privileged Keycloak identity, then calls gateway capability/token issuance. A role lookup based on the new profile email would grant the victim's role. This is an escalation introduced by combining native mutable email with live Keycloak role lookup.

Required mitigation: prevent public email mutation across supported RPC aliases/methods, or bind Penpot profile ID to verified immutable AD subject. Consider previously issued `verify-token` change-email tokens if SMTP is enabled in another environment. Do not remove unrelated invitation verification without assessing its effects. Add an abuse regression covering the actual public command paths.

Status: **mitigated in reviewed implementation**. `guardMCP` rejects `request-email-change` for either RPC prefix before proxying, independent of HTTP method. `profile` also verifies that the derived managed-password login resolves to the same immutable Penpot profile ID. `TestMCPSecurityAbusePathAndIdentityMutation` covers public mutation rejection. Live checks remain required.

### F2 — High if unbound: upstream MCP session ID overrides provided user token

Evidence: upstream `mcp/packages/server/src/PenpotMcpServer.ts`, tag `2.18.4`, lines 357–425. A known `mcp-session-id` selects the stored `session.userToken`; the request's query token is ignored. Legacy `/messages?sessionId=...` similarly selects the stored token.

Concrete attack: a permitted MCP role holder who obtains another user's session ID sends that ID with their own valid gateway token. A gateway that only validates the incoming token allows the request, while upstream executes under the stored victim token.

Required mitigation: bind every accepted session identifier to the authenticated token owner, across gateway replicas; alternatively reject unsupported legacy transports. Test cross-owner and cross-token session reuse explicitly. Session IDs must not replace authentication.

Status: **mitigated in reviewed implementation**. `signSession`/`session` HMAC-bind the returned native ID to the entire authenticated gateway token; incoming raw/mismatched IDs are rejected. Legacy `/mcp/sse` and `/mcp/messages` are denied. `TestMCPEnvelopeTamperingAndSessionBinding` and `TestMCPOriginAndSessionIDSwap` cover raw/cross-token session IDs. Live transport checks remain required.

## Review observations sent for final hardening

- `authorizeToken` originally ignored a non-null, non-string expiry value. Require strict parsing of every non-null expiry or reject it, and test malformed/expired native rows. Actual stock serialization must be confirmed live.
- Enforce POST for `delete-access-token`, reject cross-site Fetch Metadata even if Origin is absent, and avoid query/body ambiguity on state-changing token RPCs. Upstream body parser merges body after query, so a body `type=mcp` presently wins over a conflicting query `type`, but rejecting ambiguity is simpler to maintain.
- Reject duplicate MCP session headers, not only an invalid first value.
- Native query-token URLs are bearer credentials. Disable/redact query logging at both edge nginx and ingress, as well as the gateway application.

## Additional required checks

- Both modern and legacy token RPC aliases; HTTP methods; encoded/noncanonical paths; raw token creation/listing/deprecated get-current token response.
- No admin bypass and no cross-client role acceptance; disabled/deleted Keycloak users denied; lookup outage fails closed.
- Browser Origin/CSRF handling on token RPC and WebSocket upgrade; duplicate query token rejection.
- Token integrity, expiry and owner binding; signing key domain separation; HTTP redirect handling; no secrets in logs/errors.
- Active WebSocket/SSE lifetime after role removal; state the actual revocation bound rather than promising instant revocation.
- Cluster routing/NetworkPolicy must prevent alternate public access directly to official MCP ports.

## UI checks completed

Nine Node tests pass for the shipped customization script: strict server capability boolean, no-store same-origin request, denied/malformed/outage fail-closed behavior, direct-route guard, SPA navigation, removed-role refresh, pending request hiding, Password route preservation, and scoped Enterprise promotion hiding while preserving renewal warnings. This is UI behavior verification, not backend authorization proof. `go test -count=1 ./internal/authservice` and `go test -race -count=1 ./internal/authservice` also passed during independent review, including the then-current MCP abuse tests.

The Enterprise card uses the exact stock 2.18.4 banner class plus English heading `Unlock Enterprise features` because upstream shares its banner class with renewal notices and provides no unique action/test identifier. Unknown language/heading leaves the promotion visible rather than hiding a potentially important warning. UI visibility never grants backend access.

## Coverage limits

At review time final hardening and lab deployment are still in progress, so no claim of final security approval or live abuse-test completion is made. The role-reader's real Keycloak HTTP behavior, enabled/deleted users, cluster bypass routing, and active WebSocket role-removal behavior must be checked by the lead's integration/live suite. Independent review does not prove absence of vulnerabilities. Final closure must reference concrete local tests, live tests, deployment image, and any remaining limitations.
