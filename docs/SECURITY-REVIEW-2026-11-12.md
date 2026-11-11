# Penpot MCP authorization — independent security review

Author / Agent: Codex (independent UI implementation agent reviewing MCP backend)
Timestamp: 2026-11-12 Asia/Jakarta

Status: **APPROVE WITH DOCUMENTED LIMITS — reviewed local implementation and live lab authorization/transport suite passed**. No remaining confirmed high/critical issue was found in the reviewed scope. This is not a guarantee that all vulnerabilities are absent.

## Scope and method

Baseline: `fe4ef45`. Small Go gateway; high-risk change because it adds identity lookup, token wrapping and public MCP proxy authorization. Reviewed existing gateway auth boundaries, git blame of `Server.Handler`, upstream Penpot 2.18.4 profile/access-token commands, and MCP HTTP/WebSocket routing. No CodeGraph index exists; no index was created. Used `security-review` and `differential-review` instructions. Upstream image and compiled SPA bundles remain unchanged.

Attacker models: unauthenticated visitor; authenticated Penpot user without `mcp-access`; permitted role holder attempting cross-user MCP session use; previously authorized user after role removal. Trust boundaries: browser → gateway → native Penpot session/token RPC; gateway → Keycloak Admin API; gateway → official MCP HTTP/WebSocket service.

## Findings requiring closure

### F1 — High: mutable profile email can become MCP identity impersonation

Evidence: upstream `backend/src/app/rpc/commands/profile.clj`, tag `2.18.4`, lines 376–404. `request-email-change` accepts an email without the old password. With SMTP disabled, `change-email-immediately!` changes the current profile email immediately. Lab SMTP is disabled.

Concrete attack: a user without MCP role changes their Penpot email to an unused email belonging to a privileged Keycloak identity, then calls gateway capability/token issuance. A role lookup based on the new profile email would grant the victim's role. This is an escalation introduced by combining native mutable email with live Keycloak role lookup.

Required mitigation: prevent public email mutation across supported RPC aliases/methods, or bind Penpot profile ID to verified immutable AD subject. Consider previously issued `verify-token` change-email tokens if SMTP is enabled in another environment. Do not remove unrelated invitation verification without assessing its effects. Add an abuse regression covering the actual public command paths.

Status: **mitigated and verified locally/live**. `guardMCP` rejects `request-email-change` for either RPC prefix before proxying, independent of HTTP method. `profile` also verifies that the derived managed-password login resolves to the same immutable Penpot profile ID. `TestMCPSecurityAbusePathAndIdentityMutation` covers public mutation rejection; live tests verify both RPC aliases reject it.

### F2 — High if unbound: upstream MCP session ID overrides provided user token

Evidence: upstream `mcp/packages/server/src/PenpotMcpServer.ts`, tag `2.18.4`, lines 357–425. A known `mcp-session-id` selects the stored `session.userToken`; the request's query token is ignored. Legacy `/messages?sessionId=...` similarly selects the stored token.

Concrete attack: a permitted MCP role holder who obtains another user's session ID sends that ID with their own valid gateway token. A gateway that only validates the incoming token allows the request, while upstream executes under the stored victim token.

Required mitigation: bind every accepted session identifier to the authenticated token owner, across gateway replicas; alternatively reject unsupported legacy transports. Test cross-owner and cross-token session reuse explicitly. Session IDs must not replace authentication.

Status: **mitigated and verified locally/live**. `signSession`/`session` HMAC-bind the returned native ID to the entire authenticated gateway token; incoming raw/mismatched IDs are rejected. Legacy `/mcp/sse` and `/mcp/messages` are denied. `TestMCPEnvelopeTamperingAndSessionBinding` and `TestMCPOriginAndSessionIDSwap` cover raw/cross-token session IDs. Live tests initialize official MCP and reject raw IDs and cross-user reuse between two permitted role holders.

## Review observations resolved before deployment

- `authorizeToken` rejects every non-null expiry that is not a parseable supported string.
- State-changing token RPCs require POST with no query overrides; cross-site Fetch Metadata is rejected even if Origin is absent. Real API abuse tests exercise these denials.
- Duplicate MCP session headers are rejected before proxying.
- MCP goes directly from gateway to official MCP ports, bypassing frontend access logs. Lead reports ingress access logging disabled and edge vhost access/error logging disabled for these native query-token URLs. The gateway does not log query credentials.

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

The live suite does not disable/delete a Keycloak account or modify other applications' roles. Those denials were assessed from the role-reader source, not destructively exercised. Cluster bypass NetworkPolicy tests, generic UI/template checks and final CI gates are owned/reported by the lead. Independent review does not prove absence of vulnerabilities.

## Live lab verification

Executed `node e2e/mcp_abuse.mjs` against gateway image `b6c3b9e3` and official Penpot MCP `2.18.4`: **55 passed, 0 failed**. The original run had one harness-only assertion expecting HTTP 200 for deletion; the native nil RPC uses another successful 2xx response. The old token was already denied in that run. The corrected complete rerun passed.

Verified against real Keycloak/Penpot/MCP:

- Role-holder and non-role/anonymous capabilities; both native RPC aliases; public email mutation and password guard; denied personal-token creation.
- Origin/Fetch Metadata, method/query override, legacy/encoded paths, missing/duplicate query credentials, malformed/tampered/raw native tokens.
- Official MCP initialize, gateway-bound session ID, cross-user session swap rejection.
- Official WebSocket establishment; an `execute_code` request and response traversing official MCP, Redis Pub/Sub and a synthetic WebSocket plugin. The synthetic plugin answers only one exact read-only marker and never evaluates code; this proves transport/ACL routing, not native canvas editing.
- Temporary removal of `lab-test` MCP assignment disables current capability, denies new token issuance and preexisting token HTTP use, and closes an already-open WebSocket within the tested bound. Role restoration restores capability without replacing the browser session.
- Native token deletion followed by cache expiry denies the old stream/token.

Cleanup: `lab-test` group/direct MCP mappings were snapshotted and restored exactly in `finally`, verified by reread. Test-created MCP tokens were deleted. The suite neither permanently grants `lab-admin` access nor edits document contents. All credentials/tokens remain in process memory and are omitted from test output.

Bounded behavior: positive role/token checks cache for 15 seconds; active WebSockets recheck periodically, while HTTP streams have a bounded lifetime. Tests wait for cache expiry and verify live denial/closure; this is not an instant-revocation promise and cannot cancel work already authorized before revocation.
