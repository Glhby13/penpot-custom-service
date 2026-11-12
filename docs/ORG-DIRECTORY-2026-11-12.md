# Organization (team) creation and directory search

Author / Agent: Claude Code (subagent)
Timestamp: 2026-11-12

## Decision
Penpot OSS has no Organization backend (proprietary Nitrate service; "+ CREATE ORG" is an upsell modal only).
"Organization" in UX Studio = a Penpot **team**, created with `create-team` using the user's **own** session
cookie, only for Keycloak users holding the Penpot client role `penpot-admin` (`ADMIN_ROLE`).

## API (contract shared with the frontend)
- `GET /auth-ui/capabilities` -> `{"mcp":bool,"org":bool}`; `org` is a live Keycloak check (<= 10 s cache), fail-closed.
- `POST /auth-ui/orgs` `{"name"}` -> `201 {"id","name"}`; 401 no session, 403 `{"error":"forbidden"}` no role,
  415 wrong content type, 403 cross-site, 400 invalid name/body (4 KB max, 1-64 chars, no control chars),
  429 (10/min/user), 503 Keycloak unreachable, 502 Penpot failure.
- `GET /auth-ui/directory/users?q=` -> `{"users":[{"username","name","email"}]}`; q 2-64 chars of letters, digits,
  space, `. - @ '`; max 10; enabled users with e-mail (and `EMAIL_DOMAIN`); 60/min/user; no-store; 502 on Keycloak error.

## Code
- `internal/authservice/org.go` (handlers, validation), `mcp.go` (`identity()` split from `profile()`: the org
  endpoints work with MCP off; capabilities now in `org.go`), `mcp_keycloak.go` (shared service-account helper
  `bearer/json/clientID`, lock held only for token refresh; `SearchUsers`), `penpot.go` (`postJSON`).
- Tests: `org_test.go` (capabilities, create abuse table, revoke, Penpot errors do not leak, rate limits,
  directory filters/injection/shape, escaping and race-free reader).

## Keycloak lab (not the office)
`python3 scripts/provision_org_lab.py [--check|--apply|--undo]` on `auth.lab.local`, realm `lab`, client `penpot-lab`.
- Before (2026-11-12): role `penpot-admin` existed on the client; group `/penpot/admin` did not exist; `lab-admin` and
  `lab-test` did not hold the role; service account already had view-users/query-users.
- After `--apply`: group `/penpot/admin` created and mapped to the role; `lab-admin` is a member (holds the role);
  `lab-test` does not. Idempotent (second run no changes).

## Office (🟡)
Create role + group `/penpot/admin` in the office Keycloak by hand, make sure the Penpot client's service account has
`view-users` + `query-users`, add the intended administrators to the group. No DDL, no new env. User runs it.

## Assumptions and risks
- Penpot accepts `application/json` request bodies for `create-team` with cookie auth and answers JSON with `id`/`name`;
  verified only against a fake upstream, confirm live in the lab after deploy.
- Rate limits and the capability cache are per replica (in memory).
- The directory is visible to every signed-in user (name, e-mail); restricted by `EMAIL_DOMAIN`.
- A user who loses the role keeps a team already created; only creation is gated.
