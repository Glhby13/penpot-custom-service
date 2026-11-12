# Directory search for team invitations (UX Studio)

Author / Agent: Claude Code (claude-sonnet-5-5)
Timestamp: 2026-11-12 Asia/Jakarta

## What
`GET /auth-ui/directory/users?q=` (penpot-auth-service) feeds the autocomplete in Penpot's "Invite members to the team"
dialog: typing 2+ characters lists enabled Keycloak users (name, username, e-mail); picking one adds the e-mail chip.
Rules and limits: README "Directory search for team invitations". Tests: `internal/authservice/directory_test.go`,
`web/customize.test.cjs`.

## Cancelled the same day: "Create org (admin only)"
An "organization" would only have been a Penpot team (Penpot OSS has no organization backend). The user chose Penpot's
own teams for everybody. Removed: `/auth-ui/orgs`, `org` capability, `ADMIN_ROLE`, team-create guard, Keycloak role and
group `penpot-admin` on the lab realm. The stock "+ Create org" button is hidden (it only opens an Enterprise upsell).

## Office (BTN) steps - status 🟡
No role/group needed. The Penpot client's service account needs the realm-management roles `view-users` and
`query-users` (same as the MCP role lookup). `EMAIL_DOMAIN` limits the directory to one domain. No DDL, no new env.
