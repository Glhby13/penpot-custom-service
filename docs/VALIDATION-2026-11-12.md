# Penpot lab validation — MCP, managed UI and surrounding
Author / Agent: Codex
Timestamp: 2026-11-12 Asia/Jakarta

## Result

Implementation `b6c3b9e` built by Jenkins#7 SUCCESS and deployed as `auth-service:b6c3b9e3`. Official backend/frontend/exporter/admin-console/MCP images remain Penpot2.18.4. Values `a39d1c0`, chart `20629ed`; both Argo applications Synced/Healthy, all Penpot deployments available.

## Local evidence

- Go1.27.4: `go test -race -count=1 ./...`, `go vet ./...`, `golangci-lint run ./cmd/... ./internal/...`: PASS,0 lint issues.
- `govulncheck ./...`: no vulnerabilities. Initial Go1.27.2 scan identified GO-2026-6859 and GO-2026-6809; toolchain/base fallback upgraded to1.27.4 and rescanned.
- Node customization suite:9/9 PASS. Helm lint/template for Penpot and auth values PASS. Schema validates the opt-in gateway-only NetworkPolicy.
- Independent review found two High design issues (profile email impersonation and MCP session swapping); both mitigated and regression-tested before deployment. See `SECURITY-REVIEW-2026-11-12.md`.

## Live evidence

- `node e2e/mcp_abuse.mjs`:55 PASS,0 FAIL. Real Keycloak roles, native token RPCs and official MCP. Anonymous/nonrole denial, client-role exactness, no admin bypass, both RPC aliases, route/method/query ambiguity, CSRF/Origin checks, invalid/native envelopes, cross-user session reuse, token deletion and cache expiry, role removal/new issuance rejection, old token rejection and active WebSocket closure.
- Native Redis PubSub + WebSocket transport roundtrip exercised with a read-only synthetic plugin reply. This verifies the native transport and ACLs; it does not establish every official canvas plugin operation.
- Postman local collection:9/9 assertions PASS, no cloud publication. Installed CLI1.77 lacks `postman status`; collection execution works without login. No Postman initialization/account/config changes were needed.
- `e2e/live.mjs`: user without role8/8; lab-admin with explicit MCP group7/7. Menu visibility, direct-route guard, onboarding and Enterprise suppression, Password page retained.
- `TEST_TEMPLATE=true PENPOT_TEST_USER=lab-admin node e2e/live.mjs`:5/5. Official prototype template imported including assets, file read back, and opened in original editor.
- NetworkPolicy: an unrelated n8n pod could reach backend `/readyz` (positive control), while native MCP4401 timed out. Authorized gateway initializes/connects MCP successfully.
- Edge access/error logs disabled for both Penpot host server blocks; ingress access log disabled. Gateway routes native MCP directly (bypasses frontend query logs). Native MCP fingerprints only first8 characters, not full bearer values; no full envelope was observed in ingress logs.

Temporary lab-test MCP assignments restored, test tokens deleted. `lab-admin` is explicitly a member of `/penpot/mcp-access` for user acceptance testing; ordinary users remain without MCP role.

## Surrounding result

- SeaweedFS slot limit50→70, original unit backed up. After template import57 volumes registered;13 slots remain.
- Harbor7 projects/46 repositories:136→46 top-level artifacts,90 older artifacts removed after all dry-runs succeeded and no workload/Jenkins reference conflicts. GC4126 succeeded.
- Online harbor-registry vacuum completed. Logical data approximately6.61GB; deleted-byte remainder~13MB. Root disk55%→43%, free13GB→16GB.
- Ten-minute guarded retention cron on lab-bastion; native policy schedules unscheduled. Workload/CI conflicts or overlapping jobs stop deletion. Future projects are discovered dynamically. GC retains existing ten-minute schedule.

## Limits / user acceptance

Security testing establishes the scenarios above, not absence of all vulnerabilities. Positive role/native-token cache15s; active WS revocation target~35s and already admitted HTTP maximum~45s including deadlines. UI role refresh30s. Enterprise promo hiding is scoped to the English heading in stock2.18.4; another translation may leave it visible. Image rollback requires rebuilding an image that retention has removed.

Open `https://uxstudio.lab.local`, sign in again or reload, and use Account Settings → Integrations as lab-admin. MCP pairing must use the token/link supplied through this gateway; raw native tokens are intentionally rejected. Other users require the Penpot client-role group assignment.
