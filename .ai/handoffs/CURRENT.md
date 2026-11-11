# Penpot + lab surrounding implementation
Author / Agent: Codex
Timestamp: 2026-11-12 Asia/Jakarta

User authorized development, testing/security abuse, push, build and sync LAB only.

- [x] Plan and read-only checks: original Penpot 2.18.4, auth fe4ef454. MCP off.
- [x] Hide onboarding + Enterprise card; keep Password menu/guard.
- [x] MCP client role mcp-access / group /penpot/mcp-access; no admin bypass; server authorization.
- [x] SeaweedFS fix: audit confirms volume.max=50 fully occupied, disk 55%, 13GB free. Review slot increase.
- [x] Harbor all projects retain one latest artifact per repository; dry-run and active/CI conflict checks before apply; GC/vacuum.
- [x] Local tests and independent security review, push, Jenkins console watch, Argo rollout, live security abuse + template import.
- [x] README, office-sync tracking (lab only), final memory and completion checkpoint.

Parallel native agents: penpot_mcp owns auth/config/MCP; penpot_ui owns ui.go/web; storage_audit owns new scripts/report (no live mutation).
Implementation b6c3b9e; Jenkins#7 SUCCESS; live tag b6c3b9e3; values a39d1c0; chart20629ed. Both Argo apps Synced/Healthy. Live MCP abuse55/55; Postman9/9; UI8+7; template5; local race/vet/lint/SCA pass. Harbor136→46 artifacts; GC/vacuum done; disk55→43%. Role lab-admin explicitly granted; lab-test restored. Remaining milestone: commit/push validation artifacts, monitor documentation/test-only build, final smoke and memory. Unknown unrelated .opencode/opencode.json left untouched, not committed.
