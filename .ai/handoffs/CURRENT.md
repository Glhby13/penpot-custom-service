# Penpot + lab surrounding implementation
Author / Agent: Codex
Timestamp: 2026-11-12 Asia/Jakarta

User authorized development, testing/security abuse, push, build and sync LAB only.

- [x] Plan and read-only checks: original Penpot 2.18.4, auth fe4ef454. MCP off.
- [ ] Hide onboarding + Enterprise card; keep Password menu/guard.
- [ ] MCP client role mcp-access / group /penpot/mcp-access; no admin bypass; server authorization.
- [ ] SeaweedFS fix: audit confirms volume.max=50 fully occupied, disk 55%, 13GB free. Review slot increase.
- [ ] Harbor all projects retain one latest artifact per repository; dry-run and active/CI conflict checks before apply; GC/vacuum.
- [ ] Local tests and independent security review, push, Jenkins console watch, Argo rollout, live security abuse + template import.
- [ ] README, office-sync tracking (lab only), final memory and completion checkpoint.

Parallel native agents: penpot_mcp owns auth/config/MCP; penpot_ui owns ui.go/web; storage_audit owns new scripts/report (no live mutation).
Next exact action: prepare surrounding values/provisioning and integrate agent output. No push performed yet.
