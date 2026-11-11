#!/usr/bin/env python3
"""Provision Penpot lab MCP role/group + least-privilege role lookups.
Author / Agent: Codex. 2026-11-12. No passwords/tokens are printed.
Default is read-only; --apply changes only Penpot client service account, role and group.
"""
import argparse
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/e2e"))
import kc

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    clients = kc.api("GET", "/clients?clientId=penpot-lab")
    if len(clients) != 1:
        raise SystemExit("Expected exactly one penpot-lab client")
    cl = clients[0]
    cid = cl["id"]
    roles = kc.api("GET", f"/clients/{cid}/roles")
    role = next((r for r in roles if r["name"] == "mcp-access"), None)
    if not role and args.apply:
        kc.api("POST", f"/clients/{cid}/roles", {"name": "mcp-access", "description": "May use Penpot MCP integrations"})
        role = next(r for r in kc.api("GET", f"/clients/{cid}/roles") if r["name"] == "mcp-access")
    print("Penpot role mcp-access:", bool(role))
    tops = kc.api("GET", "/groups?search=penpot&max=100")
    parent = next((g for g in tops if g.get("name") == "penpot"), None)
    if not parent and args.apply:
        gid = kc.api("POST", "/groups", {"name": "penpot"})
        parent = {"id": gid}
    group = None
    if parent:
        kids = kc.api("GET", f"/groups/{parent['id']}/children?max=100")
        group = next((g for g in kids if g.get("name") == "mcp-access"), None)
        if not group and args.apply:
            gid = kc.api("POST", f"/groups/{parent['id']}/children", {"name": "mcp-access"})
            group = {"id": gid}
    if role and group:
        mappings = kc.api("GET", f"/groups/{group['id']}/role-mappings/clients/{cid}")
        if args.apply and not any(r["id"] == role["id"] for r in mappings):
            kc.api("POST", f"/groups/{group['id']}/role-mappings/clients/{cid}", [role])
    print("Penpot MCP group exists:", bool(group))
    if args.apply and not cl.get("serviceAccountsEnabled"):
        cl["serviceAccountsEnabled"] = True
        kc.api("PUT", f"/clients/{cid}", cl)
    if args.apply or cl.get("serviceAccountsEnabled"):
        sa = kc.api("GET", f"/clients/{cid}/service-account-user")
        rm = kc.api("GET", "/clients?clientId=realm-management")[0]["id"]
        available = kc.api("GET", f"/clients/{rm}/roles")
        required = {"view-users", "query-users", "query-clients", "view-clients"}
        wanted = [r for r in available if r["name"] in required]
        if len(wanted) != len(required):
            raise SystemExit("Missing realm-management read roles")
        have = kc.api("GET", f"/users/{sa['id']}/role-mappings/clients/{rm}")
        missing = [r for r in wanted if not any(h["id"] == r["id"] for h in have)]
        if args.apply and missing:
            kc.api("POST", f"/users/{sa['id']}/role-mappings/clients/{rm}", missing)
        print("Service-account read roles:", "configured" if args.apply or not missing else "missing")
    else:
        print("Service-account lookups: disabled")
    print("User membership unchanged; assign /penpot/mcp-access to intended people in Keycloak.")
if __name__ == "__main__":
    main()
