#!/usr/bin/env python3
"""Provision the Penpot lab "organization (team) creation" role in Keycloak. Idempotent.

Author / Agent: Claude Code (subagent). 2026-11-12. No passwords/tokens are printed.

Ensures, on the lab Keycloak only (auth.lab.local, realm lab):
  - client role `penpot-admin` on the Penpot client (`penpot-lab`);
  - group `/penpot/admin` mapped to that role;
  - the Penpot client's service account can search users (realm-management view-users, query-users);
  - the lab administrator user (`lab-admin`) is a member of `/penpot/admin`.
Anyone else gets the right only by being added to `/penpot/admin` (never done here).

  (no flag)  --check  read-only report (default)
  --apply             create what is missing
  --undo              remove the group membership of lab-admin, the group `/penpot/admin` and the role
                      (service-account roles are shared with the MCP provisioning and are left alone)
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/e2e"))
import kc  # noqa: E402

CLIENT = "penpot-lab"
ROLE = "penpot-admin"
GROUP = "admin"
ADMIN_USER = "lab-admin"
CHECK_USERS = ("lab-admin", "lab-test")
SA_ROLES = {"view-users", "query-users"}


def effective_roles(user_id, cid):
    return {r["name"] for r in kc.api("GET", f"/users/{user_id}/role-mappings/clients/{cid}/composite")}


def find_user(name):
    users = kc.api("GET", f"/users?username={name}&exact=true")
    return users[0] if users else None


def report(cid, label):
    print(f"-- user roles ({label})")
    for name in CHECK_USERS:
        u = find_user(name)
        if not u:
            print(f"   {name}: user not found")
            continue
        print(f"   {name}: {ROLE} = {ROLE in effective_roles(u['id'], cid)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="read-only (default)")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--undo", action="store_true")
    args = ap.parse_args()
    if args.apply and args.undo:
        raise SystemExit("choose --apply or --undo")

    clients = kc.api("GET", f"/clients?clientId={CLIENT}")
    if len(clients) != 1:
        raise SystemExit(f"expected exactly one client {CLIENT}")
    cl = clients[0]
    cid = cl["id"]
    report(cid, "before")

    role = next((r for r in kc.api("GET", f"/clients/{cid}/roles") if r["name"] == ROLE), None)
    tops = kc.api("GET", "/groups?search=penpot&max=100")
    parent = next((g for g in tops if g.get("name") == "penpot"), None)
    group = None
    if parent:
        group = next((g for g in kc.api("GET", f"/groups/{parent['id']}/children?max=100") if g.get("name") == GROUP), None)

    if args.undo:
        admin = find_user(ADMIN_USER)
        if admin and group:
            kc.api("DELETE", f"/users/{admin['id']}/groups/{group['id']}")
        if group:
            kc.api("DELETE", f"/groups/{group['id']}")
        if role:
            kc.api("DELETE", f"/clients/{cid}/roles/{ROLE}")
        print("undone: lab-admin membership, group /penpot/admin, role", ROLE)
        report(cid, "after")
        return

    apply = args.apply
    if not role and apply:
        kc.api("POST", f"/clients/{cid}/roles", {"name": ROLE, "description": "May create organizations (teams) in Penpot"})
        role = next(r for r in kc.api("GET", f"/clients/{cid}/roles") if r["name"] == ROLE)
    print(f"client role {ROLE}:", "ok" if role else "MISSING")

    if not parent and apply:
        parent = {"id": kc.api("POST", "/groups", {"name": "penpot"})}
    if parent and not group and apply:
        group = {"id": kc.api("POST", f"/groups/{parent['id']}/children", {"name": GROUP})}
    print(f"group /penpot/{GROUP}:", "ok" if group else "MISSING")

    if role and group:
        mapped = any(r["id"] == role["id"] for r in kc.api("GET", f"/groups/{group['id']}/role-mappings/clients/{cid}"))
        if not mapped and apply:
            kc.api("POST", f"/groups/{group['id']}/role-mappings/clients/{cid}", [role])
            mapped = True
        print("group maps role:", "ok" if mapped else "MISSING")

    if cl.get("serviceAccountsEnabled"):
        sa = kc.api("GET", f"/clients/{cid}/service-account-user")
        rm = kc.api("GET", "/clients?clientId=realm-management")[0]["id"]
        wanted = [r for r in kc.api("GET", f"/clients/{rm}/roles") if r["name"] in SA_ROLES]
        if len(wanted) != len(SA_ROLES):
            raise SystemExit("realm-management roles view-users/query-users not found")
        have = kc.api("GET", f"/users/{sa['id']}/role-mappings/clients/{rm}/composite")
        missing = [r for r in wanted if not any(h["id"] == r["id"] for h in have)]
        if missing and apply:
            kc.api("POST", f"/users/{sa['id']}/role-mappings/clients/{rm}", missing)
            missing = []
        print("service account user search roles:", "ok" if not missing else "MISSING")
    else:
        print("service account: DISABLED on the client (run provision_mcp_lab.py --apply first)")

    if group:
        admin = find_user(ADMIN_USER)
        if admin:
            member = any(g["id"] == group["id"] for g in kc.api("GET", f"/users/{admin['id']}/groups"))
            if not member and apply:
                kc.api("PUT", f"/users/{admin['id']}/groups/{group['id']}")
                member = True
            print(f"{ADMIN_USER} in /penpot/{GROUP}:", "ok" if member else "NO")
    if not apply:
        print("(read-only; run with --apply to create what is missing)")
    report(cid, "after")


if __name__ == "__main__":
    main()
