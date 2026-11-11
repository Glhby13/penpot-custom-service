package authservice

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPKeycloakExactClientRoleAndEnabledUniqueUser(t *testing.T) {
	for _, tc := range []struct {
		name, users, roles string
		want               bool
	}{
		{"allowed", `[{"id":"user-id","email":"ada@lab.local","enabled":true}]`, `[{"name":"mcp-access"}]`, true},
		{"admin no bypass", `[{"id":"user-id","email":"ada@lab.local","enabled":true}]`, `[{"name":"penpot-admin"}]`, false},
		{"role exact case", `[{"id":"user-id","email":"ada@lab.local","enabled":true}]`, `[{"name":"MCP-ACCESS"}]`, false},
		{"disabled user", `[{"id":"user-id","email":"ada@lab.local","enabled":false}]`, `[{"name":"mcp-access"}]`, false},
		{"foreign email", `[{"id":"user-id","email":"other@lab.local","enabled":true}]`, `[{"name":"mcp-access"}]`, false},
		{"ambiguous email", `[{"id":"one","email":"ada@lab.local","enabled":true},{"id":"two","email":"ada@lab.local","enabled":true}]`, `[{"name":"mcp-access"}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/token"):
					_ = r.ParseForm()
					if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "penpot-lab" {
						t.Error("wrong token grant")
					}
					_, _ = io.WriteString(w, `{"access_token":"service-token","expires_in":60}`)
				case strings.HasSuffix(r.URL.Path, "/clients"):
					if r.URL.Query().Get("clientId") != "penpot-lab" {
						t.Error("wrong client scope")
					}
					_, _ = io.WriteString(w, `[{"id":"client-id","clientId":"penpot-lab"}]`)
				case strings.HasSuffix(r.URL.Path, "/users"):
					if r.URL.Query().Get("email") != "ada@lab.local" || r.URL.Query().Get("exact") != "true" {
						t.Error("inexact identity query")
					}
					_, _ = io.WriteString(w, tc.users)
				case strings.HasSuffix(r.URL.Path, "/users/user-id/role-mappings/clients/client-id/composite"):
					_, _ = io.WriteString(w, tc.roles)
				default:
					t.Errorf("unexpected lookup %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer up.Close()
			reader := &roleReader{kc: NewKeycloak(up.URL+"/realms/lab", "penpot-lab", "test-secret", false)}
			got, err := reader.MCPAllowed(context.Background(), "ada@lab.local", "mcp-access")
			if err != nil || got != tc.want {
				t.Fatalf("got %v err %v want %v", got, err, tc.want)
			}
		})
	}
}
func TestMCPKeycloakFailsClosed(t *testing.T) {
	for _, status := range []int{401, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status); _, _ = io.WriteString(w, `{}`) }))
			defer up.Close()
			r := &roleReader{kc: NewKeycloak(up.URL+"/realms/lab", "penpot-lab", "test-secret", false)}
			if allowed, err := r.MCPAllowed(context.Background(), "ada@lab.local", "mcp-access"); allowed || err == nil {
				t.Fatal("identity failure did not fail closed")
			}
		})
	}
}
