package authservice

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeMCPRoles struct {
	allow    atomic.Bool
	err      error
	lastRole string
}

func (f *fakeMCPRoles) MCPAllowed(_ context.Context, _ string, role string) (bool, error) {
	f.lastRole = role
	return f.allow.Load(), f.err
}
func mcpTestServer(t *testing.T) (*Server, *fakeMCPRoles, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "get-profile") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"test-id","email":"ada@lab.local"}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "get-access-tokens") && r.Header.Get("Accept") == "application/json" {
			_, _ = io.WriteString(w, `[{"type":"mcp","token":"native-token","expires-at":null}]`)
			return
		}
		hits.Add(1)
		if strings.HasSuffix(r.URL.Path, "get-access-tokens") {
			w.Header().Set("Content-Type", transitContentType)
			_, _ = io.WriteString(w, `[["^ ","~:id","~u00112233-4455-6677-8899-001122334455","~:type","mcp","~:token","native-token"]]`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "create-access-token") {
			w.Header().Set("Content-Type", transitContentType)
			_, _ = io.WriteString(w, `["^ ","~:type","mcp","~:token","native-token"]`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "get-current-mcp-token") {
			w.Header().Set("Content-Type", transitContentType)
			_, _ = io.WriteString(w, `["^ ","~:token","native-token"]`)
			return
		}
		if r.URL.Path == "/mcp" {
			w.Header().Set("Mcp-Session-Id", "native-session")
			_, _ = io.WriteString(w, `{"ok":true}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(up.Close)
	cfg := &Config{MCPEnabled: true, MCPAccessRole: "mcp-access", MCPPublicOrigin: "https://uxstudio.lab.local", PenpotFrontendURL: up.URL, MCPServerURL: up.URL, MCPWSURL: up.URL, PenpotBackendURL: up.URL, PenpotRPCPath: "/api/rpc/command", ManagedPasswordSeed: strings.Repeat("x", 32)}
	roles := &fakeMCPRoles{}
	roles.allow.Store(true)
	s := NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.mcp = &mcpGuard{cfg: cfg, pp: NewPenpot(up.URL, cfg.PenpotRPCPath, cfg.ManagedPasswordSeed), roles: roles, allowed: map[string]cachedMCP{}, sessions: map[string]cachedMCP{"ada@lab.local": {time.Now().Add(time.Hour), "auth-token=managed"}}, slots: make(chan struct{}, 16)}
	return s, roles, hits
}
func mcpRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Cookie", "auth-token=browser")
	r.Header.Set("Content-Type", transitContentType)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestMCPEnvelopeTamperingAndSessionBinding(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	g := s.mcp
	token, err := g.wrap("ada@lab.local", "native-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.unwrap(token); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"native-token", token + "x", "ppm1.bad.bad", strings.Repeat("x", mcpTokenLimit+1)} {
		if _, err = g.unwrap(bad); err == nil {
			t.Fatal("accepted malformed or native token")
		}
	}
	other, _ := g.wrap("other@lab.local", "native-token")
	signed := g.signSession(token, "session-id")
	if id, err := g.session(token, signed); err != nil || id != "session-id" {
		t.Fatal("own session rejected")
	}
	if _, err := g.session(other, signed); err == nil {
		t.Fatal("cross-user session accepted")
	}
	if _, err := g.session(token, "native-session"); err == nil {
		t.Fatal("raw session accepted")
	}
}
func TestMCPSecurityAbuseUnauthorizedRoutes(t *testing.T) {
	s, roles, hits := mcpTestServer(t)
	roles.allow.Store(false)
	h := s.Handler()
	for _, prefix := range rpcPrefixes {
		for cmd := range mcpCommands {
			for _, method := range []string{"GET", "POST"} {
				w := mcpRequest(h, method, prefix+cmd, `["^ ","~:type","mcp"]`)
				if w.Code != 403 {
					t.Errorf("%s %s status %d", method, cmd, w.Code)
				}
			}
		}
	}
	for _, p := range []string{"/mcp", "/mcp/ws?userToken=native-token", "/mcp/stream?userToken=native-token", "/mcp/messages", "/mcp/sse", "/mcp/stream?userToken=a&userToken=b"} {
		if w := mcpRequest(h, "GET", p, ""); w.Code != 403 {
			t.Errorf("%s status %d", p, w.Code)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("unauthorized requests reached upstream: %d", hits.Load())
	}
	if roles.lastRole != "mcp-access" {
		t.Fatal("wrong role checked")
	}
}
func TestMCPSecurityAbusePathAndIdentityMutation(t *testing.T) {
	s, _, hits := mcpTestServer(t)
	h := s.Handler()
	for _, p := range []string{"/mcp//stream", "/mcp/../mcp/stream", "/mcp/%73tream", "/api/rpc/command/%67et-access-tokens", "/api//rpc/command/get-access-tokens"} {
		if w := mcpRequest(h, "GET", p, ""); w.Code != 400 {
			t.Errorf("%s status %d", p, w.Code)
		}
	}
	for _, prefix := range rpcPrefixes {
		for _, method := range []string{"GET", "POST", "PUT"} {
			if w := mcpRequest(h, method, prefix+"request-email-change", `{"email":"victim@lab.local"}`); w.Code != 403 {
				t.Errorf("email mutation %s status %d", method, w.Code)
			}
		}
	}
	if hits.Load() != 0 {
		t.Fatal("unsafe path reached upstream")
	}
}
func TestMCPAuthorizedOpaqueTokensAndCapability(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	h := s.Handler()
	cap := mcpRequest(h, "GET", "/auth-ui/capabilities", "")
	if cap.Code != 200 || !strings.Contains(cap.Body.String(), `"mcp":true`) {
		t.Fatalf("capability: %s", cap.Body.String())
	}
	for _, cmd := range []string{"get-access-tokens", "get-current-mcp-token", "create-access-token"} {
		w := mcpRequest(h, "POST", "/api/rpc/command/"+cmd, `["^ ","~:name","MCP","~:type","mcp"]`)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "ppm1.") || strings.Contains(w.Body.String(), `"native-token"`) {
			t.Fatalf("%s status=%d response=%s", cmd, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("token response cacheable")
		}
	}
	if w := mcpRequest(h, "POST", "/api/rpc/command/create-access-token", `["^ ","~:name","PAT"]`); w.Code != 403 {
		t.Fatal("non-MCP token accepted")
	}
}
func TestMCPRoleRevocationAndNativeTokenStatus(t *testing.T) {
	s, roles, _ := mcpTestServer(t)
	g := s.mcp
	token, _ := g.wrap("ada@lab.local", "native-token")
	if _, err := g.authorizeToken(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	roles.allow.Store(false)
	g.mu.Lock()
	clear(g.allowed)
	g.mu.Unlock()
	if _, err := g.authorizeToken(context.Background(), token); err == nil {
		t.Fatal("revoked role retained access")
	}
	roles.allow.Store(true)
	wrong, _ := g.wrap("ada@lab.local", "revoked-native-token")
	if _, err := g.authorizeToken(context.Background(), wrong); err == nil {
		t.Fatal("revoked native token accepted")
	}
}
func TestMCPOriginAndSessionIDSwap(t *testing.T) {
	s, _, hits := mcpTestServer(t)
	h := s.Handler()
	token, _ := s.mcp.wrap("ada@lab.local", "native-token")
	r := httptest.NewRequest("POST", "/mcp/stream?userToken="+token, strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin accepted")
	}
	r = httptest.NewRequest("POST", "/mcp/stream?userToken="+token, strings.NewReader(`{}`))
	r.Header.Set("Mcp-Session-Id", "native-session")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("unbound session accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("bad session reached upstream")
	}
	r = httptest.NewRequest("POST", "/mcp/stream?userToken="+token, strings.NewReader(`{}`))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("authorized stream %d", w.Code)
	}
	sid := w.Header().Get("Mcp-Session-Id")
	if id, err := s.mcp.session(token, sid); err != nil || id != "native-session" {
		t.Fatal("session response not bound")
	}
}
func TestTransitCacheTokenRewrite(t *testing.T) {
	body := []byte(`[["^ ","~:type","mcp","~:token","one"],["^ ","^0","mcp","^1","two"]]`)
	out, err := rewriteTokenBody(body, func(t string) (string, error) { return "wrapped-" + t, nil })
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if json.Unmarshal(out, &v) != nil || !strings.Contains(string(out), "wrapped-one") || !strings.Contains(string(out), "wrapped-two") {
		t.Fatalf("bad transit transform %s", out)
	}
}

func TestMCPSecurityAbuseMutationMethodsAndOrigin(t *testing.T) {
	s, _, hits := mcpTestServer(t)
	h := s.Handler()
	for _, cmd := range []string{"create-access-token", "delete-access-token"} {
		for _, suffix := range []string{"?type=access-token", "?profile-id=victim"} {
			if w := mcpRequest(h, "POST", "/api/rpc/command/"+cmd+suffix, `["^ ","~:type","mcp"]`); w.Code != 403 {
				t.Errorf("query override accepted %s", cmd)
			}
		}
		if w := mcpRequest(h, "GET", "/api/rpc/command/"+cmd, ""); w.Code != 403 {
			t.Errorf("GET mutation accepted %s", cmd)
		}
	}
	r := httptest.NewRequest("POST", "/api/rpc/command/create-access-token", strings.NewReader(`["^ ","~:type","mcp"]`))
	r.Header.Set("Cookie", "auth-token=browser")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-site accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("mutation abuse reached upstream")
	}
}
func TestMCPSecurityAbuseDuplicateSessionHeaderAndRateLimit(t *testing.T) {
	s, _, hits := mcpTestServer(t)
	h := s.Handler()
	token, _ := s.mcp.wrap("ada@lab.local", "native-token")
	r := httptest.NewRequest("POST", "/mcp/stream?userToken="+token, strings.NewReader(`{}`))
	r.Header.Add("Mcp-Session-Id", "first")
	r.Header.Add("Mcp-Session-Id", "second")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("duplicate session headers accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("duplicate reached upstream")
	}
	for i := 0; i < 120; i++ {
		s.mcp.admit("rate-test")
	}
	if s.mcp.admit("rate-test") {
		t.Fatal("rate limit not enforced")
	}
}
func TestMCPRejectMalformedNativeExpiryAndIdentityMismatch(t *testing.T) {
	for _, test := range []struct {
		name     string
		mismatch bool
		expiry   string
	}{{"malformed expiry", false, `123`}, {"email identity swap", true, `null`}} {
		t.Run(test.name, func(t *testing.T) {
			s, _, _ := mcpTestServer(t)
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "get-profile") {
					id := "managed-id"
					if r.Header.Get("Cookie") == "auth-token=browser" && test.mismatch {
						id = "attacker-id"
					}
					_, _ = io.WriteString(w, `{"id":"`+id+`","email":"ada@lab.local"}`)
					return
				}
				_, _ = io.WriteString(w, `[{"type":"mcp","token":"native-token","expires-at":`+test.expiry+`}]`)
			}))
			defer up.Close()
			s.mcp.pp.baseURL = up.URL
			if test.mismatch {
				if _, err := s.mcp.profile(context.Background(), "auth-token=browser"); err == nil {
					t.Fatal("managed identity mismatch accepted")
				}
			} else {
				token, _ := s.mcp.wrap("ada@lab.local", "native-token")
				if _, err := s.mcp.authorizeToken(context.Background(), token); err == nil {
					t.Fatal("malformed expiry accepted")
				}
			}
		})
	}
}
