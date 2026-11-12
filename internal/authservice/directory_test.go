package authservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeOrgRoles answers role lookups per role name and directory searches.
type fakeOrgRoles struct {
	mu       sync.Mutex
	roles    map[string]bool // role -> held
	err      error
	rows     []directoryRow
	searchEr error
	lastQ    string
	searches atomic.Int32
	inactive bool
}

func (f *fakeOrgRoles) MCPAllowed(_ context.Context, _ string, role string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roles[role], f.err
}
func (f *fakeOrgRoles) UserActive(context.Context, string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.inactive, f.err
}
func (f *fakeOrgRoles) set(role string, v bool) { f.mu.Lock(); f.roles[role] = v; f.mu.Unlock() }
func (f *fakeOrgRoles) SearchUsers(_ context.Context, q string, _ int) ([]directoryRow, error) {
	f.searches.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastQ = q
	return f.rows, f.searchEr
}

type orgEnv struct {
	s        *Server
	h        http.Handler
	roles    *fakeOrgRoles
	teamHits atomic.Int32
	teamBody atomic.Value // last create-team body
	teamCook atomic.Value // last create-team Cookie header
	teamCode atomic.Int32
	profile  atomic.Value // get-profile answer
}

func newOrgEnv(t *testing.T, domain string) *orgEnv {
	t.Helper()
	e := &orgEnv{}
	e.teamCode.Store(200)
	e.profile.Store(`{"id":"test-id","email":"ada@lab.local"}`)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "get-profile"):
			_, _ = io.WriteString(w, e.profile.Load().(string))
		case strings.HasSuffix(r.URL.Path, "create-team"):
			e.teamHits.Add(1)
			b, _ := io.ReadAll(r.Body)
			e.teamBody.Store(string(b))
			e.teamCook.Store(r.Header.Get("Cookie"))
			code := int(e.teamCode.Load())
			w.WriteHeader(code)
			if code == 200 {
				var in struct{ Name string }
				_ = json.Unmarshal(b, &in)
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "team-1", "name": in.Name, "extra": "x"})
			} else {
				_, _ = io.WriteString(w, `{"type":"internal","hint":"secret-internal-detail"}`)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(up.Close)
	cfg := &Config{MCPPublicOrigin: "https://uxstudio.lab.local", PenpotFrontendURL: up.URL, PenpotBackendURL: up.URL, PenpotRPCPath: "/api/rpc/command", ManagedPasswordSeed: strings.Repeat("x", 32), EmailDomain: domain}
	e.roles = &fakeOrgRoles{roles: map[string]bool{"penpot-admin": true}}
	e.s = NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.s.mcp = &mcpGuard{cfg: cfg, pp: NewPenpot(up.URL, cfg.PenpotRPCPath, cfg.ManagedPasswordSeed), roles: e.roles, allowed: map[string]cachedMCP{}, sessions: map[string]cachedMCP{"ada@lab.local": {time.Now().Add(time.Hour), "auth-token=managed"}}, slots: make(chan struct{}, 16)}
	e.h = e.s.Handler()
	return e
}

type reqOpt func(*http.Request)

func noCookie() reqOpt { return func(r *http.Request) { r.Header.Del("Cookie") } }

func (e *orgEnv) do(method, target, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Cookie", "auth-token=browser")
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// rows builds n enabled users of domain btn.co.id.
func rows(n int) []directoryRow {
	out := make([]directoryRow, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, directoryRow{Username: fmt.Sprintf("user%d", i), Email: fmt.Sprintf("user%d@btn.co.id", i), Enabled: true})
	}
	return out
}

func TestDirectoryFiltersAndShape(t *testing.T) {
	e := newOrgEnv(t, "btn.co.id")
	e.roles.rows = []directoryRow{
		{Username: "ok", FirstName: "Ok", LastName: "User", Email: "ok@BTN.co.id", Enabled: true},
		{Username: "disabled", Email: "d@btn.co.id", Enabled: false},
		{Username: "noemail", Enabled: true},
		{Username: "foreign", Email: "f@gmail.com", Enabled: true},
		{Username: "lookalike", Email: "l@evilbtn.co.id", Enabled: true},
		{Username: "service-account-x", Enabled: true},
	}
	w := e.do("GET", "/auth-ui/directory/users?q=ok", "")
	var out struct {
		Users []map[string]string `json:"users"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if len(out.Users) != 1 || out.Users[0]["username"] != "ok" || out.Users[0]["name"] != "Ok User" || out.Users[0]["email"] != "ok@BTN.co.id" || len(out.Users[0]) != 3 {
		t.Fatalf("got %v", out.Users)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("directory answer must not be cached")
	}
}

func TestDirectoryNoDomainStillNeedsEmail(t *testing.T) {
	e := newOrgEnv(t, "")
	e.roles.rows = []directoryRow{{Username: "a", Email: "a@x.org", Enabled: true}, {Username: "b", Enabled: true}}
	var out struct{ Users []map[string]string }
	_ = json.Unmarshal(e.do("GET", "/auth-ui/directory/users?q=ab", "").Body.Bytes(), &out)
	if len(out.Users) != 1 || out.Users[0]["username"] != "a" {
		t.Fatalf("got %v", out.Users)
	}
}

func TestDirectoryMaxTen(t *testing.T) {
	e := newOrgEnv(t, "btn.co.id")
	e.roles.rows = rows(30)
	var out struct{ Users []map[string]string }
	_ = json.Unmarshal(e.do("GET", "/auth-ui/directory/users?q=user", "").Body.Bytes(), &out)
	if len(out.Users) != 10 {
		t.Fatalf("got %d", len(out.Users))
	}
}

func TestDirectoryQueryAbuse(t *testing.T) {
	for _, tc := range []struct {
		name, q string
		want    int
		search  bool
	}{
		{"missing", "", 200, false},
		{"one char", "a", 200, false},
		{"spaces only", "%20%20%20", 200, false},
		{"two chars", "ab", 200, true},
		{"64 chars", strings.Repeat("a", 64), 200, true},
		{"65 chars", strings.Repeat("a", 65), 400, false},
		{"null byte", "ab%00", 400, false},
		{"ampersand", "ab%26enabled%3Dfalse", 400, false},
		{"star", "ab*", 400, false},
		{"lone star", "**", 400, false},
		{"percent literal", "ab%25", 400, false},
		{"underscore", "a_", 400, false},
		{"newline", "ab%0Ac", 400, false},
		{"slash", "ab%2F..", 400, false},
		{"unicode name", "Jos%C3%A9", 200, true},
		{"email", "ada@btn.co.id", 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newOrgEnv(t, "")
			w := e.do("GET", "/auth-ui/directory/users?q="+tc.q, "")
			if w.Code != tc.want {
				t.Fatalf("got %d %s", w.Code, w.Body.String())
			}
			if (e.roles.searches.Load() > 0) != tc.search {
				t.Fatalf("keycloak searches = %d", e.roles.searches.Load())
			}
		})
	}
}

func TestDirectoryAuthAndFailures(t *testing.T) {
	e := newOrgEnv(t, "")
	if w := e.do("GET", "/auth-ui/directory/users?q=ab", "", noCookie()); w.Code != 401 || e.roles.searches.Load() != 0 {
		t.Fatalf("no session: %d", w.Code)
	}
	// Any signed-in user may search, administrator or not.
	e.roles.set("penpot-admin", false)
	if w := e.do("GET", "/auth-ui/directory/users?q=ab", ""); w.Code != 200 {
		t.Fatalf("non-admin: %d", w.Code)
	}
	e.roles.searchEr = errors.New("keycloak says: secret-internal-detail")
	w := e.do("GET", "/auth-ui/directory/users?q=ab", "")
	if w.Code != 502 || strings.Contains(w.Body.String(), "secret-internal-detail") {
		t.Fatalf("keycloak error: %d %s", w.Code, w.Body.String())
	}
}

func TestDirectoryRateLimit(t *testing.T) {
	e := newOrgEnv(t, "")
	for i := 0; i < dirRatePerMin; i++ {
		if w := e.do("GET", "/auth-ui/directory/users?q=ab", ""); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if w := e.do("GET", "/auth-ui/directory/users?q=ab", ""); w.Code != 429 {
		t.Fatalf("61st request: %d", w.Code)
	}
}

func TestRoleReaderSearchUsersEscapesQueryAndUsesServiceAccount(t *testing.T) {
	var raw atomic.Value
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" {
				t.Error("wrong grant")
			}
			_, _ = io.WriteString(w, `{"access_token":"service-token","expires_in":60}`)
		case strings.HasSuffix(r.URL.Path, "/users"):
			if r.Header.Get("Authorization") != "Bearer service-token" {
				t.Error("search without the service account token")
			}
			raw.Store(r.URL.RawQuery)
			_, _ = io.WriteString(w, `[{"username":"u","email":"u@lab.local","enabled":true}]`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer up.Close()
	rr := &roleReader{kc: NewKeycloak(up.URL+"/realms/lab", "penpot-lab", "test-secret", false)}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // concurrent use must be race free
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := rr.SearchUsers(context.Background(), "a b&max=1000#x", 50); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := raw.Load(); got != "search=a+b%26max%3D1000%23x&max=50&enabled=true&briefRepresentation=true" {
		t.Fatalf("query not escaped: %v", got)
	}
}

func TestRoleReaderSearchUsersFailsClosed(t *testing.T) {
	for _, status := range []int{401, 403, 500} {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		rr := &roleReader{kc: NewKeycloak(up.URL+"/realms/lab", "penpot-lab", "test-secret", false)}
		if rows, err := rr.SearchUsers(context.Background(), "ab", 10); err == nil || rows != nil {
			t.Fatalf("status %d did not fail", status)
		}
		up.Close()
	}
}

// Team creation is Penpot's own and open to every signed-in user: the guard must not block it.
func TestTeamCreateRPCIsNotRestricted(t *testing.T) {
	for _, prefix := range rpcPrefixes {
		e := newOrgEnv(t, "")
		e.roles.set("penpot-admin", false)
		if w := e.do(http.MethodPost, prefix+"create-team", `{"name":"x"}`); w.Code != 200 || e.teamHits.Load() != 1 {
			t.Fatalf("%screate-team as an ordinary user: code %d, upstream hits %d", prefix, w.Code, e.teamHits.Load())
		}
	}
}

func TestDirectoryRefusesInactiveCaller(t *testing.T) {
	e := newOrgEnv(t, "")
	e.roles.rows = []directoryRow{{Username: "bob", Email: "bob@lab.local", Enabled: true}}
	e.roles.inactive = true
	if w := e.do(http.MethodGet, "/auth-ui/directory/users?q=bo", ""); w.Code != 403 || e.roles.searches.Load() != 0 {
		t.Fatalf("disabled account must not search: code %d searches %d", w.Code, e.roles.searches.Load())
	}
	e.roles.inactive = false
	e.roles.err = errors.New("keycloak down")
	if w := e.do(http.MethodGet, "/auth-ui/directory/users?q=bo", ""); w.Code != 403 {
		t.Fatalf("identity error must fail closed, got %d", w.Code)
	}
}

func TestLimiterAllowIsAtomic(t *testing.T) {
	l := newLimiter()
	var granted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.allow("k", 10, time.Minute) {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()
	if granted.Load() != 10 {
		t.Fatalf("burst granted %d, want exactly 10", granted.Load())
	}
}
