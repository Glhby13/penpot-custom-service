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
	cfg := &Config{MCPPublicOrigin: "https://uxstudio.lab.local", PenpotFrontendURL: up.URL, PenpotBackendURL: up.URL, PenpotRPCPath: "/api/rpc/command", ManagedPasswordSeed: strings.Repeat("x", 32), AdminRole: "penpot-admin", EmailDomain: domain}
	e.roles = &fakeOrgRoles{roles: map[string]bool{"penpot-admin": true}}
	e.s = NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.s.mcp = &mcpGuard{cfg: cfg, pp: NewPenpot(up.URL, cfg.PenpotRPCPath, cfg.ManagedPasswordSeed), roles: e.roles, allowed: map[string]cachedMCP{}, sessions: map[string]cachedMCP{"ada@lab.local": {time.Now().Add(time.Hour), "auth-token=managed"}}, slots: make(chan struct{}, 16)}
	e.h = e.s.Handler()
	return e
}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func noCookie() reqOpt              { return func(r *http.Request) { r.Header.Del("Cookie") } }

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

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %q", w.Body.String())
	}
	return m
}

func TestCapabilitiesOrg(t *testing.T) {
	for _, tc := range []struct {
		name   string
		admin  bool
		err    error
		cookie bool
		org    bool
	}{
		{"admin", true, nil, true, true},
		{"not admin", false, nil, true, false},
		{"keycloak down fails closed", true, errors.New("down"), true, false},
		{"no session", true, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newOrgEnv(t, "")
			e.roles.set("penpot-admin", tc.admin)
			e.roles.err = tc.err
			var opts []reqOpt
			if !tc.cookie {
				opts = append(opts, noCookie())
			}
			w := e.do("GET", "/auth-ui/capabilities", "", opts...)
			m := decode(t, w)
			if w.Code != 200 || m["org"] != tc.org || m["mcp"] != false {
				t.Fatalf("got %d %v", w.Code, m)
			}
			if w.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
				t.Fatal("missing hardening headers")
			}
		})
	}
}

func TestCapabilitiesAnonymousSessionIsNotAdmin(t *testing.T) {
	e := newOrgEnv(t, "")
	e.profile.Store(`{"id":"00000000-0000-0000-0000-000000000000","email":"ada@lab.local"}`)
	if m := decode(t, e.do("GET", "/auth-ui/capabilities", "")); m["org"] != false {
		t.Fatalf("anonymous session got org: %v", m)
	}
}

func TestCreateOrgSuccessUsesUserCookie(t *testing.T) {
	e := newOrgEnv(t, "")
	w := e.do("POST", "/auth-ui/orgs", `{"name":"  Design Team  "}`, withHeader("Origin", "https://uxstudio.lab.local"), withHeader("Sec-Fetch-Site", "same-origin"))
	m := decode(t, w)
	if w.Code != 201 || m["id"] != "team-1" || m["name"] != "Design Team" || len(m) != 2 {
		t.Fatalf("got %d %v", w.Code, m)
	}
	if e.teamCook.Load() != "auth-token=browser" {
		t.Fatalf("create-team did not use the caller's own cookie: %v", e.teamCook.Load())
	}
	if e.teamBody.Load() != `{"name":"Design Team"}` {
		t.Fatalf("body %v", e.teamBody.Load())
	}
}

func TestCreateOrgAbuse(t *testing.T) {
	long := strings.Repeat("a", 65)
	for _, tc := range []struct {
		name   string
		body   string
		opts   []reqOpt
		admin  bool
		kcErr  error
		want   int
		teamOK bool // upstream must have been called
	}{
		{"no session", `{"name":"x"}`, []reqOpt{noCookie()}, true, nil, 401, false},
		{"not admin", `{"name":"x"}`, nil, false, nil, 403, false},
		{"keycloak down", `{"name":"x"}`, nil, true, errors.New("down"), 503, false},
		{"cross-site fetch metadata", `{"name":"x"}`, []reqOpt{withHeader("Sec-Fetch-Site", "cross-site")}, true, nil, 403, false},
		{"same-site subdomain", `{"name":"x"}`, []reqOpt{withHeader("Sec-Fetch-Site", "same-site")}, true, nil, 403, false},
		{"foreign origin", `{"name":"x"}`, []reqOpt{withHeader("Origin", "https://evil.example")}, true, nil, 403, false},
		{"null origin", `{"name":"x"}`, []reqOpt{withHeader("Origin", "null")}, true, nil, 403, false},
		{"form content type", `{"name":"x"}`, []reqOpt{withHeader("Content-Type", "application/x-www-form-urlencoded")}, true, nil, 415, false},
		{"text/plain", `{"name":"x"}`, []reqOpt{withHeader("Content-Type", "text/plain")}, true, nil, 415, false},
		{"empty name", `{"name":""}`, nil, true, nil, 400, false},
		{"blank name", `{"name":"   "}`, nil, true, nil, 400, false},
		{"missing name", `{}`, nil, true, nil, 400, false},
		{"too long", `{"name":"` + long + `"}`, nil, true, nil, 400, false},
		{"control char", `{"name":"a\u0000b"}`, nil, true, nil, 400, false},
		{"newline", `{"name":"a\nb"}`, nil, true, nil, 400, false},
		{"zero width", "{\"name\":\"a\u200bb\"}", nil, true, nil, 400, false},
		{"line separator", `{"name":"a b"}`, nil, true, nil, 400, false},
		{"not json", `name=x`, nil, true, nil, 400, false},
		{"name not string", `{"name":123}`, nil, true, nil, 400, false},
		{"body over 4 KB", `{"name":"x","pad":"` + strings.Repeat("p", 5000) + `"}`, nil, true, nil, 400, false},
		{"64 chars ok", `{"name":"` + strings.Repeat("é", 64) + `"}`, nil, true, nil, 201, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newOrgEnv(t, "")
			e.roles.set("penpot-admin", tc.admin)
			e.roles.err = tc.kcErr
			w := e.do("POST", "/auth-ui/orgs", tc.body, tc.opts...)
			if w.Code != tc.want {
				t.Fatalf("got %d %s want %d", w.Code, w.Body.String(), tc.want)
			}
			if (e.teamHits.Load() > 0) != tc.teamOK {
				t.Fatalf("upstream create-team calls = %d", e.teamHits.Load())
			}
		})
	}
}

func TestCreateOrgRoleRevokedBetweenRequests(t *testing.T) {
	e := newOrgEnv(t, "")
	if w := e.do("GET", "/auth-ui/capabilities", ""); decode(t, w)["org"] != true {
		t.Fatal("expected admin")
	}
	e.roles.set("penpot-admin", false) // revoked right after a positive (cached) capability answer
	if w := e.do("POST", "/auth-ui/orgs", `{"name":"x"}`); w.Code != 403 || e.teamHits.Load() != 0 {
		t.Fatalf("revoked admin created an org: %d", w.Code)
	}
}

func TestCreateOrgPenpotAnswersDoNotLeak(t *testing.T) {
	for code, want := range map[int]int{400: 400, 403: 401, 401: 401, 429: 429, 500: 502, 502: 502} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			e := newOrgEnv(t, "")
			e.teamCode.Store(int32(code))
			w := e.do("POST", "/auth-ui/orgs", `{"name":"x"}`)
			if w.Code != want || strings.Contains(w.Body.String(), "secret-internal-detail") {
				t.Fatalf("got %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateOrgRateLimitPerUser(t *testing.T) {
	e := newOrgEnv(t, "")
	for i := 0; i < orgRatePerMin; i++ {
		if w := e.do("POST", "/auth-ui/orgs", `{"name":"x"}`); w.Code != 201 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if w := e.do("POST", "/auth-ui/orgs", `{"name":"x"}`); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("11th request: %d", w.Code)
	}
}

func TestCreateOrgWrongMethod(t *testing.T) {
	e := newOrgEnv(t, "")
	if w := e.do("GET", "/auth-ui/orgs", ""); w.Code == 200 || w.Code == 201 {
		t.Fatalf("GET allowed: %d", w.Code)
	}
}

func rows(n int) []directoryRow {
	out := make([]directoryRow, n)
	for i := range out {
		out[i] = directoryRow{Username: fmt.Sprintf("user%d", i), FirstName: "User", LastName: fmt.Sprint(i), Email: fmt.Sprintf("user%d@btn.co.id", i), Enabled: true}
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

// The native Penpot RPC must not be a way around the administrator rule.
func TestDirectTeamCreateRPCNeedsAdmin(t *testing.T) {
	for _, prefix := range rpcPrefixes {
		for cmd := range orgCommands {
			e := newOrgEnv(t, "")
			e.roles.set("penpot-admin", false)
			if w := e.do(http.MethodPost, prefix+cmd, `{"name":"x"}`); w.Code != 403 || e.teamHits.Load() != 0 {
				t.Fatalf("%s%s as non-admin: code %d, upstream hits %d", prefix, cmd, w.Code, e.teamHits.Load())
			}
			e.roles.set("penpot-admin", true)
			e.roles.err = errors.New("keycloak down")
			if w := e.do(http.MethodPost, prefix+cmd, `{"name":"x"}`); w.Code != 403 || e.teamHits.Load() != 0 {
				t.Fatalf("%s%s with identity error must fail closed: code %d", prefix, cmd, w.Code)
			}
		}
	}
	e := newOrgEnv(t, "")
	if w := e.do(http.MethodPost, "/api/rpc/command/create-team", `{"name":"x"}`, noCookie()); w.Code != 403 || e.teamHits.Load() != 0 {
		t.Fatalf("no session must be refused, got %d", w.Code)
	}
	if w := e.do(http.MethodPost, "/api/rpc/command/create-team", `{"name":"x"}`); w.Code != 200 || e.teamHits.Load() != 1 {
		t.Fatalf("admin must reach penpot: code %d hits %d", w.Code, e.teamHits.Load())
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
