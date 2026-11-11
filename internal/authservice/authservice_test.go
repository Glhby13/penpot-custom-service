package authservice

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDecodeLoginBodyTransit(t *testing.T) {
	body := `["^ ","~:email","Ada@BTN.co.id","~:password","~~secret"]`
	email, pw, err := decodeLoginBody(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if email != "ada@btn.co.id" || pw != "~secret" {
		t.Fatalf("got %q %q", email, pw)
	}
}

func TestDecodeLoginBodyJSON(t *testing.T) {
	email, pw, err := decodeLoginBody(strings.NewReader(`{"email":"a@b.id","password":"p"}`))
	if err != nil || email != "a@b.id" || pw != "p" {
		t.Fatalf("got %q %q %v", email, pw, err)
	}
}

func TestDecodeLoginBodyRejects(t *testing.T) {
	for _, b := range []string{``, `[]`, `["^ ","~:email","a@b.id"]`, `{"email":"","password":"x"}`, `"x"`} {
		if _, _, err := decodeLoginBody(strings.NewReader(b)); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func TestTransitEncoding(t *testing.T) {
	got := string(transitMap("email", transitEscape("a@b.id"), "password", transitEscape("^x\"y")))
	want := `["^ ","~:email","a@b.id","~:password","~^x\"y"]`
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if got := string(transitError("validation", "wrong-credentials", "no")); got != `["^ ","~:type","~:validation","~:code","~:wrong-credentials","~:hint","no"]` {
		t.Fatalf("got %s", got)
	}
}

func TestManagedPasswordStable(t *testing.T) {
	p := NewPenpot("http://x", "/api/rpc/command", strings.Repeat("s", 32))
	a, b := p.ManagedPassword("Ada@BTN.co.id"), p.ManagedPassword("ada@btn.co.id")
	if a != b || len(a) != 64 {
		t.Fatalf("not stable/64 hex: %q %q", a, b)
	}
	if a == NewPenpot("http://x", "/api/rpc/command", strings.Repeat("t", 32)).ManagedPassword("ada@btn.co.id") {
		t.Fatal("seed ignored")
	}
}

func TestParseClaimsReadsOnlyPenpotClientRoles(t *testing.T) {
	payload := `{"sub":"u1","email":"ada@btn.co.id","name":"Ada L","resource_access":{` +
		`"penpot-dev":{"roles":["penpot-access","penpot-admin"]},"other-app":{"roles":["penpot-admin-lookalike","x"]}}}`
	jwt := "h." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".s"
	c, err := parseClaims(jwt, "penpot-dev")
	if err != nil {
		t.Fatal(err)
	}
	if !c.HasRole("penpot-access") || !c.HasRole("penpot-admin") || c.HasRole("x") || c.DisplayName() != "Ada L" {
		t.Fatalf("%+v", c)
	}
	other, _ := parseClaims(jwt, "penpot-prod")
	if other.HasRole("penpot-access") {
		t.Fatal("roles of another client leaked")
	}
}

func TestExtractToken(t *testing.T) {
	tok, err := extractToken([]byte(`["^ ","~:token","abc.def"]`))
	if err != nil || tok != "abc.def" {
		t.Fatalf("got %q %v", tok, err)
	}
	if _, err := extractToken([]byte(`["^ ","~:other","x"]`)); err == nil {
		t.Fatal("expected error")
	}
}

// ---- handler flow with fakes ----------------------------------------------------------------------------------

type fakeKC struct {
	claims *Claims
	err    error
	calls  int
	user   string
}

func (f *fakeKC) DirectGrant(_ context.Context, username, _ string) (*Claims, error) {
	f.calls++
	f.user = username
	return f.claims, f.err
}

type fakePenpot struct {
	exists     bool // a profile with the managed password exists
	localOnly  bool // a profile exists with a different password
	registered int
	logins     int
	anon       bool // the session check says "not signed in"
	anonErr    error
	localOK    bool // the typed password of a local account is right
	localCalls int
}

func (f *fakePenpot) LoginPassword(context.Context, string, string) (*rpcResult, error) {
	f.localCalls++
	if f.localOK {
		return cookieResult(`["^ ","~:id","9"]`), nil
	}
	return &rpcResult{Status: 400, Header: http.Header{}, Body: []byte(`["^ ","~:code","~:wrong-credentials"]`)}, nil
}

func (f *fakePenpot) IsAnonymous(context.Context, string) (bool, error) { return f.anon, f.anonErr }

func cookieResult(body string) *rpcResult {
	h := http.Header{}
	h.Add("Set-Cookie", "auth-token=abc; Path=/; HttpOnly")
	return &rpcResult{Status: 200, Header: h, Body: []byte(body)}
}

func (f *fakePenpot) Login(context.Context, string) (*rpcResult, error) {
	f.logins++
	if f.exists {
		return cookieResult(`["^ ","~:id","1"]`), nil
	}
	return &rpcResult{Status: 400, Header: http.Header{}, Body: []byte(`["^ ","~:type","~:validation","~:code","~:wrong-credentials"]`)}, nil
}

func (f *fakePenpot) Register(context.Context, string, string) (*rpcResult, error) {
	if f.localOnly {
		return &rpcResult{Status: 400, Header: http.Header{}, Body: []byte(`["^ ","~:code","~:email-already-exists"]`)}, nil
	}
	f.registered++
	f.exists = true
	return cookieResult(`["^ ","~:id","2"]`), nil
}

func newTestServer(kc *fakeKC, pp *fakePenpot) *Server {
	return &Server{
		cfg: &Config{AccessRole: "penpot-access"},
		kc:  kc,
		pp:  pp,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		lim: newLimiter(),
	}
}

func post(s *Server, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", transitContentType)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

const loginBody = `["^ ","~:email","ada@btn.co.id","~:password","pw"]`

func okClaims() *Claims {
	return &Claims{Email: "ada@btn.co.id", Name: "Ada L", Roles: []string{"penpot-access"}}
}

func TestLoginExistingUser(t *testing.T) {
	pp := &fakePenpot{exists: true}
	rec := post(newTestServer(&fakeKC{claims: okClaims()}, pp), "/api/rpc/command/login-with-password", loginBody)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Set-Cookie"), "auth-token=abc") || pp.registered != 0 {
		t.Fatalf("code=%d cookie=%q registered=%d", rec.Code, rec.Header().Get("Set-Cookie"), pp.registered)
	}
}

func TestLoginFirstTimeRegisters(t *testing.T) {
	pp := &fakePenpot{}
	rec := post(newTestServer(&fakeKC{claims: okClaims()}, pp), "/api/main/methods/login-with-password", loginBody)
	if rec.Code != 200 || pp.registered != 1 || rec.Header().Get("Set-Cookie") == "" {
		t.Fatalf("code=%d registered=%d", rec.Code, pp.registered)
	}
}

func TestLoginLocalProfileNeedsAdmin(t *testing.T) {
	pp := &fakePenpot{localOnly: true}
	rec := post(newTestServer(&fakeKC{claims: okClaims()}, pp), "/api/rpc/command/login-with-password", loginBody)
	if rec.Code != http.StatusBadGateway || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestLoginWithoutRoleIsBlocked(t *testing.T) {
	c := okClaims()
	c.Roles = nil
	pp := &fakePenpot{}
	rec := post(newTestServer(&fakeKC{claims: c}, pp), "/api/rpc/command/login-with-password", loginBody)
	if rec.Code != 403 || !bytes.Contains(rec.Body.Bytes(), []byte("~:profile-blocked")) || pp.logins != 0 || pp.registered != 0 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
}

func TestLoginWrongPasswordLocksOut(t *testing.T) {
	kc := &fakeKC{err: ErrBadCredentials}
	s := newTestServer(kc, &fakePenpot{})
	for i := 0; i < maxUserFailures; i++ {
		if rec := post(s, "/api/rpc/command/login-with-password", loginBody); rec.Code != 400 || !bytes.Contains(rec.Body.Bytes(), []byte("~:wrong-credentials")) {
			t.Fatalf("attempt %d: code=%d", i, rec.Code)
		}
	}
	if rec := post(s, "/api/rpc/command/login-with-password", loginBody); rec.Code != 429 {
		t.Fatalf("expected lockout, got %d", rec.Code)
	}
	if kc.calls != maxUserFailures {
		t.Fatalf("keycloak called %d times after lockout", kc.calls)
	}
}

func TestLoginUsernameFromEmailDomain(t *testing.T) {
	kc := &fakeKC{claims: okClaims()}
	s := newTestServer(kc, &fakePenpot{exists: true})
	s.cfg.EmailDomain = "btn.co.id"
	if rec := post(s, "/api/rpc/command/login-with-password", `["^ ","~:email","Ada.L@btn.co.id","~:password","pw"]`); rec.Code != 200 || kc.user != "ada.l" {
		t.Fatalf("code=%d keycloak user=%q", rec.Code, kc.user)
	}
	kc.calls = 0
	if rec := post(s, "/api/rpc/command/login-with-password", `["^ ","~:email","ada@other.com","~:password","pw"]`); rec.Code != 400 || kc.calls != 0 {
		t.Fatalf("other domain: code=%d keycloak calls=%d", rec.Code, kc.calls)
	}
}

func TestUILoginBareUsername(t *testing.T) {
	kc := &fakeKC{claims: okClaims()}
	pp := &fakePenpot{exists: true}
	s := newTestServer(kc, pp)
	s.cfg.EmailDomain = "btn.co.id"
	rec := post(s, "/auth-ui/login", `{"username":" Ada.L ","password":"pw"}`)
	if rec.Code != 200 || kc.user != "ada.l" || !strings.Contains(rec.Header().Get("Set-Cookie"), "auth-token=abc") || !strings.Contains(rec.Body.String(), `"redirect":"/"`) {
		t.Fatalf("code=%d user=%q body=%s", rec.Code, kc.user, rec.Body)
	}
}

func TestUILoginErrors(t *testing.T) {
	s := newTestServer(&fakeKC{err: ErrBadCredentials}, &fakePenpot{})
	rec := post(s, "/auth-ui/login", `{"username":"ada","password":"bad"}`)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "wrong-credentials") || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	if rec := post(s, "/auth-ui/login", `{"username":"","password":"x"}`); rec.Code != 400 {
		t.Fatalf("empty username: code=%d", rec.Code)
	}
	c := okClaims()
	c.Roles = nil
	if rec := post(newTestServer(&fakeKC{claims: c}, &fakePenpot{}), "/auth-ui/login", `{"username":"ada","password":"x"}`); rec.Code != 403 {
		t.Fatalf("no role: code=%d", rec.Code)
	}
}

func get(s *Server, path, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestRootServesPageOrProxies(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><head><title>penpot</title></head><body>app</body></html>"))
			return
		}
		_, _ = w.Write([]byte("other"))
	}))
	defer up.Close()
	proxy, err := newFrontendProxy(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	pp := &fakePenpot{}
	s := newTestServer(&fakeKC{}, pp)
	s.proxy = proxy

	// No cookie: the sign-in page, without asking Penpot.
	if rec := get(s, "/", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Sign in with AD BTN") || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("no cookie: code=%d", rec.Code)
	}
	// A cookie that Penpot says is anonymous: the page.
	pp.anon = true
	if rec := get(s, "/", "x=1"); !strings.Contains(rec.Body.String(), "Sign in with AD BTN") {
		t.Fatalf("anonymous cookie did not get the page")
	}
	// Signed in: Penpot's page, with the redirect script added.
	pp.anon = false
	rec := get(s, "/", "auth-token=abc")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "app") || !strings.Contains(rec.Body.String(), redirectTag+"</head>") || rec.Header().Get("Content-Length") != strconv.Itoa(rec.Body.Len()) {
		t.Fatalf("signed in: code=%d body=%s", rec.Code, rec.Body)
	}
	// Every other path goes to Penpot whatever the session says, and POST "/" is not the page either.
	pp.anon = true
	if rec := get(s, "/js/main.js", ""); rec.Body.String() != "other" {
		t.Fatalf("asset not proxied: %q", rec.Body)
	}
	pp.anon = false
	// The session check fails: pass through to Penpot, never loop on the page.
	pp.anonErr = errors.New("backend down")
	if rec := get(s, "/", "auth-token=abc"); strings.Contains(rec.Body.String(), "Sign in with AD BTN") {
		t.Fatal("served the page although the session check failed")
	}
}

func TestNoAccessRoleRequiredByDefault(t *testing.T) {
	c := okClaims()
	c.Roles = nil // an AD user with no Keycloak role at all
	s := newTestServer(&fakeKC{claims: c}, &fakePenpot{exists: true})
	s.cfg.AccessRole = ""
	if rec := post(s, "/auth-ui/login", `{"username":"ada","password":"pw"}`); rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
}

func TestLocalSignIn(t *testing.T) {
	pp := &fakePenpot{localOK: true}
	s := newTestServer(&fakeKC{}, pp)

	// Off by default: the page is told not to show the button, and the endpoint refuses.
	if rec := get(s, "/auth-ui/config", ""); !strings.Contains(rec.Body.String(), `"local":false`) {
		t.Fatalf("config: %s", rec.Body)
	}
	if rec := post(s, "/auth-ui/login/local", `{"username":"bg@btn.co.id","password":"x"}`); rec.Code != 401 || pp.localCalls != 0 {
		t.Fatalf("disabled: code=%d calls=%d", rec.Code, pp.localCalls)
	}

	s.cfg.LocalAccounts = []string{"bg@btn.co.id"}
	if rec := get(s, "/auth-ui/config", ""); !strings.Contains(rec.Body.String(), `"local":true`) {
		t.Fatalf("config: %s", rec.Body)
	}
	// An address outside the list never reaches Penpot.
	if rec := post(s, "/auth-ui/login/local", `{"username":"ada@btn.co.id","password":"x"}`); rec.Code != 401 || pp.localCalls != 0 {
		t.Fatalf("not listed: code=%d calls=%d", rec.Code, pp.localCalls)
	}
	// A listed account with the right password.
	rec := post(s, "/auth-ui/login/local", `{"username":"BG@btn.co.id","password":"x"}`)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Set-Cookie"), "auth-token=abc") {
		t.Fatalf("listed: code=%d", rec.Code)
	}
	// Wrong password: refused, and repeated failures lock the account.
	pp.localOK = false
	for i := 0; i < maxUserFailures; i++ {
		if rec := post(s, "/auth-ui/login/local", `{"username":"bg@btn.co.id","password":"bad"}`); rec.Code != 401 {
			t.Fatalf("attempt %d: code=%d", i, rec.Code)
		}
	}
	pp.localCalls = 0
	if rec := post(s, "/auth-ui/login/local", `{"username":"bg@btn.co.id","password":"bad"}`); rec.Code != 429 || pp.localCalls != 0 {
		t.Fatalf("lockout: code=%d calls=%d", rec.Code, pp.localCalls)
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" A@b.id, ,c@d.id ,")
	if len(got) != 2 || got[0] != "a@b.id" || got[1] != "c@d.id" {
		t.Fatalf("%q", got)
	}
	if len(splitList("")) != 0 {
		t.Fatal("empty list not empty")
	}
}

func TestAnonymousFromProfile(t *testing.T) {
	anon, err := anonymousFromProfile([]byte(`["^ ","~:id","~u00000000-0000-0000-0000-000000000000","~:fullname","x"]`))
	if err != nil || !anon {
		t.Fatalf("anon=%v err=%v", anon, err)
	}
	anon, err = anonymousFromProfile([]byte(`["^ ","~:email","a@b.id","~:id","~u3f2c1a9e-0000-4000-8000-000000000001"]`))
	if err != nil || anon {
		t.Fatalf("anon=%v err=%v", anon, err)
	}
	if _, err := anonymousFromProfile([]byte(`["^ ","~:email","a@b.id"]`)); err == nil {
		t.Fatal("expected error without :id")
	}
}

func TestAdUsernameBare(t *testing.T) {
	s := &Server{cfg: &Config{EmailDomain: "btn.co.id"}}
	for in, want := range map[string]string{"ada": "ada", "ada@btn.co.id": "ada"} {
		if got, ok := s.adUsername(in); !ok || got != want {
			t.Errorf("%q -> %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "@btn.co.id", "ada@other.com"} {
		if _, ok := s.adUsername(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestLoginKeycloakDown(t *testing.T) {
	rec := post(newTestServer(&fakeKC{err: errors.New("boom")}, &fakePenpot{}), "/api/rpc/command/login-with-password", loginBody)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestBlockedCommands(t *testing.T) {
	s := newTestServer(&fakeKC{}, &fakePenpot{})
	for _, p := range []string{"/api/rpc/command/prepare-register-profile", "/api/rpc/command/register-profile", "/api/main/methods/update-profile-password", "/api/rpc/command/recover-profile"} {
		if rec := post(s, p, `["^ "]`); rec.Code != 403 {
			t.Errorf("%s: code=%d", p, rec.Code)
		}
	}
}

func TestLoadConfigRequiresSecrets(t *testing.T) {
	for _, k := range []string{"KEYCLOAK_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "PENPOT_BACKEND_URL", "MANAGED_PASSWORD_SEED"} {
		t.Setenv(k, "")
	}
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error")
	}
	t.Setenv("KEYCLOAK_URL", "https://kc/realms/r/")
	t.Setenv("OIDC_CLIENT_ID", "penpot-dev")
	t.Setenv("OIDC_CLIENT_SECRET", "s")
	t.Setenv("PENPOT_BACKEND_URL", "http://backend:6060")
	t.Setenv("MANAGED_PASSWORD_SEED", "short")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("short seed accepted")
	}
	t.Setenv("MANAGED_PASSWORD_SEED", strings.Repeat("x", 32))
	c, err := LoadConfig()
	if err != nil || c.KeycloakURL != "https://kc/realms/r" || c.PenpotRPCPath != "/api/rpc/command" {
		t.Fatalf("%+v %v", c, err)
	}
}
