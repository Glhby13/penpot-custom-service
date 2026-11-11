package authservice

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecurityAbuse_BlockedCommands verifies that all Penpot registration and password-reset
// commands that would bypass AD authentication cannot be accessed.
func TestSecurityAbuse_BlockedCommands(t *testing.T) {
	s := newTestServer(&fakeKC{}, &fakePenpot{})
	handler := s.Handler()

	pathsToBlock := []string{
		"/api/rpc/command/prepare-register-profile",
		"/api/rpc/command/register-profile",
		"/api/rpc/command/request-profile-recovery",
		"/api/rpc/command/recover-profile",
		"/api/rpc/command/update-profile-password",
		"/api/rpc/command/login-with-ldap",
		"/api/rpc/command/login-with-oidc",
		"/api/main/methods/register-profile",
		"/api/main/methods/request-profile-recovery",
		"/api/main/methods/update-profile-password",
		"/api/main/methods/login-with-ldap",
		"/api/main/methods/login-with-oidc",
	}

	for _, p := range pathsToBlock {
		req := httptest.NewRequest(http.MethodPost, p, strings.NewReader(`["^ "]`))
		req.Header.Set("Content-Type", transitContentType)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Path %s was NOT blocked! Got code %d", p, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "restriction") {
			t.Errorf("Path %s did not return restriction error: %s", p, rec.Body.String())
		}
	}
}

// TestSecurityAbuse_RoleEnforcement tests that only users with penpot-access role can log in.
func TestSecurityAbuse_RoleEnforcement(t *testing.T) {
	tests := []struct {
		name       string
		roles      []string
		accessRole string
		wantCode   int
		wantBlock  bool
	}{
		{
			name:       "User has penpot-access role",
			roles:      []string{"penpot-access"},
			accessRole: "penpot-access",
			wantCode:   http.StatusOK,
			wantBlock:  false,
		},
		{
			name:       "User has both penpot-access and penpot-admin",
			roles:      []string{"penpot-access", "penpot-admin"},
			accessRole: "penpot-access",
			wantCode:   http.StatusOK,
			wantBlock:  false,
		},
		{
			name:       "User has NO roles",
			roles:      []string{},
			accessRole: "penpot-access",
			wantCode:   http.StatusForbidden,
			wantBlock:  true,
		},
		{
			name:       "User has different client role (privilege escalation attempt)",
			roles:      []string{"drawio-access", "n8n-access", "argocd-admin"},
			accessRole: "penpot-access",
			wantCode:   http.StatusForbidden,
			wantBlock:  true,
		},
		{
			name:       "User has role with lookalike name (penpot-access-fake)",
			roles:      []string{"penpot-access-fake", "penpot_access"},
			accessRole: "penpot-access",
			wantCode:   http.StatusForbidden,
			wantBlock:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := okClaims()
			claims.Roles = tc.roles
			kc := &fakeKC{claims: claims}
			pp := &fakePenpot{exists: true}

			s := newTestServer(kc, pp)
			s.cfg.AccessRole = tc.accessRole

			// Test UI login endpoint
			rec := post(s, "/auth-ui/login", `{"username":"ada@btn.co.id","password":"correct-password"}`)
			if rec.Code != tc.wantCode {
				t.Fatalf("UI login got status %d, want %d (body: %s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantBlock && !strings.Contains(rec.Body.String(), "profile-blocked") {
				t.Fatalf("UI login expected profile-blocked, got %s", rec.Body.String())
			}

			// Test RPC login endpoint
			rpcRec := post(s, "/api/rpc/command/login-with-password", `["^ ","~:email","ada@btn.co.id","~:password","correct-password"]`)
			if rpcRec.Code != tc.wantCode {
				t.Fatalf("RPC login got status %d, want %d", rpcRec.Code, tc.wantCode)
			}
		})
	}
}

// TestSecurityAbuse_BruteForceAndRateLimit tests rate limiting against brute force attacks.
func TestSecurityAbuse_BruteForceAndRateLimit(t *testing.T) {
	kc := &fakeKC{err: ErrBadCredentials}
	s := newTestServer(kc, &fakePenpot{})

	// 5 failed attempts allowed
	for i := 1; i <= maxUserFailures; i++ {
		rec := post(s, "/auth-ui/login", `{"username":"victim_user","password":"bad-password"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Attempt %d should return 400 Bad Request, got %d", i, rec.Code)
		}
	}

	// 6th attempt MUST be blocked by rate limiter (HTTP 429)
	rec := post(s, "/auth-ui/login", `{"username":"victim_user","password":"bad-password"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt should be locked out with 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "900" {
		t.Errorf("Expected Retry-After header 900, got %q", rec.Header().Get("Retry-After"))
	}
	if !strings.Contains(rec.Body.String(), "too-many-attempts") {
		t.Errorf("Expected too-many-attempts in body: %s", rec.Body.String())
	}

	// Verify that Keycloak was NOT called on the locked attempt
	if kc.calls != maxUserFailures {
		t.Fatalf("Keycloak was called %d times; expected exactly %d calls", kc.calls, maxUserFailures)
	}
}

// TestSecurityAbuse_BreakGlassAbuse tests authorization and lockout of break-glass local accounts.
func TestSecurityAbuse_BreakGlassAbuse(t *testing.T) {
	s := newTestServer(&fakeKC{}, &fakePenpot{})
	s.cfg.LocalAccounts = []string{"admin@btn.co.id"}

	// 1. Unlisted local account cannot log in
	rec := post(s, "/auth-ui/login/local", `{"username":"intruder@btn.co.id","password":"password123"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Unlisted local account got %d, want 401", rec.Code)
	}

	// 2. Empty LOCAL_ACCOUNTS refuses all local sign-ins
	sEmpty := newTestServer(&fakeKC{}, &fakePenpot{})
	sEmpty.cfg.LocalAccounts = nil
	recEmpty := post(sEmpty, "/auth-ui/login/local", `{"username":"admin@btn.co.id","password":"password123"}`)
	if recEmpty.Code != http.StatusUnauthorized {
		t.Fatalf("Empty LocalAccounts got %d, want 401", recEmpty.Code)
	}
}

// TestSecurityAbuse_MalformedPayloads verifies service robustness against fuzzing / malformed input.
func TestSecurityAbuse_MalformedPayloads(t *testing.T) {
	s := newTestServer(&fakeKC{}, &fakePenpot{})

	malformedBodies := []string{
		"",
		"{",
		`{"username": 123}`,
		`{"username": "", "password": ""}`,
		`{"username": "admin", "password": "` + strings.Repeat("A", 1000) + `"}`, // oversized password
		`["^ ","~:email", null]`,
		`["invalid transit]`,
		`<?xml version="1.0"?><root></root>`,
	}

	for _, body := range malformedBodies {
		rec := post(s, "/auth-ui/login", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("Malformed body %q returned code %d, expected 400", body, rec.Code)
		}
	}
}

// TestSecurityAbuse_SecurityHeaders verifies security headers on login page to prevent clickjacking and XSS.
func TestSecurityAbuse_SecurityHeaders(t *testing.T) {
	s := newTestServer(&fakeKC{}, &fakePenpot{})
	rec := httptest.NewRecorder()
	s.servePage(rec)

	headers := rec.Header()

	if h := headers.Get("X-Frame-Options"); h != "DENY" {
		t.Errorf("X-Frame-Options is %q, expected DENY", h)
	}
	if h := headers.Get("X-Content-Type-Options"); h != "nosniff" {
		t.Errorf("X-Content-Type-Options is %q, expected nosniff", h)
	}
	if h := headers.Get("Content-Security-Policy"); !strings.Contains(h, "default-src 'none'") {
		t.Errorf("CSP missing default-src 'none': %q", h)
	}
	if h := headers.Get("Cache-Control"); !strings.Contains(h, "no-store") {
		t.Errorf("Cache-Control missing no-store: %q", h)
	}
}
