package authservice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type revokingKC struct {
	*fakeKC
	revoked []string
}

func (r *revokingKC) Revoke(_ context.Context, rt string) error {
	r.revoked = append(r.revoked, rt)
	return nil
}

func TestLogoutEndsKeycloakSession(t *testing.T) {
	upstream := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { upstream++; w.WriteHeader(200) }))
	defer up.Close()
	claims := okClaims()
	claims.RefreshToken = "rt-1"
	kc := &revokingKC{fakeKC: &fakeKC{claims: claims}}
	s := newTestServer(kc.fakeKC, &fakePenpot{exists: true})
	s.kc = kc
	s.sessions = newSessionStore()
	px, err := newFrontendProxy(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	s.proxy = px

	if rec := post(s, "/api/rpc/command/login-with-password", loginBody); rec.Code != 200 {
		t.Fatalf("login %d", rec.Code)
	}
	logout := func(cookie string) {
		req := httptest.NewRequest(http.MethodPost, "/api/rpc/command/logout", strings.NewReader("{}"))
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		s.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	logout("auth-token=other") // unknown session: nothing revoked, Penpot still answers
	if len(kc.revoked) != 0 || upstream != 1 {
		t.Fatalf("unknown session: revoked=%v upstream=%d", kc.revoked, upstream)
	}
	logout("auth-token=abc")
	if len(kc.revoked) != 1 || kc.revoked[0] != "rt-1" || upstream != 2 {
		t.Fatalf("revoked=%v upstream=%d", kc.revoked, upstream)
	}
	logout("auth-token=abc") // token is single use
	if len(kc.revoked) != 1 || upstream != 3 {
		t.Fatalf("second logout: revoked=%v upstream=%d", kc.revoked, upstream)
	}
}
