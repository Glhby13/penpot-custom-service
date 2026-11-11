package authservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Author / Agent: Claude Code. Direct grant opens a Keycloak session that nobody closes, so the refresh token is
// kept in memory (never logged, never persisted) under a hash of Penpot's session cookie and used at sign-out.
// A pod restart forgets the tokens; those Keycloak sessions then simply expire by their idle timeout.

const (
	sessionCookie = "auth-token"
	sessionTTL    = 24 * time.Hour
	sessionMax    = 20000
)

type sessionEntry struct {
	refresh string
	exp     time.Time
}

type sessionStore struct {
	mu sync.Mutex
	m  map[string]sessionEntry
}

func newSessionStore() *sessionStore { return &sessionStore{m: map[string]sessionEntry{}} }

func sessionKey(cookieValue string) string {
	h := sha256.Sum256([]byte(cookieValue))
	return hex.EncodeToString(h[:])
}

func (s *sessionStore) put(cookieValue, refresh string) {
	if s == nil || cookieValue == "" || refresh == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= sessionMax {
		for k, v := range s.m {
			if now.After(v.exp) {
				delete(s.m, k)
			}
		}
		if len(s.m) >= sessionMax { // still full: drop everything rather than grow without bound
			s.m = map[string]sessionEntry{}
		}
	}
	s.m[sessionKey(cookieValue)] = sessionEntry{refresh: refresh, exp: now.Add(sessionTTL)}
}

// take removes and returns the refresh token of a session.
func (s *sessionStore) take(cookieValue string) string {
	if s == nil || cookieValue == "" {
		return ""
	}
	k := sessionKey(cookieValue)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	delete(s.m, k)
	if !ok || time.Now().After(e.exp) {
		return ""
	}
	return e.refresh
}

// revoker is implemented by the real Keycloak client (test fakes need not).
type revoker interface {
	Revoke(ctx context.Context, refreshToken string) error
}

// rememberSession links Penpot's new session cookie to the Keycloak refresh token.
func (s *Server) rememberSession(res *rpcResult, refresh string) {
	if res == nil {
		return
	}
	for _, line := range res.Header.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err == nil && c.Name == sessionCookie {
			s.sessions.put(c.Value, refresh)
			return
		}
	}
}

// handleLogout ends the Keycloak session, then lets Penpot end its own (the answer clears the cookie).
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if rt := s.sessions.take(c.Value); rt != "" {
			if rv, ok := s.kc.(revoker); ok {
				ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				if err := rv.Revoke(ctx, rt); err != nil {
					s.log.Warn("keycloak session was not ended", "err", err)
				}
				cancel()
			}
		}
	}
	if s.proxy == nil {
		writeTransit(w, http.StatusBadGateway, transitError("internal", "service-unavailable", msgSignInFailed))
		return
	}
	s.proxy.ServeHTTP(w, r)
}
