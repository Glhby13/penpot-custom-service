package authservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Organizations and the user directory.
//
// Penpot OSS has no organization backend, so an "organization" in UX Studio is a Penpot team. Creating one is
// reserved for Keycloak users holding the AdminRole client role (checked live), and the team is created with the
// caller's own Penpot session, so Penpot itself records the right owner. The directory search lets the page offer
// colleagues from Keycloak when inviting people; it exposes username, name and e-mail only.

const (
	orgNameMax      = 64
	orgBodyMax      = 4096
	orgRatePerMin   = 10
	dirRatePerMin   = 60
	dirQueryMin     = 2
	dirQueryMax     = 64
	dirResultMax    = 10
	dirFetch        = 50
	adminCacheTTLNs = int64(10 * time.Second)
)

const apiCSP = "default-src 'none'; frame-ancestors 'none'"

// apiJSON is writeJSON plus the hardening headers of the other handlers.
func apiJSON(w http.ResponseWriter, status int, v map[string]any) {
	w.Header().Set("Content-Security-Policy", apiCSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	writeJSON(w, status, v)
}

func (s *Server) registerOrg(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth-ui/orgs", s.handleCreateOrg)
	mux.HandleFunc("GET /auth-ui/directory/users", s.handleDirectory)
}

// handleCapabilities tells the page which entry points to show. Every answer is decided live and fails closed.
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if !s.mcp.admit(clientIP(r)) {
		apiJSON(w, http.StatusTooManyRequests, map[string]any{"mcp": false, "org": false})
		return
	}
	email, err := s.mcp.identity(r.Context(), r.Header.Get("Cookie"))
	mcp, org := false, false
	if err == nil {
		mcp = s.mcp.allowedEmail(r.Context(), email) == nil
		org = s.isOrgAdmin(r.Context(), email, true)
	}
	apiJSON(w, http.StatusOK, map[string]any{"mcp": mcp, "org": org})
}

// roleLive asks Keycloak (bounded concurrency and time) whether the user holds the client role right now.
func (g *mcpGuard) roleLive(ctx context.Context, email, role string) (bool, error) {
	if g == nil || g.roles == nil || role == "" || email == "" {
		return false, errors.New("identity check unavailable")
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		return false, errors.New("identity check busy")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return g.roles.MCPAllowed(ctx, email, role)
}

// isOrgAdmin reports whether the user holds the administrator role. useCache allows an answer up to 10 s old (used
// for the page's capability poll only; creating an organization always asks Keycloak).
func (s *Server) isOrgAdmin(ctx context.Context, email string, useCache bool) bool {
	g := s.mcp
	key := "admin:" + email
	if useCache {
		if v, ok := g.cached(key); ok {
			return v == "1"
		}
	}
	ok, err := g.roleLive(ctx, email, s.cfg.AdminRole)
	if err != nil {
		return false
	}
	v := "0"
	if ok {
		v = "1"
	}
	g.cacheFor(key, v, time.Duration(adminCacheTTLNs))
	return ok
}

func (g *mcpGuard) cacheFor(key, value string, ttl time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.allowed) > 2000 {
		clear(g.allowed)
	}
	g.allowed[key] = cachedMCP{time.Now().Add(ttl), value}
}

// sameOrigin rejects cross-site browser requests (CSRF). Non-browser callers send neither header and are let
// through; they still need the session cookie, which a cross-site page cannot make a browser attach to JSON.
func (s *Server) sameOrigin(r *http.Request) bool {
	if v := r.Header.Get("Sec-Fetch-Site"); v != "" && v != "same-origin" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	if s.cfg.MCPPublicOrigin != "" && o == s.cfg.MCPPublicOrigin {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.Path == "" && strings.EqualFold(u.Host, r.Host)
}

// apiSession is the common start of both endpoints: admission, session, per-user rate limit. It writes the refusal
// itself and returns ok=false.
func (s *Server) apiSession(w http.ResponseWriter, r *http.Request, rateKey string, perMin int) (email, cookie string, ok bool) {
	if s.mcp == nil || !s.mcp.admit(clientIP(r)) {
		apiJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate_limited"})
		return "", "", false
	}
	cookie = r.Header.Get("Cookie")
	email, err := s.mcp.identity(r.Context(), cookie)
	if err != nil {
		apiJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return "", "", false
	}
	if !s.lim.allow(rateKey+email, perMin, time.Minute) {
		w.Header().Set("Retry-After", "60")
		apiJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate_limited"})
		return "", "", false
	}
	return email, cookie, true
}

// validOrgName trims and checks a team name: 1-64 characters, no control or line-separator characters.
func validOrgName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > orgNameMax {
		return "", false
	}
	for _, c := range name {
		if unicode.IsControl(c) || unicode.Is(unicode.Zl, c) || unicode.Is(unicode.Zp, c) || unicode.Is(unicode.Cf, c) {
			return "", false
		}
	}
	return name, true
}

func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		apiJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		apiJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "unsupported_media_type"})
		return
	}
	email, cookie, ok := s.apiSession(w, r, "org:", orgRatePerMin)
	if !ok {
		return
	}
	allowed, err := s.mcp.roleLive(r.Context(), email, s.cfg.AdminRole)
	if err != nil {
		s.log.Warn("org create: role check failed", "user", email, "err", err)
		apiJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable"})
		return
	}
	if !allowed {
		s.log.Warn("org create refused: administrator role required", "user", email)
		apiJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, orgBodyMax))
	if err != nil || json.Unmarshal(body, &in) != nil {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return
	}
	name, valid := validOrgName(in.Name)
	if !valid {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_name"})
		return
	}
	var team struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	status, err := s.mcp.pp.postJSON(ctx, "create-team", cookie, map[string]any{"name": name}, &team)
	switch {
	case err != nil || status >= 500 || status == 0:
		s.log.Error("org create: penpot failed", "user", email, "status", status, "err", err)
		apiJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream"})
		return
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		apiJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	case status == http.StatusTooManyRequests:
		apiJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate_limited"})
		return
	case status != http.StatusOK:
		s.log.Warn("org create: penpot refused", "user", email, "status", status)
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "rejected"})
		return
	case team.ID == "":
		s.log.Error("org create: penpot answer without id", "user", email)
		apiJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream"})
		return
	}
	if team.Name == "" {
		team.Name = name
	}
	s.log.Info("org created", "user", email, "team", team.ID, "name", name)
	apiJSON(w, http.StatusCreated, map[string]any{"id": team.ID, "name": team.Name})
}

// dirQueryOK allows letters, digits, spaces and . - @ ' only: Keycloak's search treats * (and SQL LIKE characters)
// as wildcards, which would let anyone list the whole directory.
func dirQueryOK(q string) bool {
	for _, c := range q {
		if !(unicode.IsLetter(c) || unicode.IsDigit(c) || c == ' ' || c == '.' || c == '-' || c == '@' || c == '\'') {
			return false
		}
	}
	return true
}

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	email, _, ok := s.apiSession(w, r, "dir:", dirRatePerMin)
	if !ok {
		return
	}
	// The Penpot session outlives the Keycloak account: only a user who is still active may read the directory.
	if active, err := s.callerActive(r.Context(), email); err != nil || !active {
		apiJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	raw := r.URL.Query().Get("q")
	if strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return
	}
	q := strings.Join(strings.Fields(raw), " ")
	if utf8.RuneCountInString(q) < dirQueryMin {
		apiJSON(w, http.StatusOK, map[string]any{"users": []any{}})
		return
	}
	if utf8.RuneCountInString(q) > dirQueryMax || !dirQueryOK(q) {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_request"})
		return
	}
	dir, _ := s.mcp.roles.(userDirectory)
	if dir == nil {
		apiJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream"})
		return
	}
	select {
	case s.mcp.slots <- struct{}{}:
		defer func() { <-s.mcp.slots }()
	default:
		apiJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rows, err := dir.SearchUsers(ctx, q, dirFetch)
	if err != nil {
		s.log.Warn("directory search failed", "err", err)
		apiJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream"})
		return
	}
	suffix := ""
	if s.cfg.EmailDomain != "" {
		suffix = "@" + s.cfg.EmailDomain
	}
	users := make([]any, 0, dirResultMax)
	for _, u := range rows {
		email := strings.TrimSpace(u.Email)
		if !u.Enabled || email == "" || (suffix != "" && !strings.HasSuffix(strings.ToLower(email), suffix)) {
			continue
		}
		users = append(users, map[string]string{
			"username": u.Username,
			"name":     strings.TrimSpace(u.FirstName + " " + u.LastName),
			"email":    email,
		})
		if len(users) == dirResultMax {
			break
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"users": users})
}

// activeChecker is satisfied by *roleReader: is there exactly one enabled Keycloak user with this e-mail.
type activeChecker interface {
	UserActive(ctx context.Context, email string) (bool, error)
}

// callerActive fails closed: no checker, busy, timeout or Keycloak error all mean "not active".
func (s *Server) callerActive(ctx context.Context, email string) (bool, error) {
	chk, ok := s.mcp.roles.(activeChecker)
	if !ok || email == "" {
		return false, errors.New("identity check unavailable")
	}
	select {
	case s.mcp.slots <- struct{}{}:
		defer func() { <-s.mcp.slots }()
	default:
		return false, errors.New("identity check busy")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return chk.UserActive(ctx, email)
}
