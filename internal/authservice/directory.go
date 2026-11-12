package authservice

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// User directory. Penpot OSS has no organization backend, so there is no "organization" feature here (teams are
// Penpot's own). The directory search lets the page offer colleagues from Keycloak when inviting people to a team;
// it exposes username, name and e-mail only and is limited to signed-in, still-enabled Keycloak users.

const (
	dirRatePerMin = 60
	dirQueryMin   = 2
	dirQueryMax   = 64
	dirResultMax  = 10
	dirFetch      = 50
)

const apiCSP = "default-src 'none'; frame-ancestors 'none'"

// apiJSON is writeJSON plus the hardening headers of the other handlers.
func apiJSON(w http.ResponseWriter, status int, v map[string]any) {
	w.Header().Set("Content-Security-Policy", apiCSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	writeJSON(w, status, v)
}

func (s *Server) registerDirectory(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth-ui/directory/users", s.handleDirectory)
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
