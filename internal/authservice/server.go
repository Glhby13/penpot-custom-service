package authservice

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maxUserFailures = 5
	maxIPFailures   = 20
	failWindow      = 15 * time.Minute

	msgWrongCredentials = "Username or password is incorrect."
	msgNotAuthorized    = "Your account is not authorized to access this application. Please contact your administrator for assistance."
	msgSignInFailed     = "We couldn't complete your sign-in. Please try again, and contact your administrator if the problem continues."
)

// The two path prefixes under which Penpot's login command can arrive (current RPC path and the older alias). The
// ingress sends exactly these login paths to this service; the same paths are also used for the blocked commands.
var rpcPrefixes = []string{"/api/rpc/command/", "/api/main/methods/"}

// blockedCommands are Penpot commands that would let someone bypass AD sign-in (own password, own account). The
// ingress routes them here and they are refused; this service calls the backend directly and is not affected.
var blockedCommands = map[string]string{
	"prepare-register-profile": "registration-disabled",
	"register-profile":         "registration-disabled",
	"request-profile-recovery": "not-allowed",
	"recover-profile":          "not-allowed",
	"update-profile-password":  "not-allowed",
	"login-with-ldap":          "not-allowed",
	"login-with-oidc":          "not-allowed",
}

// backend is the part of Penpot the sign-in needs (satisfied by *Penpot).
type backend interface {
	Login(ctx context.Context, email string) (*rpcResult, error)
	// LoginPassword is Penpot's login with a password the caller typed (local break-glass accounts).
	LoginPassword(ctx context.Context, email, password string) (*rpcResult, error)
	Register(ctx context.Context, email, fullname string) (*rpcResult, error)
	// IsAnonymous reports whether the session in the Cookie header is not signed in.
	IsAnonymous(ctx context.Context, cookie string) (bool, error)
}

// directGranter is the part of Keycloak the sign-in needs (satisfied by *Keycloak).
type directGranter interface {
	DirectGrant(ctx context.Context, username, password string) (*Claims, error)
}

// Server is the HTTP server of penpot-auth-service.
type Server struct {
	cfg *Config
	kc  directGranter
	pp  backend
	log *slog.Logger
	lim *limiter
	// proxy forwards "/" to the Penpot frontend for signed-in users (nil = the sign-in page is not served).
	proxy http.Handler
	mcp   *mcpGuard
}

// NewServer wires the server to Keycloak and the Penpot backend.
func NewServer(cfg *Config, log *slog.Logger) *Server {
	s := &Server{
		cfg: cfg,
		kc:  NewKeycloak(cfg.KeycloakURL, cfg.OIDCClientID, cfg.OIDCClientSecret, cfg.KeycloakInsecureTLS),
		pp:  NewPenpot(cfg.PenpotBackendURL, cfg.PenpotRPCPath, cfg.ManagedPasswordSeed),
		log: log.With("component", "auth-server"),
		lim: newLimiter(),
	}
	if cfg.PenpotFrontendURL != "" {
		if p, err := newFrontendProxy(cfg.PenpotFrontendURL); err == nil {
			s.proxy = p
		} else {
			s.log.Error("PENPOT_FRONTEND_URL is not usable, the sign-in page is disabled", "err", err)
		}
	}
	return s
}

// Handler registers the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	ok := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}
	}
	mux.HandleFunc("GET /healthz", ok(`{"status":"ok"}`))
	mux.HandleFunc("GET /readyz", ok(`{"status":"ready"}`))
	for _, prefix := range rpcPrefixes {
		mux.HandleFunc("POST "+prefix+"login-with-password", s.handleLogin)
		for cmd, code := range blockedCommands {
			mux.HandleFunc("POST "+prefix+cmd, s.blocked(code))
		}
	}
	s.registerUI(mux)
	s.registerMCP(mux)
	return s.guardMCP(mux)
}

func writeTransit(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", transitContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) blocked(code string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.log.Warn("blocked penpot command", "path", r.URL.Path, "ip", clientIP(r))
		writeTransit(w, http.StatusForbidden, transitError("restriction", code, "This operation is disabled. Sign in with your AD account."))
	}
}

// authFail is a refused sign-in: the HTTP status, Penpot's error type and code, and the text for the user.
type authFail struct {
	status int
	typ    string
	code   string
	msg    string
	retry  bool // locked out: tell the client when to try again
}

// authenticate is the whole sign-in, shared by Penpot's own form and the sign-in page: Keycloak direct grant, role
// check, then Penpot login (creating the profile on the first sign-in). On success the result is Penpot's own answer
// with its session cookie.
func (s *Server) authenticate(ctx context.Context, typed, password, ip string) (*rpcResult, *authFail) {
	username, ok := s.adUsername(typed)
	if !ok {
		s.failed(typed, ip)
		s.log.Info("sign-in refused: e-mail domain", "user", typed)
		return nil, &authFail{http.StatusBadRequest, "validation", "wrong-credentials", msgWrongCredentials, false}
	}
	if s.locked(username, ip) {
		s.log.Warn("sign-in locked", "user", username)
		return nil, &authFail{http.StatusTooManyRequests, "restriction", "too-many-attempts", "Too many failed attempts. Try again in 15 minutes.", true}
	}

	claims, err := s.kc.DirectGrant(ctx, username, password)
	switch {
	case errors.Is(err, ErrBadCredentials):
		s.failed(username, ip)
		s.log.Info("sign-in refused", "user", username)
		return nil, &authFail{http.StatusBadRequest, "validation", "wrong-credentials", msgWrongCredentials, false}
	case errors.Is(err, ErrAccessDenied):
		s.log.Warn("sign-in denied by keycloak", "user", username)
		return nil, &authFail{http.StatusForbidden, "restriction", "profile-blocked", msgNotAuthorized, false}
	case err != nil:
		s.log.Error("keycloak unavailable", "err", err)
		return nil, &authFail{http.StatusServiceUnavailable, "internal", "service-unavailable", "The sign-in service is unavailable. Please try again later.", false}
	}
	if s.cfg.AccessRole != "" && !claims.HasRole(s.cfg.AccessRole) {
		s.log.Warn("user lacks access role", "user", username, "role", s.cfg.AccessRole)
		return nil, &authFail{http.StatusForbidden, "restriction", "profile-blocked", msgNotAuthorized, false}
	}
	// Penpot profiles are keyed by the e-mail address, so the account must use the one Keycloak holds.
	if claims.Email == "" {
		s.log.Warn("keycloak user has no e-mail", "user", username)
		return nil, &authFail{http.StatusForbidden, "restriction", "profile-blocked", "Your account has no e-mail address. Please contact your administrator.", false}
	}
	penpotEmail := strings.ToLower(claims.Email)

	res, err := s.signInPenpot(ctx, penpotEmail, claims.DisplayName())
	if err != nil {
		s.log.Error("penpot sign-in failed", "user", penpotEmail, "err", err)
		return nil, &authFail{http.StatusBadGateway, "internal", "service-unavailable", msgSignInFailed, false}
	}
	if res.Status != http.StatusOK {
		// Penpot's error answer carries a code and a hint, never a secret; the success body (profile) is not logged.
		s.log.Error("penpot refused managed sign-in", "user", penpotEmail, "status", res.Status, "body", snippet(res.Body, 400))
		return nil, &authFail{http.StatusBadGateway, "internal", "service-unavailable", msgSignInFailed, false}
	}
	s.lim.reset("u:" + username)
	s.log.Info("sign-in ok", "user", penpotEmail, "admin", s.cfg.AdminRole != "" && claims.HasRole(s.cfg.AdminRole))
	return res, nil
}

// passCookies hands Penpot's session cookie to the browser.
func passCookies(w http.ResponseWriter, res *rpcResult) {
	for _, c := range res.Header.Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", c)
	}
}

// handleLogin answers Penpot's own login form (transit+json in, Penpot's answer out).
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	email, password, err := decodeLoginBody(r.Body)
	if err != nil {
		writeTransit(w, http.StatusBadRequest, transitError("validation", "wrong-credentials", msgWrongCredentials))
		return
	}
	res, fail := s.authenticate(r.Context(), email, password, clientIP(r))
	if fail != nil {
		if fail.retry {
			w.Header().Set("Retry-After", "900")
		}
		writeTransit(w, fail.status, transitError(fail.typ, fail.code, fail.msg))
		return
	}
	passCookies(w, res)
	writeTransit(w, http.StatusOK, res.Body)
}

// signInPenpot logs the user into Penpot with the managed password, creating the profile on the first sign-in.
func (s *Server) signInPenpot(ctx context.Context, email, fullname string) (*rpcResult, error) {
	res, err := s.pp.Login(ctx, email)
	if err != nil || res.Status == http.StatusOK || !res.has("wrong-credentials") {
		return res, err
	}

	// Unknown e-mail (first sign-in), or an old local profile that does not use the managed password.
	reg, err := s.pp.Register(ctx, email, fullname)
	if err != nil {
		return nil, err
	}
	if reg.Status == http.StatusOK && len(reg.Header.Values("Set-Cookie")) > 0 {
		return reg, nil
	}
	if reg.has("email-already-exists") {
		// Either another first sign-in of the same user won the race (the managed password now works) or a local
		// profile exists with its own password (it keeps failing and needs an administrator).
		return s.pp.Login(ctx, email)
	}
	return reg, nil
}

// adUsername turns what was typed into the name sent to Keycloak. With EmailDomain set, user@domain becomes user,
// a bare user is kept, and any other domain is refused.
func (s *Server) adUsername(typed string) (string, bool) {
	if typed == "" {
		return "", false
	}
	if s.cfg.EmailDomain == "" {
		return typed, true
	}
	local, domain, found := strings.Cut(typed, "@")
	if !found {
		return typed, true
	}
	if local == "" || domain != s.cfg.EmailDomain {
		return "", false
	}
	return local, true
}

func snippet(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

func (s *Server) locked(user, ip string) bool {
	return s.lim.count("u:"+user) >= maxUserFailures || s.lim.count("ip:"+ip) >= maxIPFailures
}

func (s *Server) failed(user, ip string) {
	s.lim.add("u:"+user, failWindow)
	s.lim.add("ip:"+ip, failWindow)
}

// clientIP is the caller's address as set by ingress-nginx.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); ip != "" {
			return ip
		}
	}
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiter counts failed sign-ins per key inside a window (in memory, per replica).
type limiter struct {
	mu sync.Mutex
	m  map[string]*bucket
}

type bucket struct {
	n       int
	expires time.Time
}

func newLimiter() *limiter { return &limiter{m: map[string]*bucket{}} }

func (l *limiter) count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.m[key]
	if !ok || time.Now().After(b.expires) {
		delete(l.m, key)
		return 0
	}
	return b.n
}

func (l *limiter) add(key string, window time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.m) > 10000 {
		for k, v := range l.m {
			if now.After(v.expires) {
				delete(l.m, k)
			}
		}
	}
	b, ok := l.m[key]
	if !ok || now.After(b.expires) {
		l.m[key] = &bucket{n: 1, expires: now.Add(window)}
		return
	}
	b.n++
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}
