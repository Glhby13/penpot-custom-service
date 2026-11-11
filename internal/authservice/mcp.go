package authservice

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const mcpCacheTTL = 15 * time.Second
const mcpTokenLimit = 12000

type mcpEnvelope struct {
	Version int    `json:"v"`
	Kind    string `json:"kind"`
	Email   string `json:"email"`
	Token   string `json:"token"`
}
type cachedMCP struct {
	until time.Time
	value string
}
type mcpGuard struct {
	cfg      *Config
	pp       *Penpot
	roles    liveRoleReader
	mu       sync.Mutex
	allowed  map[string]cachedMCP
	sessions map[string]cachedMCP
	slots    chan struct{}
	rates    map[string]bucket
}

func (s *Server) registerMCP(mux *http.ServeMux) {
	if s.mcp == nil {
		p, _ := s.pp.(*Penpot)
		kc, _ := s.kc.(*Keycloak)
		s.mcp = &mcpGuard{cfg: s.cfg, pp: p, allowed: map[string]cachedMCP{}, sessions: map[string]cachedMCP{}, slots: make(chan struct{}, 16)}
		if kc != nil {
			s.mcp.roles = &roleReader{kc: kc}
		}
	}
	mux.HandleFunc("GET /auth-ui/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if !s.mcp.admit(clientIP(r)) {
			writeJSON(w, 429, map[string]any{"mcp": false})
			return
		}
		email, err := s.mcp.profile(r.Context(), r.Header.Get("Cookie"))
		allowed := err == nil && s.mcp.allowedEmail(r.Context(), email) == nil
		writeJSON(w, 200, map[string]any{"mcp": allowed})
	})
}
func (g *mcpGuard) admit(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.rates == nil {
		g.rates = map[string]bucket{}
	}
	now := time.Now()
	v, ok := g.rates[ip]
	if !ok || now.After(v.expires) {
		if len(g.rates) >= 4096 {
			for k, b := range g.rates {
				if now.After(b.expires) {
					delete(g.rates, k)
				}
			}
			if len(g.rates) >= 4096 {
				return false
			}
		}
		g.rates[ip] = bucket{1, now.Add(time.Minute)}
		return true
	}
	if v.n >= 120 {
		return false
	}
	v.n++
	g.rates[ip] = v
	return true
}
func (g *mcpGuard) configured() bool {
	return g != nil && g.cfg.MCPEnabled && g.cfg.MCPAccessRole != "" && g.roles != nil && g.pp != nil
}
func (g *mcpGuard) cached(key string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	v, ok := g.allowed[key]
	return v.value, ok && time.Now().Before(v.until)
}
func (g *mcpGuard) cache(key, value string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.allowed) > 2000 {
		clear(g.allowed)
	}
	g.allowed[key] = cachedMCP{time.Now().Add(mcpCacheTTL), value}
}
func (g *mcpGuard) allowedEmail(ctx context.Context, email string) error {
	if !g.configured() || email == "" {
		return errors.New("mcp disabled")
	}
	if _, ok := g.cached("role:" + email); ok {
		return nil
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		return errors.New("identity check busy")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ok, err := g.roles.MCPAllowed(ctx, email, g.cfg.MCPAccessRole)
	if err != nil || !ok {
		return errors.New("mcp role required")
	}
	g.cache("role:"+email, email)
	return nil
}
func (p *Penpot) getJSON(ctx context.Context, command, cookie string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+p.rpcPath+"/"+command, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return errors.New("penpot unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return fmt.Errorf("penpot identity status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(out)
}
func (g *mcpGuard) profile(ctx context.Context, cookie string) (string, error) {
	if !g.configured() || cookie == "" {
		return "", errors.New("session required")
	}
	var profile struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := g.pp.getJSON(ctx, "get-profile", cookie, &profile); err != nil {
		return "", err
	}
	if profile.ID == "" || profile.ID == strings.TrimPrefix(zeroUUID, "~u") || profile.Email == "" {
		return "", errors.New("session required")
	}
	email := strings.ToLower(profile.Email)
	cookie, err := g.managedCookie(ctx, email)
	if err != nil {
		return "", errors.New("managed identity required")
	}
	var managed struct {
		ID string `json:"id"`
	}
	if err := g.pp.getJSON(ctx, "get-profile", cookie, &managed); err != nil || managed.ID != profile.ID {
		return "", errors.New("managed identity mismatch")
	}
	return email, nil
}
func (g *mcpGuard) mac(kind, payload string) string {
	m := hmac.New(sha256.New, []byte(g.cfg.ManagedPasswordSeed))
	_, _ = m.Write([]byte("penpot-gateway-mcp:" + kind + ":" + payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func (g *mcpGuard) wrap(email, token string) (string, error) {
	if email == "" || len(email) > 254 || token == "" || len(token) > 5000 {
		return "", errors.New("invalid mcp token")
	}
	b, _ := json.Marshal(mcpEnvelope{1, "penpot-mcp", email, token})
	encoded := base64.RawURLEncoding.EncodeToString(b)
	return "ppm1." + encoded + "." + g.mac("token", encoded), nil
}
func (g *mcpGuard) unwrap(token string) (mcpEnvelope, error) {
	var e mcpEnvelope
	if len(token) > mcpTokenLimit {
		return e, errors.New("invalid token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "ppm1" || !hmac.Equal([]byte(parts[2]), []byte(g.mac("token", parts[1]))) {
		return e, errors.New("invalid token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return e, errors.New("invalid token")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&e); err != nil || e.Version != 1 || e.Kind != "penpot-mcp" || e.Email == "" || len(e.Email) > 254 || len(e.Token) == 0 || len(e.Token) > 5000 {
		return e, errors.New("invalid token")
	}
	canonical, _ := json.Marshal(e)
	if !bytes.Equal(canonical, raw) {
		return e, errors.New("noncanonical token")
	}
	return e, nil
}
func (g *mcpGuard) managedCookie(ctx context.Context, email string) (string, error) {
	g.mu.Lock()
	v, ok := g.sessions[email]
	g.mu.Unlock()
	if ok && time.Now().Before(v.until) {
		return v.value, nil
	}
	res, err := g.pp.Login(ctx, email)
	if err != nil || res.Status != 200 {
		return "", errors.New("native session unavailable")
	}
	resp := &http.Response{Header: res.Header}
	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, c.Name+"="+c.Value)
	}
	if len(cookies) == 0 {
		return "", errors.New("native session unavailable")
	}
	cookie := strings.Join(cookies, "; ")
	g.mu.Lock()
	if len(g.sessions) > 1000 {
		clear(g.sessions)
	}
	g.sessions[email] = cachedMCP{time.Now().Add(5 * time.Minute), cookie}
	g.mu.Unlock()
	return cookie, nil
}
func (g *mcpGuard) authorizeToken(ctx context.Context, token string) (string, error) {
	if !g.configured() {
		return "", errors.New("mcp disabled")
	}
	e, err := g.unwrap(token)
	if err != nil {
		return "", err
	}
	if err = g.allowedEmail(ctx, e.Email); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(token))
	key := "token:" + hex.EncodeToString(sum[:])
	if _, ok := g.cached(key); ok {
		return e.Email, nil
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		return "", errors.New("token check busy")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cookie, err := g.managedCookie(ctx, e.Email)
	if err != nil {
		return "", err
	}
	// Penpot JSON uses kebab-case field names, matching RPC keywords.
	var rows []map[string]any
	if err = g.pp.getJSON(ctx, "get-access-tokens", cookie, &rows); err != nil {
		return "", err
	}
	for _, row := range rows {
		tok, _ := row["token"].(string)
		typ, _ := row["type"].(string)
		if tok != e.Token || typ != "mcp" {
			continue
		}
		if row["expires-at"] == nil {
			row["expires-at"] = row["expiresAt"]
		}
		if value := row["expires-at"]; value != nil {
			if _, ok := value.(string); !ok {
				return "", errors.New("invalid token expiry")
			}
		}
		if exp, ok := row["expires-at"].(string); ok {
			when, err := time.Parse(time.RFC3339Nano, exp)
			if err != nil || !time.Now().Before(when) {
				return "", errors.New("expired token")
			}
		}
		g.cache(key, e.Email)
		return e.Email, nil
	}
	return "", errors.New("revoked token")
}
func (g *mcpGuard) originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	return r.Header.Get("Sec-Fetch-Site") != "cross-site" && (o == "" || o == g.cfg.MCPPublicOrigin)
}

var mcpCommands = map[string]bool{"create-access-token": true, "get-access-tokens": true, "get-current-mcp-token": true, "delete-access-token": true}

func (s *Server) guardMCP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		// Reject alternate encodings/canonicalizations for sensitive routes rather than letting a downstream
		// server interpret a different path. The outer guard executes before ServeMux redirects.
		clean := path.Clean(p)
		sensitive := strings.HasPrefix(clean, "/mcp") || strings.HasPrefix(clean, "/api/")
		if sensitive && (r.URL.RawPath != "" || clean != p || strings.Contains(p, "\\")) {
			http.Error(w, "invalid path", 400)
			return
		}
		if strings.HasPrefix(p, "/mcp") {
			s.handleMCP(w, r)
			return
		}
		for _, prefix := range rpcPrefixes {
			if strings.HasPrefix(p, prefix) {
				cmd := strings.TrimPrefix(p, prefix)
				if cmd == "request-email-change" {
					s.denyMCP(w)
					return
				}
				if mcpCommands[cmd] {
					s.handleMCPRPC(w, r, cmd)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) denyMCP(w http.ResponseWriter) {
	writeTransit(w, 403, transitError("restriction", "mcp-not-permitted", "MCP access is not permitted for this account."))
}
func (s *Server) handleMCPRPC(w http.ResponseWriter, r *http.Request, cmd string) {
	g := s.mcp
	if !g.admit(clientIP(r)) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if !g.originOK(r) {
		s.denyMCP(w)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	email, err := g.profile(r.Context(), r.Header.Get("Cookie"))
	if err != nil || g.allowedEmail(r.Context(), email) != nil {
		s.denyMCP(w)
		return
	}
	if s.proxy == nil {
		s.denyMCP(w)
		return
	}
	if (cmd == "create-access-token" || cmd == "delete-access-token") && (r.Method != http.MethodPost || r.URL.RawQuery != "") {
		s.denyMCP(w)
		return
	}
	if cmd == "create-access-token" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 8193))
		if readErr != nil || len(body) > 8192 {
			http.Error(w, "invalid request", 400)
			return
		}
		var v any
		if json.Unmarshal(body, &v) != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		cache := []string{}
		v, readErr = expandTransit(v, &cache, false)
		if readErr != nil || tokenFields(v)["type"] != "mcp" {
			s.denyMCP(w)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	// Responses are compact Transit, with opaque native MCP values replaced by a signed gateway envelope.
	handler, err := newFrontendProxy(g.cfg.PenpotFrontendURL)
	if err != nil {
		s.denyMCP(w)
		return
	}
	pr := handler.(*httputil.ReverseProxy)
	pr.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode != 200 || cmd == "delete-access-token" {
			return nil
		}
		originalBody := resp.Body
		defer func() { _ = originalBody.Close() }()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			return err
		}
		out, err := rewriteTokenBody(b, func(tok string) (string, error) { return g.wrap(email, tok) })
		if err != nil {
			return errors.New("invalid token response")
		}
		resp.Body = io.NopCloser(bytes.NewReader(out))
		resp.ContentLength = int64(len(out))
		resp.Header.Del("Content-Length")
		resp.Header.Set("Content-Type", transitContentType)
		resp.Header.Set("Cache-Control", "no-store")
		return nil
	}
	r.Header.Set("Accept", transitContentType)
	r.Header.Del("Accept-Encoding")
	pr.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
	pr.ServeHTTP(w, r)
}
func (g *mcpGuard) signSession(token, id string) string {
	p := base64.RawURLEncoding.EncodeToString([]byte(id))
	return p + "." + g.mac("session", token+":"+p)
}
func (g *mcpGuard) session(token, signed string) (string, error) {
	p := strings.Split(signed, ".")
	if len(p) != 2 || len(signed) > 1024 || !hmac.Equal([]byte(p[1]), []byte(g.mac("session", token+":"+p[0]))) {
		return "", errors.New("session token mismatch")
	}
	b, err := base64.RawURLEncoding.DecodeString(p[0])
	if err != nil || len(b) == 0 {
		return "", errors.New("invalid session")
	}
	return string(b), nil
}
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	g := s.mcp
	if !g.admit(clientIP(r)) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if (r.URL.Path != "/mcp/stream" && r.URL.Path != "/mcp/ws") || !g.originOK(r) {
		s.denyMCP(w)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.WriteHeader(405)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q["userToken"]) != 1 {
		s.denyMCP(w)
		return
	}
	token := q.Get("userToken")
	if _, err = g.authorizeToken(r.Context(), token); err != nil {
		s.denyMCP(w)
		return
	}
	if len(r.Header.Values("Mcp-Session-Id")) > 1 {
		s.denyMCP(w)
		return
	}
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
		native, err := g.session(token, sid)
		if err != nil {
			s.denyMCP(w)
			return
		}
		r.Header.Set("Mcp-Session-Id", native)
	}
	if r.URL.Path == "/mcp/ws" && (!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Method != http.MethodGet) {
		s.denyMCP(w)
		return
	}
	if r.ContentLength > 1<<20 {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if r.URL.Path == "/mcp/stream" {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
	}
	upstream := g.cfg.MCPServerURL
	if r.URL.Path == "/mcp/ws" {
		upstream = g.cfg.MCPWSURL
	}
	target, err := url.Parse(upstream)
	if err != nil || target.Host == "" {
		s.denyMCP(w)
		return
	}
	if r.URL.Path == "/mcp/stream" {
		r.URL.Path = "/mcp"
	}
	pr := httputil.NewSingleHostReverseProxy(target)
	pr.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "MCP upstream unavailable", http.StatusBadGateway)
	}
	pr.ModifyResponse = func(resp *http.Response) error {
		if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
			resp.Header.Set("Mcp-Session-Id", g.signSession(token, sid))
		}
		if resp.StatusCode == 101 {
			if rw, ok := resp.Body.(io.ReadWriteCloser); ok {
				resp.Body = newMCPStream(rw, g, token)
			}
		}
		return nil
	}
	// Query credentials must never be included in gateway error logs. No request URL is logged here.
	pr.ServeHTTP(w, r)
}

type mcpStream struct {
	io.ReadWriteCloser
	once sync.Once
	done chan struct{}
}

func newMCPStream(rw io.ReadWriteCloser, g *mcpGuard, token string) *mcpStream {
	stream := &mcpStream{ReadWriteCloser: rw, done: make(chan struct{})}
	go func() {
		tick := time.NewTicker(mcpCacheTTL)
		defer tick.Stop()
		for {
			select {
			case <-stream.done:
				return
			case <-tick.C:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, err := g.authorizeToken(ctx, token)
				cancel()
				if err != nil {
					_ = stream.Close()
					return
				}
			}
		}
	}()
	return stream
}
func (s *mcpStream) Close() error {
	var err error
	s.once.Do(func() { close(s.done); err = s.ReadWriteCloser.Close() })
	return err
}
