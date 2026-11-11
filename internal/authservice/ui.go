package authservice

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// The sign-in page. Penpot's own login screen is a route inside its single-page app (a "#/auth/login" fragment the
// server never sees), so it cannot be replaced from outside. Instead this service is the only entry point of the
// Penpot host (like the DrawSpace gateway): "/" gives a visitor without a Penpot session this page; every other
// request, and "/" for a signed-in user, is proxied to the Penpot frontend untouched, except that a tiny script is
// added to its start page which sends "#/auth/login" (session expired, logout) back to "/".

//go:embed web/login.html web/login.css web/login.js web/redirect.js web/logo.png
var webFS embed.FS

// uiCSP allows only this service's own script and styles; no inline code and no framing.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

const redirectTag = `<script src="/auth-ui/assets/redirect.js"></script>`

func (s *Server) registerUI(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth-ui/assets/login.css", s.asset("web/login.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /auth-ui/assets/login.js", s.asset("web/login.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /auth-ui/assets/redirect.js", s.asset("web/redirect.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /auth-ui/assets/logo.png", s.asset("web/logo.png", "image/png"))
	mux.HandleFunc("GET /auth-ui/config", s.handleUIConfig)
	mux.HandleFunc("POST /auth-ui/login", s.handleUILogin)
	mux.HandleFunc("POST /auth-ui/login/local", s.handleUILocal)
	if s.proxy != nil {
		// Everything not matched above: the sign-in page at "/", the Penpot frontend for the rest.
		mux.HandleFunc("/", s.handleAll)
	}
}

func (s *Server) asset(name, ctype string) http.HandlerFunc {
	body, err := webFS.ReadFile(name)
	return func(w http.ResponseWriter, _ *http.Request) {
		if err != nil {
			http.NotFound(w, nil)
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(body)
	}
}

// handleAll shows the sign-in page for "/" to visitors without a session and passes everything else to Penpot.
func (s *Server) handleAll(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/" && s.signedOut(r) {
		s.servePage(w)
		return
	}
	s.proxy.ServeHTTP(w, r)
}

// signedOut is true only when it is certain the visitor has no session. Any doubt (Penpot unreachable, unexpected
// answer) passes the request on, so Penpot's own login screen stays usable instead of the page looping.
func (s *Server) signedOut(r *http.Request) bool {
	cookie := r.Header.Get("Cookie")
	if cookie == "" {
		return true
	}
	anon, err := s.pp.IsAnonymous(r.Context(), cookie)
	if err != nil {
		s.log.Warn("session check failed, passing the request to penpot", "err", err)
		return false
	}
	return anon
}

func (s *Server) servePage(w http.ResponseWriter) {
	body, err := webFS.ReadFile("web/login.html")
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", uiCSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, v map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleUIConfig tells the page whether to show "Sign in with local account".
func (s *Server) handleUIConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"local": len(s.cfg.LocalAccounts) > 0})
}

// decodeUICreds reads {"username","password"} from the sign-in page.
func decodeUICreds(w http.ResponseWriter, r *http.Request) (typed, password string, ok bool) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_request", "error_description": msgWrongCredentials})
		return "", "", false
	}
	typed = strings.ToLower(strings.TrimSpace(in.Username))
	if typed == "" || in.Password == "" || len(typed) > 254 || len(in.Password) > 500 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_request", "error_description": msgWrongCredentials})
		return "", "", false
	}
	return typed, in.Password, true
}

// handleUILocal signs in a local Penpot account (break-glass): only the e-mail addresses in LocalAccounts, with the
// password Penpot itself holds for them. AD users never use this; their Penpot password is a value nobody knows.
func (s *Server) handleUILocal(w http.ResponseWriter, r *http.Request) {
	email, password, ok := decodeUICreds(w, r)
	if !ok {
		return
	}
	ip := clientIP(r)
	key := "local:" + email
	if s.locked(key, ip) {
		w.Header().Set("Retry-After", "900")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too-many-attempts", "error_description": "Too many failed attempts. Try again in 15 minutes."})
		return
	}
	if !slices.Contains(s.cfg.LocalAccounts, email) {
		s.failed(key, ip)
		s.log.Warn("local sign-in refused: not a break-glass account", "user", email, "ip", ip)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "wrong-credentials", "error_description": msgWrongCredentials})
		return
	}
	res, err := s.pp.LoginPassword(r.Context(), email, password)
	if err != nil {
		s.log.Error("local sign-in: penpot unavailable", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "service-unavailable", "error_description": msgSignInFailed})
		return
	}
	if res.Status != http.StatusOK {
		s.failed(key, ip)
		s.log.Warn("local sign-in refused", "user", email, "ip", ip, "status", res.Status)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "wrong-credentials", "error_description": msgWrongCredentials})
		return
	}
	s.lim.reset("u:" + key)
	s.log.Warn("break-glass local sign-in", "user", email, "ip", ip)
	passCookies(w, res)
	writeJSON(w, http.StatusOK, map[string]any{"redirect": "/"})
}

// handleUILogin answers the sign-in page: {"username","password"} in, Penpot's session cookie out.
func (s *Server) handleUILogin(w http.ResponseWriter, r *http.Request) {
	typed, password, ok := decodeUICreds(w, r)
	if !ok {
		return
	}
	res, fail := s.authenticate(r.Context(), typed, password, clientIP(r))
	if fail != nil {
		if fail.retry {
			w.Header().Set("Retry-After", "900")
		}
		writeJSON(w, fail.status, map[string]any{"error": fail.code, "error_description": fail.msg})
		return
	}
	passCookies(w, res)
	writeJSON(w, http.StatusOK, map[string]any{"redirect": "/"})
}

// newFrontendProxy forwards requests to the Penpot frontend Service and adds redirectTag to its HTML.
func newFrontendProxy(target string) (http.Handler, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("not an http(s) URL: %q", target)
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = pr.In.Host
			// Plain HTML is needed to add the script tag; every other file keeps its compression.
			if pr.In.URL.Path == "/" {
				pr.Out.Header.Del("Accept-Encoding")
			}
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-Ip"} {
				if v := pr.In.Header.Values(h); len(v) > 0 {
					pr.Out.Header[h] = v
				}
			}
		},
		// Penpot streams events and uses WebSockets: never hold output back.
		FlushInterval:  -1,
		ModifyResponse: injectRedirect,
	}, nil
}

// injectRedirect adds redirectTag at the end of <head> of an HTML page; any other response passes unchanged.
func injectRedirect(resp *http.Response) error {
	if resp.Request == nil || resp.Request.URL.Path != "/" || resp.StatusCode != http.StatusOK ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || resp.Header.Get("Content-Encoding") != "" {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	out := bytes.Replace(b, []byte("</head>"), []byte(redirectTag+"</head>"), 1)
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}
