package authservice

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Penpot talks to the Penpot backend Service inside the cluster. It uses Penpot's own RPC commands only, so the
// profile and the session are created by Penpot itself and no database access is needed.
type Penpot struct {
	baseURL    string
	rpcPath    string
	seed       string
	httpClient *http.Client
}

// NewPenpot builds the backend client.
func NewPenpot(baseURL, rpcPath, seed string) *Penpot {
	return &Penpot{baseURL: baseURL, rpcPath: rpcPath, seed: seed, httpClient: &http.Client{Timeout: 20 * time.Second}}
}

// ManagedPassword is the password the service sets for a user's Penpot profile: Aa1# + HMAC-SHA256(seed, email), never
// shown to anyone. The user signs in with the AD password; Penpot only ever sees this value.
// The prefix guarantees lowercase, uppercase, digit, and special character required by Penpot's password policy.
func (p *Penpot) ManagedPassword(email string) string {
	m := hmac.New(sha256.New, []byte(p.seed))
	m.Write([]byte("penpot-managed::" + strings.ToLower(email)))
	return "Aa1#" + hex.EncodeToString(m.Sum(nil))
}

// rpcResult is an unmodified answer of the Penpot backend.
type rpcResult struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *rpcResult) has(code string) bool { return bytes.Contains(r.Body, []byte("~:"+code)) }

func (p *Penpot) call(ctx context.Context, command string, body []byte) (*rpcResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+p.rpcPath+"/"+command, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", transitContentType)
	req.Header.Set("Accept", transitContentType)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("penpot %s: %w", command, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("penpot %s: %w", command, err)
	}
	return &rpcResult{Status: resp.StatusCode, Header: resp.Header, Body: b}, nil
}

const zeroUUID = "~u00000000-0000-0000-0000-000000000000"

// IsAnonymous asks the backend who the session cookie belongs to (the same get-profile call Penpot's own frontend
// makes at start-up): a visitor without a session gets the profile with the all-zero id.
func (p *Penpot) IsAnonymous(ctx context.Context, cookie string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+p.rpcPath+"/get-profile", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Accept", transitContentType)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("penpot get-profile: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, fmt.Errorf("penpot get-profile: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("penpot get-profile: status %d", resp.StatusCode)
	}
	return anonymousFromProfile(b)
}

// anonymousFromProfile reads :id from the transit map of a profile.
func anonymousFromProfile(body []byte) (bool, error) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return false, err
	}
	if t, ok := v.([]any); ok {
		for i := 1; i+1 < len(t); i += 2 {
			if k, _ := t[i].(string); k == "~:id" {
				id, _ := t[i+1].(string)
				return id == zeroUUID, nil
			}
		}
	}
	return false, fmt.Errorf("no :id in the profile answer")
}

// Login runs Penpot's login-with-password with the managed password.
func (p *Penpot) Login(ctx context.Context, email string) (*rpcResult, error) {
	return p.LoginPassword(ctx, email, p.ManagedPassword(email))
}

// LoginPassword runs Penpot's login-with-password with the given password.
func (p *Penpot) LoginPassword(ctx context.Context, email, password string) (*rpcResult, error) {
	return p.call(ctx, "login-with-password", transitMap(
		"email", transitEscape(email),
		"password", transitEscape(password),
	))
}

// Register creates the profile (first sign-in) and returns Penpot's register-profile answer, which carries the
// session cookie when the profile is created active (email verification disabled). Errors that Penpot answers with
// an HTTP status are returned in the result, not as err.
func (p *Penpot) Register(ctx context.Context, email, fullname string) (*rpcResult, error) {
	prep, err := p.call(ctx, "prepare-register-profile", transitMap(
		"fullname", transitEscape(fullname),
		"email", transitEscape(email),
		"password", transitEscape(p.ManagedPassword(email)),
	))
	if err != nil || prep.Status != http.StatusOK {
		return prep, err
	}
	token, err := extractToken(prep.Body)
	if err != nil {
		return nil, fmt.Errorf("penpot prepare-register-profile: %w", err)
	}
	return p.call(ctx, "register-profile", transitMap("token", transitEscape(token)))
}

// extractToken reads :token from the transit map that prepare-register-profile returns.
func extractToken(body []byte) (string, error) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return "", err
	}
	switch t := v.(type) {
	case []any:
		for i := 1; i+1 < len(t); i += 2 {
			if k, _ := t[i].(string); k == "~:token" {
				if s, ok := t[i+1].(string); ok && s != "" {
					return transitUnescape(s), nil
				}
			}
		}
	case map[string]any:
		for _, key := range []string{"~:token", "token"} {
			if s, ok := t[key].(string); ok && s != "" {
				return transitUnescape(s), nil
			}
		}
	}
	return "", fmt.Errorf("no token in response")
}
