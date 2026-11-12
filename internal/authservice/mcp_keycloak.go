package authservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// liveRoleReader checks current client-role mappings rather than trusting roles from an old login.
type liveRoleReader interface {
	MCPAllowed(context.Context, string, string) (bool, error)
}
type roleReader struct {
	kc                *Keycloak
	mu                sync.Mutex
	token, clientUUID string
	expires           time.Time
}

// directoryRow is the part of a Keycloak user the directory search reads (brief representation).
type directoryRow struct {
	Username  string `json:"username"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Enabled   bool   `json:"enabled"`
}

// userDirectory searches Keycloak users with the service account (satisfied by *roleReader).
type userDirectory interface {
	SearchUsers(ctx context.Context, q string, limit int) ([]directoryRow, error)
}

// bearer returns the service-account token, fetching a new one (client_credentials) when the old one is about to
// expire. Only the refresh holds the lock, lookups run concurrently.
func (r *roleReader) bearer(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Now().Before(r.expires) && r.token != "" {
		return r.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {r.kc.clientID}, "client_secret": {r.kc.clientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.kc.issuerURL+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := r.kc.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	var tok struct {
		Token   string `json:"access_token"`
		Expires int    `json:"expires_in"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || tok.Token == "" {
		return "", errors.New("identity service authentication failed")
	}
	r.token = tok.Token
	r.expires = time.Now().Add(time.Duration(max(1, tok.Expires-30)) * time.Second)
	return r.token, nil
}

func (r *roleReader) adminBase() string {
	return strings.Replace(r.kc.issuerURL, "/realms/", "/admin/realms/", 1)
}

func (r *roleReader) json(ctx context.Context, path string, out any) error {
	tok, err := r.bearer(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := r.kc.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		r.mu.Lock()
		r.expires = time.Time{} // revoked early: fetch a new token next time
		r.mu.Unlock()
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("identity lookup status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(out)
}

func (r *roleReader) clientID(ctx context.Context, base string) (string, error) {
	r.mu.Lock()
	id := r.clientUUID
	r.mu.Unlock()
	if id != "" {
		return id, nil
	}
	var clients []struct {
		ID       string `json:"id"`
		ClientID string `json:"clientId"`
	}
	if err := r.json(ctx, base+"/clients?clientId="+url.QueryEscape(r.kc.clientID), &clients); err != nil {
		return "", err
	}
	for _, c := range clients {
		if c.ClientID == r.kc.clientID {
			id = c.ID
		}
	}
	if id == "" {
		return "", errors.New("identity client not found")
	}
	r.mu.Lock()
	r.clientUUID = id
	r.mu.Unlock()
	return id, nil
}

// SearchUsers runs Keycloak's user search (enabled users only; the caller filters further and picks the fields).
func (r *roleReader) SearchUsers(ctx context.Context, q string, limit int) ([]directoryRow, error) {
	var rows []directoryRow
	path := fmt.Sprintf("%s/users?search=%s&max=%d&enabled=true&briefRepresentation=true", r.adminBase(), url.QueryEscape(q), limit)
	if err := r.json(ctx, path, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// MCPAllowed reports whether the enabled, unique user with this e-mail holds the exact Penpot client role now
// (despite the name it checks any client role, e.g. the administrator role).
func (r *roleReader) MCPAllowed(ctx context.Context, email, role string) (bool, error) {
	base := r.adminBase()
	clientUUID, err := r.clientID(ctx, base)
	if err != nil {
		return false, err
	}
	var users []struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Enabled bool   `json:"enabled"`
	}
	if err := r.json(ctx, base+"/users?exact=true&email="+url.QueryEscape(email), &users); err != nil {
		return false, err
	}
	if len(users) != 1 || !strings.EqualFold(users[0].Email, email) || !users[0].Enabled {
		return false, nil
	}
	var roles []struct {
		Name string `json:"name"`
	}
	if err := r.json(ctx, base+"/users/"+url.PathEscape(users[0].ID)+"/role-mappings/clients/"+url.PathEscape(clientUUID)+"/composite", &roles); err != nil {
		return false, err
	}
	for _, v := range roles {
		if v.Name == role {
			return true, nil
		}
	}
	return false, nil
}

// UserActive reports whether exactly one Keycloak user has this e-mail and is enabled.
func (r *roleReader) UserActive(ctx context.Context, email string) (bool, error) {
	var users []struct {
		Email   string `json:"email"`
		Enabled bool   `json:"enabled"`
	}
	if err := r.json(ctx, r.adminBase()+"/users?exact=true&email="+url.QueryEscape(email), &users); err != nil {
		return false, err
	}
	return len(users) == 1 && strings.EqualFold(users[0].Email, email) && users[0].Enabled, nil
}
