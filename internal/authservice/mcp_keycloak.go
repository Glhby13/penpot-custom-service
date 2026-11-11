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

func (r *roleReader) json(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.kc.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("identity lookup status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(out)
}
func (r *roleReader) MCPAllowed(ctx context.Context, email, role string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Now().After(r.expires) {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {r.kc.clientID}, "client_secret": {r.kc.clientSecret}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.kc.issuerURL+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
		if err != nil {
			return false, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := r.kc.httpClient.Do(req)
		if err != nil {
			return false, err
		}
		var tok struct {
			Token   string `json:"access_token"`
			Expires int    `json:"expires_in"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || tok.Token == "" {
			return false, errors.New("identity service authentication failed")
		}
		r.token = tok.Token
		r.expires = time.Now().Add(time.Duration(max(1, tok.Expires-30)) * time.Second)
	}
	base := strings.Replace(r.kc.issuerURL, "/realms/", "/admin/realms/", 1)
	if r.clientUUID == "" {
		var clients []struct {
			ID       string `json:"id"`
			ClientID string `json:"clientId"`
		}
		if err := r.json(ctx, base+"/clients?clientId="+url.QueryEscape(r.kc.clientID), &clients); err != nil {
			return false, err
		}
		for _, c := range clients {
			if c.ClientID == r.kc.clientID {
				r.clientUUID = c.ID
			}
		}
		if r.clientUUID == "" {
			return false, errors.New("identity client not found")
		}
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
	if err := r.json(ctx, base+"/users/"+url.PathEscape(users[0].ID)+"/role-mappings/clients/"+url.PathEscape(r.clientUUID)+"/composite", &roles); err != nil {
		return false, err
	}
	for _, v := range roles {
		if v.Name == role {
			return true, nil
		}
	}
	return false, nil
}
