package authservice

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Errors returned by DirectGrant.
var (
	// ErrBadCredentials: Keycloak refused the username or password (it answers invalid_grant for both).
	ErrBadCredentials = errors.New("invalid credentials")
	// ErrAccessDenied: Keycloak refused the sign-in for a reason other than the credentials (policy, deny-without-role flow).
	ErrAccessDenied = errors.New("access denied")
)

// Claims is the identity read from the Keycloak access token.
type Claims struct {
	Subject           string
	Email             string
	PreferredUsername string
	Name              string
	GivenName         string
	FamilyName        string
	// Roles are the client roles of the Penpot client only (resource_access[client].roles).
	Roles []string
}

// HasRole reports whether the user holds the client role.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// DisplayName is the Penpot full name: Keycloak "name", else given + family name, else the part before the @.
func (c *Claims) DisplayName() string {
	if n := strings.TrimSpace(c.Name); n != "" {
		return n
	}
	if n := strings.TrimSpace(c.GivenName + " " + c.FamilyName); n != "" {
		return n
	}
	if i := strings.Index(c.Email, "@"); i > 0 {
		return c.Email[:i]
	}
	return c.Email
}

// Keycloak signs users in with the Resource Owner Password flow of the Penpot client.
type Keycloak struct {
	issuerURL    string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

// NewKeycloak builds the client. insecureTLS disables certificate checks (internal CA missing from the image).
func NewKeycloak(issuerURL, clientID, clientSecret string, insecureTLS bool) *Keycloak {
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecureTLS}} // #nosec G402 -- opt-in, off by default
	return &Keycloak{
		issuerURL:    strings.TrimRight(issuerURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Transport: tr, Timeout: 15 * time.Second},
	}
}

// DirectGrant signs the user in with Keycloak's token endpoint (grant_type=password). No redirect is involved.
func (k *Keycloak) DirectGrant(ctx context.Context, username, password string) (*Claims, error) {
	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {k.clientID},
		"client_secret": {k.clientSecret},
		"username":      {username},
		"password":      {password},
		"scope":         {"openid profile email"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.issuerURL+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("direct grant: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("direct grant: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("direct grant: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		switch {
		case e.Error == "invalid_grant":
			return nil, ErrBadCredentials
		case resp.StatusCode == http.StatusForbidden || e.Error == "access_denied" || e.Error == "unauthorized_client":
			return nil, ErrAccessDenied
		case resp.StatusCode == http.StatusUnauthorized && e.Error == "":
			// The "deny access" step of the Direct Grant flow (user without the client's access role) answers 401 with
			// an HTML page instead of JSON. A wrong client secret comes back as JSON invalid_client and falls through.
			return nil, ErrAccessDenied
		}
		return nil, fmt.Errorf("direct grant failed (%d): %s", resp.StatusCode, e.Error)
	}

	var tr struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("direct grant response: %w", err)
	}
	claims, err := parseClaims(tr.AccessToken, k.clientID)
	if err != nil {
		if claims, err = parseClaims(tr.IDToken, k.clientID); err != nil {
			return nil, fmt.Errorf("parse token: %w", err)
		}
	}
	return claims, nil
}

// parseClaims reads the payload of a JWT that came straight from Keycloak's token endpoint over TLS in the same
// request, so the signature is not re-verified (same approach as the n8n auth-service).
func parseClaims(jwt, clientID string) (*Claims, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid jwt format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode jwt payload: %w", err)
	}
	var raw struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
		ResourceAccess    map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("parse jwt payload: %w", err)
	}
	return &Claims{
		Subject:           raw.Sub,
		Email:             raw.Email,
		PreferredUsername: raw.PreferredUsername,
		Name:              raw.Name,
		GivenName:         raw.GivenName,
		FamilyName:        raw.FamilyName,
		Roles:             raw.ResourceAccess[clientID].Roles,
	}, nil
}
