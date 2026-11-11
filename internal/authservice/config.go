package authservice

import (
	"errors"
	"net/url"
	"os"
	"strings"
)

// Config holds the settings of penpot-auth-service. Everything comes from environment variables; the two secrets
// have no default on purpose (the service refuses to start without them).
type Config struct {
	Port     string
	LogLevel string

	// Keycloak realm URL, e.g. https://auth.dev.btn.co.id/realms/platform-dev-btn
	KeycloakURL      string
	OIDCClientID     string
	OIDCClientSecret string
	// KeycloakInsecureTLS skips certificate verification towards Keycloak (internal CA not in the image).
	KeycloakInsecureTLS bool
	// AccessRole is the Keycloak client role a user needs to sign in. Empty (the default) = every user Keycloak
	// accepts may sign in, i.e. every AD user; no role has to be assigned.
	AccessRole string
	// LocalAccounts are the e-mail addresses of Penpot's own (local) break-glass accounts that may use "Sign in with
	// local account". Empty = that button is off.
	LocalAccounts []string
	// AdminRole is the Keycloak client role for Penpot administrators. Nothing is enforced with it yet; it is
	// read at sign-in and logged. MCP independently requires MCPAccessRole (no admin bypass).
	AdminRole string
	// MCP is opt-in; the dedicated client role is mandatory (administrators have no bypass).
	MCPEnabled      bool
	MCPAccessRole   string
	MCPPublicOrigin string
	MCPServerURL    string
	MCPWSURL        string
	// EmailDomain (e.g. "btn.co.id"): Penpot's form only accepts an e-mail address, so users type user@<domain> and
	// the part before the @ is what is sent to Keycloak as the AD username (no need for Keycloak "Login with email").
	// Any other domain is refused. Empty = the typed value is sent to Keycloak unchanged.
	EmailDomain string

	// PenpotBackendURL is the in-cluster URL of the Penpot backend Service (never the public ingress).
	PenpotBackendURL string
	// PenpotFrontendURL is the in-cluster URL of the Penpot frontend Service. When set, this service answers "/":
	// the sign-in page for visitors without a session, the Penpot frontend (proxied) for everyone else.
	PenpotFrontendURL string
	// PenpotRPCPath is the path prefix of Penpot's RPC commands on the backend.
	PenpotRPCPath string
	// ManagedPasswordSeed keys the HMAC that derives each user's Penpot password. Rotating it locks every
	// already-provisioned user out until their profile is deleted in Penpot, so treat it as permanent.
	ManagedPasswordSeed string
}

// LoadConfig reads the configuration from the environment.
func LoadConfig() (*Config, error) {
	c := &Config{
		Port:                env("PORT", "8080"),
		LogLevel:            env("LOG_LEVEL", "info"),
		KeycloakURL:         strings.TrimRight(env("KEYCLOAK_URL", ""), "/"),
		OIDCClientID:        env("OIDC_CLIENT_ID", ""),
		OIDCClientSecret:    env("OIDC_CLIENT_SECRET", ""),
		KeycloakInsecureTLS: strings.EqualFold(env("KEYCLOAK_INSECURE_TLS", "false"), "true"),
		AccessRole:          env("ACCESS_ROLE", ""),
		LocalAccounts:       splitList(env("LOCAL_ACCOUNTS", "")),
		AdminRole:           env("ADMIN_ROLE", "penpot-admin"),
		MCPEnabled:          strings.EqualFold(env("MCP_ENABLED", "false"), "true"),
		MCPAccessRole:       env("MCP_ACCESS_ROLE", "mcp-access"),
		MCPPublicOrigin:     strings.TrimRight(env("MCP_PUBLIC_ORIGIN", ""), "/"),
		MCPServerURL:        env("MCP_SERVER_URL", ""),
		MCPWSURL:            env("MCP_WS_URL", ""),
		EmailDomain:         strings.ToLower(strings.TrimPrefix(env("EMAIL_DOMAIN", ""), "@")),
		PenpotBackendURL:    strings.TrimRight(env("PENPOT_BACKEND_URL", ""), "/"),
		PenpotFrontendURL:   strings.TrimRight(env("PENPOT_FRONTEND_URL", ""), "/"),
		PenpotRPCPath:       "/" + strings.Trim(env("PENPOT_RPC_PATH", "/api/rpc/command"), "/"),
		ManagedPasswordSeed: env("MANAGED_PASSWORD_SEED", ""),
	}
	if c.MCPEnabled && (c.MCPAccessRole == "" || c.MCPPublicOrigin == "") {
		return nil, errors.New("MCP_ENABLED requires MCP_ACCESS_ROLE and MCP_PUBLIC_ORIGIN")
	}
	if c.MCPEnabled {
		for _, raw := range []string{c.MCPPublicOrigin, c.MCPServerURL, c.MCPWSURL} {
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return nil, errors.New("invalid MCP origin/upstream URL")
			}
		}
	}
	var missing []string
	for k, v := range map[string]string{
		"KEYCLOAK_URL":          c.KeycloakURL,
		"OIDC_CLIENT_ID":        c.OIDCClientID,
		"OIDC_CLIENT_SECRET":    c.OIDCClientSecret,
		"PENPOT_BACKEND_URL":    c.PenpotBackendURL,
		"MANAGED_PASSWORD_SEED": c.ManagedPasswordSeed,
	} {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, errors.New("missing required environment: " + strings.Join(missing, ", "))
	}
	if len(c.ManagedPasswordSeed) < 32 {
		return nil, errors.New("MANAGED_PASSWORD_SEED must be at least 32 characters")
	}
	return c, nil
}

// splitList reads a comma separated list, lower-cased, without empty entries.
func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
