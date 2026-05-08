// Package zita is the Lurus identity SDK — a thin client over
// identity.lurus.cn that gives any Go service a drop-in OIDC redirect URL,
// HMAC-fast-path session validation, and a gin AuthMiddleware. See the
// repo README and ADR-0011 (in the lurus governance repo) for the design
// contract.
//
// Example:
//
//	cli, err := zita.NewClient(zita.Config{
//	    PlatformURL:   "https://identity.lurus.cn",
//	    SessionSecret: os.Getenv("IDENTITY_SESSION_SECRET"),
//	})
//	if err != nil {
//	    log.Fatalf("zita: %v", err)
//	}
//
//	r := gin.New()
//	r.Use(cli.AuthMiddleware())
package zita

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config is the runtime contract between the consumer and platform-core.
// All fields are validated by NewClient — fail-fast at boot is the SDK's
// contract.
type Config struct {
	// PlatformURL is the canonical lurus identity origin, e.g.
	// "https://identity.lurus.cn". Trailing slash is stripped on parse.
	// Required.
	PlatformURL string

	// SessionSecret MUST equal platform-core's SessionSecret (the HMAC
	// key used to sign session tokens). Distribution is out-of-band —
	// the SDK never fetches it from the network. Required.
	//
	// Empty value => NewClient returns ErrConfigInvalid.
	SessionSecret string

	// HTTPClient is the optional HTTP client used for any network calls
	// the SDK eventually makes (Whoami / Refresh land in v0.2.x). Nil
	// uses a default with a 10s timeout — passing your own is the escape
	// hatch for proxies, chaos injection, or test fixtures.
	HTTPClient *http.Client
}

// Client is the SDK's main type. All public surface hangs off this
// struct; the zero value is unusable — always go through NewClient.
type Client struct {
	platformURL   string // normalised: scheme + host, no trailing slash
	sessionSecret string
	httpClient    *http.Client
}

// NewClient validates Config and returns a ready-to-use Client. Returns
// ErrConfigInvalid (wrapped with the specific reason) for any missing or
// unparseable field — boot-time crash beats every-request 503.
func NewClient(cfg Config) (*Client, error) {
	if cfg.PlatformURL == "" {
		return nil, fmt.Errorf("%w: PlatformURL is required", ErrConfigInvalid)
	}
	u, err := url.Parse(cfg.PlatformURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parse PlatformURL: %v", ErrConfigInvalid, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: PlatformURL must be http(s), got %q",
			ErrConfigInvalid, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: PlatformURL is missing host", ErrConfigInvalid)
	}
	if cfg.SessionSecret == "" {
		return nil, fmt.Errorf("%w: SessionSecret is required (must match "+
			"platform-core's SESSION_SECRET)", ErrConfigInvalid)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	// Re-render normalised URL: scheme://host[:port], no trailing slash.
	normalised := strings.TrimRight(
		(&url.URL{Scheme: u.Scheme, Host: u.Host}).String(),
		"/",
	)

	return &Client{
		platformURL:   normalised,
		sessionSecret: cfg.SessionSecret,
		httpClient:    httpClient,
	}, nil
}

// PlatformURL returns the normalised origin the client was configured
// with. Useful for consumers that want to render "logged out, click here
// to login" without re-deriving the URL.
func (c *Client) PlatformURL() string { return c.platformURL }
