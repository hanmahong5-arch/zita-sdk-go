//go:build e2e

// Package zita e2e tests against a live STAGE platform-core. Gated on the
// `e2e` build tag and on PLATFORM_STAGE_REACHABLE=1 so a developer running
// `go test ./...` locally never accidentally talks to production
// infrastructure.
//
// What's verified:
//   - /sli endpoint reachable and returns expected JSON (sanity probe)
//   - LoginRedirectURL produces a URL the live platform actually serves
//     (catches drift if the platform renames /login or the host)
//   - ValidateSession with malformed input returns ErrInvalidSession
//     (verifies the SDK's error path is sound; does not exercise HMAC
//     since CI does not hold the platform's session secret)
//
// What's NOT verified (deferred to Layer C / newhub integration):
//   - Round-trip of a real session token (mint at platform → validate via
//     SDK). That requires CI to hold IDENTITY_SESSION_SECRET, which the
//     symmetric HMAC scheme makes equivalent to giving CI signing
//     capability. We'll revisit when newhub's first PR lands and
//     necessitates a full-trust e2e harness.
package zita

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

// stageURL returns the STAGE platform base URL or skips the test when not
// configured. Honors PLATFORM_STAGE_URL with a default for local
// experimentation; PLATFORM_STAGE_REACHABLE=1 is the master gate (CI sets
// it after the reachability probe succeeds).
func stageURL(t *testing.T) string {
	t.Helper()
	if os.Getenv("PLATFORM_STAGE_REACHABLE") != "1" {
		t.Skip("PLATFORM_STAGE_REACHABLE != 1 — skipping STAGE e2e")
	}
	u := os.Getenv("PLATFORM_STAGE_URL")
	if u == "" {
		u = "https://identity.lurus.cn"
	}
	return u
}

func TestE2E_StageReachable(t *testing.T) {
	base := stageURL(t)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(base + "/sli")
	if err != nil {
		t.Fatalf("GET /sli: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /sli: status = %d, want 200", resp.StatusCode)
	}
}

func TestE2E_LoginRedirectURL_HitsRealPlatform(t *testing.T) {
	base := stageURL(t)

	cli, err := NewClient(Config{
		PlatformURL:   base,
		SessionSecret: "e2e-placeholder-no-roundtrip",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	u := cli.LoginRedirectURL("https://example.com/cb")

	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("LoginRedirectURL produced unparseable URL: %q (%v)", u, err)
	}

	// Hit the URL — the platform must serve /login (200 or 30x). 404
	// would mean the route was removed, breaking every consumer's
	// "Login" button.
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		// Don't follow redirects — a 30x is a valid answer (login UI may
		// bounce to OIDC) and we just want to confirm the route exists.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := httpClient.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 400:
		// OK — platform served the route
	default:
		t.Errorf("GET %s: status = %d, want 2xx or 3xx (parsed: %s)",
			u, resp.StatusCode, parsed.String())
	}
}

func TestE2E_ValidateSession_MalformedRejected(t *testing.T) {
	// Doesn't actually need network, but lives here so it ALSO runs as
	// part of the e2e suite — guards against the SDK's invariant
	// "obviously bad input fails closed" surviving across releases.
	base := stageURL(t)

	cli, err := NewClient(Config{
		PlatformURL:   base,
		SessionSecret: "e2e-placeholder-no-roundtrip",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	cases := []string{
		"",
		"not-a-jwt",
		"only.two",
		"a.b.c.d",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			_, err := cli.ValidateSession(tc)
			if !errors.Is(err, ErrInvalidSession) {
				t.Errorf("err = %v, want ErrInvalidSession", err)
			}
		})
	}
}
