package zita

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// mintTestToken builds a HS256 lurus_session JWT in the same shape
// platform-core's auth.IssueSessionToken produces. Used by every test
// that needs a "valid" token to feed into ValidateSession or the
// middleware. Mirrors platform-core's auth/session.go IssueSessionToken
// — if the platform's signing changes, this helper changes in lockstep
// and every test re-runs.
//
// Returning an empty string for the token is the convention for "give me
// a malformed token" — callers pass that to test the happy-path-failed
// branches.
func mintTestToken(t *testing.T, accountID int64, ttl time.Duration, secret string) string {
	t.Helper()
	if secret == "" {
		t.Fatalf("mintTestToken: empty secret")
	}
	header := `{"typ":"JWT","alg":"HS256"}`
	payload, err := json.Marshal(map[string]any{
		"iss": sessionIssuer,
		"sub": fmt.Sprintf("lurus:%d", accountID),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(ttl).Unix(),
	})
	if err != nil {
		t.Fatalf("mintTestToken: marshal payload: %v", err)
	}
	body := b64(header) + "." + b64(string(payload))
	sig := hmacSHA256([]byte(body), []byte(secret))
	return body + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// mintTokenCustomClaims is the escape hatch for tests that need a
// non-default iss / sub / exp. Mirrors mintTestToken but takes the
// payload as a map so each test can express exactly the shape it wants
// to verify the validator against.
func mintTokenCustomClaims(t *testing.T, claims map[string]any, secret string) string {
	t.Helper()
	header := `{"typ":"JWT","alg":"HS256"}`
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("mintTokenCustomClaims: marshal payload: %v", err)
	}
	body := b64(header) + "." + b64(string(payload))
	sig := hmacSHA256([]byte(body), []byte(secret))
	return body + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func b64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
