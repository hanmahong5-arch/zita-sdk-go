package zita

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// sessionIssuer is the iss claim platform-core writes into every
// HS256-signed lurus_session JWT. Mirrors auth.SessionIssuer in
// 2l-svc-platform/internal/pkg/auth/session.go — the SDK and the platform
// MUST agree on this string.
const sessionIssuer = "lurus-platform"

// sessionSubPrefix is the prefix the platform uses on the sub claim:
// "lurus:<accountID>". Mirrors the same constant in platform-core's
// auth/session.go ValidateSession.
const sessionSubPrefix = "lurus:"

// verifySessionToken HMAC-verifies a lurus_session JWT and returns the
// embedded account id. Pure function — no network, no global state — so
// it is safe to call on every request without coordination.
//
// Errors map onto the SDK's sentinels:
//   - ErrSessionExpired when exp < now
//   - ErrInvalidSession for everything else (malformed, bad sig, wrong
//     issuer, bad sub format)
//
// Implementation mirrors 2l-svc-platform/internal/pkg/auth/session.go
// ValidateSession exactly. If the platform's signing changes, the SDK
// breaks at v0.x boundary — which is the point of the v0.1.x pre-alpha
// pin.
func verifySessionToken(token, secret string) (int64, error) {
	if secret == "" {
		// Should never happen — NewClient rejects an empty secret. Keep
		// the guard so a stray nil-Client.verifySessionToken call is a
		// loud error instead of a silent "all sessions valid" disaster.
		return 0, fmt.Errorf("%w: empty secret", ErrConfigInvalid)
	}
	if token == "" {
		return 0, fmt.Errorf("%w: empty token", ErrInvalidSession)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, fmt.Errorf("%w: malformed token (expected 3 parts, got %d)",
			ErrInvalidSession, len(parts))
	}

	// Verify HMAC-SHA256 signature before trusting any claims.
	body := parts[0] + "." + parts[1]
	expectedSig := hmacSHA256([]byte(body), []byte(secret))
	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, fmt.Errorf("%w: decode signature: %v", ErrInvalidSession, err)
	}
	if !hmac.Equal(expectedSig, gotSig) {
		return 0, fmt.Errorf("%w: signature mismatch", ErrInvalidSession)
	}

	// Decode and validate payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, fmt.Errorf("%w: decode payload: %v", ErrInvalidSession, err)
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return 0, fmt.Errorf("%w: parse payload: %v", ErrInvalidSession, err)
	}
	if claims.Iss != sessionIssuer {
		return 0, fmt.Errorf("%w: unexpected issuer %q", ErrInvalidSession, claims.Iss)
	}
	if claims.Exp == 0 {
		return 0, fmt.Errorf("%w: missing exp claim", ErrInvalidSession)
	}
	if time.Now().Unix() > claims.Exp {
		return 0, ErrSessionExpired
	}

	// Parse sub: "lurus:<accountID>".
	if !strings.HasPrefix(claims.Sub, sessionSubPrefix) {
		return 0, fmt.Errorf("%w: invalid sub format %q", ErrInvalidSession, claims.Sub)
	}
	id, err := strconv.ParseInt(claims.Sub[len(sessionSubPrefix):], 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: invalid account id in sub", ErrInvalidSession)
	}
	return id, nil
}

func hmacSHA256(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
