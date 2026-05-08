package zita

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVerifySessionToken_HappyPath(t *testing.T) {
	const secret = "test-secret-please-do-not-use-in-prod"
	tok := mintTestToken(t, 4521, time.Hour, secret)

	gotID, err := verifySessionToken(tok, secret)
	if err != nil {
		t.Fatalf("verifySessionToken: unexpected err: %v", err)
	}
	if gotID != 4521 {
		t.Errorf("accountID = %d, want 4521", gotID)
	}
}

func TestVerifySessionToken_EmptySecret(t *testing.T) {
	_, err := verifySessionToken("anything", "")
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("err = %v, want ErrConfigInvalid", err)
	}
}

func TestVerifySessionToken_EmptyToken(t *testing.T) {
	_, err := verifySessionToken("", "secret")
	if !errors.Is(err, ErrInvalidSession) {
		t.Errorf("err = %v, want ErrInvalidSession", err)
	}
}

func TestVerifySessionToken_MalformedShape(t *testing.T) {
	cases := []string{
		"not-a-jwt",
		"only.two",
		"a.b.c.d",
		"....",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			_, err := verifySessionToken(tc, "secret")
			if !errors.Is(err, ErrInvalidSession) {
				t.Errorf("err = %v, want ErrInvalidSession", err)
			}
		})
	}
}

func TestVerifySessionToken_TamperedSignature(t *testing.T) {
	const secret = "test-secret"
	tok := mintTestToken(t, 1, time.Hour, secret)

	// Flip the last char of the signature segment.
	parts := strings.Split(tok, ".")
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	tampered := strings.Join(parts, ".")

	_, err := verifySessionToken(tampered, secret)
	if !errors.Is(err, ErrInvalidSession) {
		t.Errorf("err = %v, want ErrInvalidSession", err)
	}
}

func TestVerifySessionToken_WrongSecret(t *testing.T) {
	tok := mintTestToken(t, 1, time.Hour, "secret-A")
	_, err := verifySessionToken(tok, "secret-B")
	if !errors.Is(err, ErrInvalidSession) {
		t.Errorf("err = %v, want ErrInvalidSession", err)
	}
}

func TestVerifySessionToken_Expired(t *testing.T) {
	const secret = "test-secret"
	// Mint with a past expiry — give it -1h so the second-precision exp
	// is unambiguously in the past.
	tok := mintTestToken(t, 1, -1*time.Hour, secret)

	_, err := verifySessionToken(tok, secret)
	if !errors.Is(err, ErrSessionExpired) {
		t.Errorf("err = %v, want ErrSessionExpired", err)
	}
}

func TestVerifySessionToken_WrongIssuer(t *testing.T) {
	const secret = "test-secret"
	tok := mintTokenCustomClaims(t, map[string]any{
		"iss": "not-lurus-platform",
		"sub": "lurus:1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}, secret)

	_, err := verifySessionToken(tok, secret)
	if !errors.Is(err, ErrInvalidSession) {
		t.Errorf("err = %v, want ErrInvalidSession", err)
	}
}

func TestVerifySessionToken_BadSubFormat(t *testing.T) {
	const secret = "test-secret"
	cases := []map[string]any{
		{
			"iss": sessionIssuer,
			"sub": "not-prefixed",
			"exp": time.Now().Add(time.Hour).Unix(),
		},
		{
			"iss": sessionIssuer,
			"sub": "lurus:not-an-int",
			"exp": time.Now().Add(time.Hour).Unix(),
		},
		{
			"iss": sessionIssuer,
			"sub": "lurus:0",
			"exp": time.Now().Add(time.Hour).Unix(),
		},
		{
			"iss": sessionIssuer,
			"sub": "lurus:-5",
			"exp": time.Now().Add(time.Hour).Unix(),
		},
	}
	for i, claims := range cases {
		tok := mintTokenCustomClaims(t, claims, secret)
		_, err := verifySessionToken(tok, secret)
		if !errors.Is(err, ErrInvalidSession) {
			t.Errorf("case %d: err = %v, want ErrInvalidSession", i, err)
		}
	}
}

func TestVerifySessionToken_MissingExp(t *testing.T) {
	const secret = "test-secret"
	tok := mintTokenCustomClaims(t, map[string]any{
		"iss": sessionIssuer,
		"sub": "lurus:1",
		// exp deliberately omitted — defaults to 0
	}, secret)

	_, err := verifySessionToken(tok, secret)
	if !errors.Is(err, ErrInvalidSession) {
		t.Errorf("err = %v, want ErrInvalidSession", err)
	}
}
