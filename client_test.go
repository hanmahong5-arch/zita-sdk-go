package zita

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestNewClient_HappyPath(t *testing.T) {
	cli, err := NewClient(Config{
		PlatformURL:   "https://identity.lurus.cn",
		SessionSecret: "secret",
	})
	if err != nil {
		t.Fatalf("NewClient: unexpected err: %v", err)
	}
	if got := cli.PlatformURL(); got != "https://identity.lurus.cn" {
		t.Errorf("PlatformURL() = %q, want https://identity.lurus.cn", got)
	}
}

func TestNewClient_TrailingSlashStripped(t *testing.T) {
	cli, err := NewClient(Config{
		PlatformURL:   "https://identity.lurus.cn/",
		SessionSecret: "secret",
	})
	if err != nil {
		t.Fatalf("NewClient: unexpected err: %v", err)
	}
	if got := cli.PlatformURL(); got != "https://identity.lurus.cn" {
		t.Errorf("PlatformURL() = %q, want trailing slash stripped", got)
	}
}

func TestNewClient_RejectsEmptyURL(t *testing.T) {
	_, err := NewClient(Config{SessionSecret: "secret"})
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("err = %v, want ErrConfigInvalid", err)
	}
}

func TestNewClient_RejectsBadScheme(t *testing.T) {
	cases := []string{
		"file:///etc/passwd",
		"ftp://example.com",
		"identity.lurus.cn", // no scheme — url.Parse accepts but Scheme=""
		"://no-scheme.com",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			_, err := NewClient(Config{
				PlatformURL:   tc,
				SessionSecret: "secret",
			})
			if !errors.Is(err, ErrConfigInvalid) {
				t.Errorf("err = %v, want ErrConfigInvalid", err)
			}
		})
	}
}

func TestNewClient_RejectsEmptySecret(t *testing.T) {
	_, err := NewClient(Config{PlatformURL: "https://identity.lurus.cn"})
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("err = %v, want ErrConfigInvalid", err)
	}
}

func TestNewClient_CustomHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 99 * time.Second}
	cli, err := NewClient(Config{
		PlatformURL:   "https://identity.lurus.cn",
		SessionSecret: "secret",
		HTTPClient:    custom,
	})
	if err != nil {
		t.Fatalf("NewClient: unexpected err: %v", err)
	}
	if cli.httpClient != custom {
		t.Errorf("httpClient was not the custom one (override broken)")
	}
}

func TestClient_ValidateSession_RoundTrip(t *testing.T) {
	const secret = "test-secret"
	cli, err := NewClient(Config{
		PlatformURL:   "https://identity.lurus.cn",
		SessionSecret: secret,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tok := mintTestToken(t, 4521, time.Hour, secret)

	id, err := cli.ValidateSession(tok)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if id == nil || id.AccountID != 4521 {
		t.Errorf("identity = %+v, want AccountID=4521", id)
	}
}

func TestClient_ValidateSession_Errors(t *testing.T) {
	const secret = "test-secret"
	cli, _ := NewClient(Config{
		PlatformURL:   "https://identity.lurus.cn",
		SessionSecret: secret,
	})

	t.Run("expired", func(t *testing.T) {
		tok := mintTestToken(t, 1, -1*time.Hour, secret)
		_, err := cli.ValidateSession(tok)
		if !errors.Is(err, ErrSessionExpired) {
			t.Errorf("err = %v, want ErrSessionExpired", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		_, err := cli.ValidateSession("not-a-jwt")
		if !errors.Is(err, ErrInvalidSession) {
			t.Errorf("err = %v, want ErrInvalidSession", err)
		}
	})
}
