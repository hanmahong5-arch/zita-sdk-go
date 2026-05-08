package zita

import (
	"net/url"
	"strings"
	"testing"
)

func TestLoginRedirectURL_WithReturnTo(t *testing.T) {
	cli, _ := NewClient(Config{
		PlatformURL:   "https://identity.lurus.cn",
		SessionSecret: "secret",
	})

	got := cli.LoginRedirectURL("https://yourapp.lurus.cn/auth/callback")

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("LoginRedirectURL produced unparseable URL: %q (%v)", got, err)
	}
	if u.Scheme != "https" {
		t.Errorf("Scheme = %q, want https", u.Scheme)
	}
	if u.Host != "identity.lurus.cn" {
		t.Errorf("Host = %q, want identity.lurus.cn", u.Host)
	}
	if u.Path != "/login" {
		t.Errorf("Path = %q, want /login", u.Path)
	}
	rt := u.Query().Get("return_to")
	if rt != "https://yourapp.lurus.cn/auth/callback" {
		t.Errorf("return_to = %q, want full callback URL (URL-decoded)", rt)
	}
}

func TestLoginRedirectURL_EmptyReturnTo(t *testing.T) {
	cli, _ := NewClient(Config{
		PlatformURL:   "https://identity.lurus.cn",
		SessionSecret: "secret",
	})

	got := cli.LoginRedirectURL("")

	if got != "https://identity.lurus.cn/login" {
		t.Errorf("got %q, want plain /login URL with no query", got)
	}
}

func TestLoginRedirectURL_EncodesReservedChars(t *testing.T) {
	cli, _ := NewClient(Config{
		PlatformURL:   "https://identity.lurus.cn",
		SessionSecret: "secret",
	})

	// returnTo with query string + fragment + spaces — all chars that
	// would break the outer URL if not encoded.
	tricky := "https://app.lurus.cn/cb?ref=foo bar&x=1#section"
	got := cli.LoginRedirectURL(tricky)

	// The outer URL must still parse cleanly.
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("encoded URL is malformed: %q (%v)", got, err)
	}

	// And the decoded return_to round-trips to the original.
	gotReturn := u.Query().Get("return_to")
	if gotReturn != tricky {
		t.Errorf("round-trip lost data: got %q, want %q", gotReturn, tricky)
	}

	// Sanity: the raw URL must NOT contain a literal space or `#` outside the
	// encoded value (would cause browsers to truncate at the unencoded `#`).
	if strings.Contains(got[strings.Index(got, "?"):], "#") {
		t.Errorf("found literal # in query string: %q", got)
	}
}
