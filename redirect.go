package zita

import "net/url"

// LoginRedirectURL returns the URL the browser should be sent to when the
// consumer wants to start a Lurus login flow. Drop the result into a
// "Login" button's href — when the user finishes authenticating at
// identity.lurus.cn, they are bounced back to returnTo with the
// lurus_session cookie set on the parent domain.
//
// returnTo is the consumer's own callback URL (e.g.
// "https://yourapp.lurus.cn/auth/callback"). It is URL-encoded into the
// `return_to` query parameter. Empty returnTo is allowed and produces a
// URL without the `return_to` parameter — the platform will use its own
// default landing page (typically the user's lurus profile).
//
// The shape of the produced URL is intentionally NOT
// `auth.lurus.cn/oauth/v2/authorize?...` — that's an OIDC
// implementation detail inside platform-core. Consumers go through
// identity.lurus.cn so the platform can swap auth providers without
// breaking every consumer's hardcoded OIDC URL.
func (c *Client) LoginRedirectURL(returnTo string) string {
	if returnTo == "" {
		return c.platformURL + "/login"
	}
	q := url.Values{}
	q.Set("return_to", returnTo)
	return c.platformURL + "/login?" + q.Encode()
}
