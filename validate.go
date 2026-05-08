package zita

// ValidateSession HMAC-verifies a session cookie value (or Bearer token —
// they share the same JWT shape) and returns the resolved Identity.
//
// MVP fast path: HMAC-only, no network. Only Identity.AccountID is
// populated — the JWT's sub claim doesn't carry email / display_name. A
// future Whoami() addition will GET /api/v1/whoami to fill in the rest;
// for now consumers that need those fields call platform-core directly.
//
// Errors:
//   - ErrSessionExpired (use errors.Is to branch — UX is "redirect to
//     login")
//   - ErrInvalidSession (everything else — malformed, signature mismatch,
//     wrong issuer, bad sub format; UX is "force logout")
func (c *Client) ValidateSession(token string) (*Identity, error) {
	accountID, err := verifySessionToken(token, c.sessionSecret)
	if err != nil {
		return nil, err
	}
	return &Identity{AccountID: accountID}, nil
}
