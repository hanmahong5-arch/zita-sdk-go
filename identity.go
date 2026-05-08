package zita

// Identity is the resolved Lurus account on a session-validated request.
//
// MVP contract (v0.1.x): AccountID is always populated. Email / DisplayName /
// Phone / OrgID are reserved for the v0.2.x Whoami() addition; the HMAC fast
// path that ValidateSession uses today only carries the account id in the
// JWT `sub` claim, so populating other fields would require an extra
// network round-trip the consumer didn't ask for.
//
// New fields are additive — never remove or rename across versions.
type Identity struct {
	// AccountID is the lurus-platform account.id (BIGSERIAL primary key).
	// Always > 0 on a successful ValidateSession.
	AccountID int64 `json:"account_id"`

	// LurusID is the public-facing stable user identifier (e.g. "lurus_a1b2c3").
	// Reserved — not populated by ValidateSession's HMAC fast path.
	LurusID string `json:"lurus_id,omitempty"`

	// Email is the account's primary email. Reserved — see LurusID.
	Email string `json:"email,omitempty"`

	// DisplayName is what to render in UIs. Reserved — see LurusID.
	DisplayName string `json:"display_name,omitempty"`

	// Phone is the masked phone number (e.g. "+86138****2222"). Reserved.
	Phone string `json:"phone,omitempty"`

	// OrgID, when non-nil, scopes the session to a specific organization.
	// Reserved — multi-tenant org context lands with /api/v1/account/me/orgs.
	OrgID *int64 `json:"org_id,omitempty"`
}

// ContextKey is the gin context key under which AuthMiddleware stuffs the
// resolved *Identity. Consumers read it via:
//
//	id := c.MustGet(zita.ContextKey).(*zita.Identity)
//
// Exported as a typed constant rather than a magic string so renames are
// caught at compile time on consumer upgrades.
const ContextKey = "lurus.identity"
