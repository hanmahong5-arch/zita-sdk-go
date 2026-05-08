package zita

import "errors"

// Sentinel errors returned by the SDK. Wrap with %w when adding context so
// callers can use errors.Is() to branch on the root cause.
//
// We keep this list small and stable: every entry maps to a 4xx HTTP class
// the consumer is expected to surface to the end user (or in middleware,
// to a 401). Subdividing further would push branching complexity into
// every caller for no benefit — the SDK has one thing to say: "this
// session is not usable, ask the user to log in again".
var (
	// ErrConfigInvalid is returned by NewClient when Config is missing a
	// required field or has an unparseable value. Fail-fast: consumers
	// should panic at boot rather than ship with a half-working SDK.
	ErrConfigInvalid = errors.New("zita: invalid config")

	// ErrInvalidSession covers any reason the session token is not
	// trustworthy: missing, malformed, signature mismatch, wrong issuer,
	// bad sub format. We deliberately do NOT distinguish these to avoid
	// helping attackers calibrate (matching platform-core's whoami
	// handler — see internal/adapter/handler/whoami_handler.go:88).
	ErrInvalidSession = errors.New("zita: invalid session")

	// ErrSessionExpired is split out from ErrInvalidSession because
	// consumers DO want to branch on it: the right UX for an expired
	// session is "redirect to login" (LoginRedirectURL), whereas for an
	// otherwise-invalid session it's "log a warning, force logout".
	ErrSessionExpired = errors.New("zita: session expired")
)
