package zita

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// SessionCookieName is the canonical browser-cookie key platform-core
// writes the lurus session JWT into. Mirrors handler.SessionCookieName
// in 2l-svc-platform/internal/adapter/handler/session_cookie.go — the
// SDK and the platform MUST agree.
const SessionCookieName = "lurus_session"

// AuthMiddleware returns a gin.HandlerFunc that:
//
//  1. extracts the session token from the `lurus_session` cookie OR an
//     `Authorization: Bearer <token>` header (cookie wins on conflict —
//     browsers reliably attach it; Bearer is the SDK / curl path)
//  2. HMAC-verifies via Client.ValidateSession
//  3. on success, c.Set(zita.ContextKey, *Identity) and c.Next()
//  4. on failure, AbortWithStatusJSON 401 in the platform-canonical
//     envelope: {error, message}
//
// The 401 message intentionally does NOT distinguish "no token" from
// "expired" from "bad sig" — clients shouldn't branch on it and detail
// helps attackers calibrate. (Same reasoning as platform-core's whoami
// handler — see internal/adapter/handler/whoami_handler.go:88.)
func (c *Client) AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token := readSessionToken(ctx)
		if token == "" {
			abortUnauthorized(ctx, "Authentication required")
			return
		}

		id, err := c.ValidateSession(token)
		if err != nil {
			// Don't leak "expired" vs "invalid" to the client — same
			// envelope, same status. Caller-side logging is fine since
			// the upstream consumer's logs don't help an attacker.
			abortUnauthorized(ctx, "Invalid or expired session")
			return
		}

		ctx.Set(ContextKey, id)
		ctx.Next()
	}
}

// readSessionToken extracts the lurus session JWT from the cookie or
// Authorization Bearer header. Mirrors handler.ReadSessionToken in
// platform-core (2l-svc-platform/internal/adapter/handler/session_cookie.go:79).
// Cookie wins on conflict.
func readSessionToken(c *gin.Context) string {
	if cookie, err := c.Cookie(SessionCookieName); err == nil {
		if cookie = strings.TrimSpace(cookie); cookie != "" {
			return cookie
		}
	}
	header := c.GetHeader("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimSpace(header[len("Bearer "):])
	}
	return ""
}

// abortUnauthorized writes the platform-canonical 401 envelope and stops
// the gin chain. {"error": "unauthorized", "message": "<text>"} — matches
// 2l-svc-platform/internal/adapter/handler/respond.go.
func abortUnauthorized(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":   "unauthorized",
		"message": message,
	})
}

// IdentityFromContext retrieves the *Identity AuthMiddleware put into the
// gin context. Returns (nil, false) when the middleware did not run or
// authentication failed — handlers gated by AuthMiddleware can safely use
// MustGet, but this helper is friendlier when a route is OPTIONALLY
// authenticated.
func IdentityFromContext(c *gin.Context) (*Identity, bool) {
	v, ok := c.Get(ContextKey)
	if !ok {
		return nil, false
	}
	id, ok := v.(*Identity)
	return id, ok
}
