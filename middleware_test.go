package zita

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	// Quiet gin's default chatter during tests. Doesn't affect production
	// since this init only runs in the _test binary.
	gin.SetMode(gin.TestMode)
}

// newTestClientAndRouter returns a Client + a gin.Engine with a single
// /me route gated by AuthMiddleware. The handler echoes the resolved
// identity as JSON so tests can assert on the AccountID.
func newTestClientAndRouter(t *testing.T) (*Client, *gin.Engine, string) {
	t.Helper()
	const secret = "middleware-test-secret"
	cli, err := NewClient(Config{
		PlatformURL:   "https://identity.lurus.cn",
		SessionSecret: secret,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	r := gin.New()
	r.Use(cli.AuthMiddleware())
	r.GET("/me", func(c *gin.Context) {
		id := c.MustGet(ContextKey).(*Identity)
		c.JSON(http.StatusOK, id)
	})
	return cli, r, secret
}

func TestAuthMiddleware_ValidCookie(t *testing.T) {
	_, r, secret := newTestClientAndRouter(t)
	tok := mintTestToken(t, 4521, time.Hour, secret)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var id Identity
	if err := json.Unmarshal(w.Body.Bytes(), &id); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, w.Body.String())
	}
	if id.AccountID != 4521 {
		t.Errorf("AccountID = %d, want 4521", id.AccountID)
	}
}

func TestAuthMiddleware_ValidBearer(t *testing.T) {
	_, r, secret := newTestClientAndRouter(t)
	tok := mintTestToken(t, 99, time.Hour, secret)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	var id Identity
	_ = json.Unmarshal(w.Body.Bytes(), &id)
	if id.AccountID != 99 {
		t.Errorf("AccountID = %d, want 99", id.AccountID)
	}
}

func TestAuthMiddleware_MissingToken(t *testing.T) {
	_, r, _ := newTestClientAndRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "unauthorized" {
		t.Errorf("error = %q, want %q", body["error"], "unauthorized")
	}
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	_, r, secret := newTestClientAndRouter(t)
	tok := mintTestToken(t, 1, -1*time.Hour, secret)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestAuthMiddleware_BadSignature(t *testing.T) {
	_, r, _ := newTestClientAndRouter(t)
	// Mint with a different secret — middleware's secret won't verify.
	tok := mintTestToken(t, 1, time.Hour, "different-secret")

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestAuthMiddleware_CookieWinsOverBearer(t *testing.T) {
	_, r, secret := newTestClientAndRouter(t)
	cookieTok := mintTestToken(t, 100, time.Hour, secret)
	bearerTok := mintTestToken(t, 200, time.Hour, secret)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookieTok})
	req.Header.Set("Authorization", "Bearer "+bearerTok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	var id Identity
	_ = json.Unmarshal(w.Body.Bytes(), &id)
	if id.AccountID != 100 {
		t.Errorf("AccountID = %d, want 100 (cookie value, not bearer)", id.AccountID)
	}
}

func TestIdentityFromContext_NotSet(t *testing.T) {
	r := gin.New()
	r.GET("/x", func(c *gin.Context) {
		_, ok := IdentityFromContext(c)
		if ok {
			c.JSON(500, gin.H{"err": "should not have identity"})
			return
		}
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
}
