# zita-sdk-go

Lurus identity SDK for Go — drop-in OIDC redirect, session validation, and
gin AuthMiddleware backed by `identity.lurus.cn` (the platform-core service
implementing `zita.IdentityProvider`).

> Status: **v0.1.x — pre-alpha**. API not stable. Pin to a commit SHA via
> `replace` in your go.mod. See [ADR-0011] for the design contract.
>
> [ADR-0011]: https://github.com/hanmahong5-arch/lurus/blob/main/doc/decisions/0011-zita-sdk-go-mvp.md

## What it does

Without this SDK every Lurus consumer (lucrum / lutu / admin / switch /
newhub) hand-writes the same code: build a redirect URL to
`identity.lurus.cn`, parse the returned cookie, HMAC-verify the session
token, fetch `/whoami`, surface `401` on bad sessions. ~700 LOC each, and
the first time the platform changes its session shape every consumer
breaks.

This SDK collapses that into three calls:

```go
import "github.com/hanmahong5-arch/zita-sdk-go"

cli, err := zita.NewClient(zita.Config{
    PlatformURL:   "https://identity.lurus.cn",
    SessionSecret: os.Getenv("IDENTITY_SESSION_SECRET"),
})
if err != nil { /* fail-fast */ }

// 1. Login redirect (browser -> identity.lurus.cn)
//    Drop this URL into your "Login" button.
url := cli.LoginRedirectURL("https://yourapp.lurus.cn/auth/callback")

// 2. Validate the session cookie that came back
//    (cookie name: `lurus_session`, parent-domain *.lurus.cn)
identity, err := cli.ValidateSession(cookieValue)

// 3. gin middleware that does (2) per-request
r := gin.New()
r.Use(cli.AuthMiddleware())
r.GET("/me", func(c *gin.Context) {
    id := c.MustGet("lurus.identity").(*zita.Identity)
    c.JSON(200, id)
})
```

That's the entire MVP. **Whoami / Refresh / Logout** are intentionally
omitted — they will be added when a real consumer needs them, not before.

## Versioning

| Range  | Stability     | Recommended pin           |
|--------|---------------|---------------------------|
| v0.1.x | API in flux   | `replace ... => ...@<sha>` |
| v0.2.x | First stable  | `~> v0.2.0`               |
| v1.0.0 | All consumers migrated; SemVer enforced | `~> v1`        |

## Dependency contract

`SessionSecret` MUST equal `platform-core`'s `SessionSecret` (the HMAC key
the platform uses to sign session tokens). The SDK does **not** mint
tokens — it only verifies the ones the platform sent. Distribution is
out-of-band (K8s Secret synced by ops); the SDK never fetches it from a
network service.

Rotation: when the platform rotates `SessionSecret`, consumers must
update their env in lockstep. The platform's
`credential_rotation_worker` provides a `_NEXT` grace window for
rolling updates — consumers that need this window can supply a
secondary `SessionSecretNext` field on `Config` (added when first
rotation drill consumer needs it).

## Testing

The SDK is verified against the **live STAGE** platform (R6,
`identity.lurus.cn`) on every CI run. There is **no mock platform** —
the SDK's whole value is "talks to platform correctly", and a mock would
just test itself.

CI workflow lives at `.github/workflows/ci.yaml` (added at v0.1.0).
Joins the Tailnet via `tailscale/github-action`, runs `go test ./...`
including the e2e suite gated on `PLATFORM_STAGE_REACHABLE=1`.

## License

MIT — see [LICENSE](LICENSE).
