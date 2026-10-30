# Configuration

Every setting passes through `goJwt.New(goJwt.Config{...})`; the library reads no environment variables. Key settings are covered in [Key Management](/key-management).

## Config

| Field | Type | JSON tag | Required | Description |
|---|---|---|---|---|
| `Redis` | `Redis` | `redis` | Yes | Redis connection settings |
| `File` | `*File` | `file` | No | PEM key file paths |
| `Option` | `*Option` | `parameter` | No | Token parameters; `nil` applies every default |
| `Cookie` | `*Cookie` | `cookie` | No | Cookie attribute overrides; `nil` keeps the defaults |
| `CheckAuth` | `func(Auth) (bool, error)` | not serialized | No | Called on every refresh; returning `false` or an error rejects the refresh (see [Transparent Refresh](/refresh)) |

The JSON tag of `Option` is `parameter`; use that key when loading the config from JSON.

## Redis

| Field | Type | Description |
|---|---|---|
| `Host` | `string` | Host address |
| `Port` | `int` | Port |
| `Password` | `string` | Password, optional |
| `DB` | `int` | Database index |

`New()` builds a `go-redis` client for `Host:Port` with `Password` and `DB`, then sends `PING`; a failed `PING` makes `New()` return an error.

## Option

| Field | Type | Default | Description |
|---|---|---|---|
| `PrivateKey` | `string` | — | ECDSA private key PEM |
| `PublicKey` | `string` | — | ECDSA public key PEM |
| `AccessTokenExpires` | `time.Duration` | `15 * time.Minute` | Lifetime of the Access Token and its JTI |
| `RefreshIdExpires` | `time.Duration` | `7 * 24 * time.Hour` | Refresh ID lifetime |
| `AccessTokenCookieKey` | `string` | `access_token` | Access Token cookie name |
| `RefreshIdCookieKey` | `string` | `refresh_id` | Refresh ID cookie name; also the JWT claim name holding the Refresh ID |
| `MaxVersion` | `int` | `5` | Maximum re-sign-only refreshes before a full reissue |
| `RefreshTTL` | `float64` | `0.5` | Full reissue once the Refresh ID's remaining TTL drops below `RefreshIdExpires × RefreshTTL` |

Zero or negative values fall back to the defaults. `Verify()` reads the Refresh ID claim under the current `RefreshIdCookieKey` with an unchecked type assertion, so after changing it, a still-valid Access Token issued under the old name panics inside `Verify()` (under `gin.Default()` the recovery middleware answers 500; a plain `net/http` server aborts that request). Change it together with a key rotation, or wait until every Access Token issued under the old name has expired.

## Cookie

| Field | Type | Default |
|---|---|---|
| `Domain` | `*string` | unset (host-only) |
| `Path` | `*string` | `/` |
| `SameSite` | `*http.SameSite` | `http.SameSiteLaxMode` |
| `Secure` | `*bool` | `false` |
| `HttpOnly` | `*bool` | `true` |

Only non-`nil` fields override the defaults; they apply to the `access_token`, `refresh_id`, and `conn.device.id` cookies.

## Full Example

```go
package main

import (
	"log"
	"net/http"
	"time"

	goJwt "github.com/pardnchiu/go-jwt/core"
)

func main() {
	domain := "example.com"
	secure := true
	sameSite := http.SameSiteStrictMode

	auth, err := goJwt.New(goJwt.Config{
		Redis: goJwt.Redis{Host: "redis.internal", Port: 6379, Password: "secret", DB: 1},
		File: &goJwt.File{
			PrivateKeyPath: "/etc/app/keys/private-key.pem",
			PublicKeyPath:  "/etc/app/keys/public-key.pem",
		},
		Option: &goJwt.Option{
			AccessTokenExpires: 10 * time.Minute,
			RefreshIdExpires:   30 * 24 * time.Hour,
			MaxVersion:         10,
			RefreshTTL:         0.3,
		},
		Cookie: &goJwt.Cookie{
			Domain:   &domain,
			Secure:   &secure,
			SameSite: &sameSite,
		},
	})
	if err != nil {
		log.Fatalf("failed to init go-jwt: %v", err)
	}
	defer auth.Close()
}
```

## Logging

`New()` points the package-level `slog` logger to syslog (priority `LOG_INFO|LOG_LOCAL0`, tag `goCron`, JSON format) and falls back to stderr (text format) when syslog is unreachable. Filter syslog by the `goCron` tag to find go-jwt entries.
