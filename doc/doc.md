# go-jwt - Documentation

Last updated: 2026-10-04

> Back to [README](../README.md)

## Prerequisites

- Go 1.24 or higher
- Redis server (connected through `github.com/redis/go-redis/v9`)
- `github.com/gin-gonic/gin` when using `GinMiddleware()`

## Installation

### Using go get

```bash
go get github.com/pardnchiu/go-jwt@latest
```

The package lives under the `core/` subdirectory and its package name is `goJwt`:

```go
import goJwt "github.com/pardnchiu/go-jwt/core"
```

### From Source

```bash
git clone https://github.com/pardnchiu/go-jwt.git
cd go-jwt
go build ./...
```

### Running Tests

Tests require a reachable Redis at `localhost:6379`:

```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
go test -race ./...
```

## Configuration

All settings pass through `goJwt.New(goJwt.Config{...})`; the library reads no environment variables.

### Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `Redis` | `Redis` | Yes | Redis connection settings |
| `File` | `*File` | No | PEM key file paths |
| `Option` | `*Option` | No | Token parameters; `nil` applies every default |
| `Cookie` | `*Cookie` | No | Cookie attribute overrides; `nil` keeps the defaults |
| `CheckAuth` | `func(Auth) (bool, error)` | No | Called on every refresh to confirm the user is still valid; returning `false` or an error rejects the refresh |

### Redis

| Field | Type | Description |
|-------|------|-------------|
| `Host` | `string` | Host address |
| `Port` | `int` | Port |
| `Password` | `string` | Password (optional) |
| `DB` | `int` | Database index |

`New()` sends a `PING` first and returns an error when the connection fails.

### Option

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `PrivateKey` | `string` | — | ECDSA private key PEM (PKCS#8) |
| `PublicKey` | `string` | — | ECDSA public key PEM (PKIX) |
| `AccessTokenExpires` | `time.Duration` | `15 * time.Minute` | Access Token lifetime |
| `RefreshIdExpires` | `time.Duration` | `7 * 24 * time.Hour` | Refresh ID lifetime |
| `AccessTokenCookieKey` | `string` | `access_token` | Access Token cookie name |
| `RefreshIdCookieKey` | `string` | `refresh_id` | Refresh ID cookie name; also the JWT claim name holding the Refresh ID |
| `MaxVersion` | `int` | `5` | Reissue the full token pair once the refresh count exceeds this value |
| `RefreshTTL` | `float64` | `0.5` | Reissue the full token pair once the Refresh ID's remaining TTL drops below `RefreshIdExpires × RefreshTTL` |

Zero or negative values fall back to the defaults.

### Cookie

| Field | Type | Default |
|-------|------|---------|
| `Domain` | `*string` | unset |
| `Path` | `*string` | `/` |
| `SameSite` | `*http.SameSite` | `http.SameSiteLaxMode` |
| `Secure` | `*bool` | `false` |
| `HttpOnly` | `*bool` | `true` |

Only non-`nil` fields override the defaults. Set `Secure: true` in production behind HTTPS.

### Key Loading Order

| Priority | Condition | Behavior |
|----------|-----------|----------|
| 1 | `File.PrivateKeyPath` / `File.PublicKeyPath` set | Read the files and overwrite `Option.PrivateKey` / `Option.PublicKey`; a read failure returns an error |
| 2 | Both `Option.PrivateKey` and `Option.PublicKey` set | Use them directly |
| 3 | Both empty and `./keys/private-key.pem`, `./keys/public-key.pem` exist | Read the existing files |
| 4 | Both empty and those files are absent | Generate a P-256 key pair into `./keys/` (private `0600`, public `0644`) |
| — | Only one key provided | Return an error |

After loading, both keys must be ECDSA and form a matching pair. Multi-instance deployments must share one key pair; keys auto-generated per instance do not accept each other's tokens.

### Request Inputs

| Source | Name | Purpose |
|--------|------|---------|
| Cookie | `access_token` (configurable) | Access Token; takes precedence over the Authorization header |
| Header | `Authorization: Bearer <token>` | Access Token when no cookie is present |
| Header | `X-Refresh-ID` | Refresh ID; takes precedence over the cookie |
| Cookie | `refresh_id` (configurable) | Refresh ID |
| Header | `X-Device-FP` | Supplies the device fingerprint directly, skipping User-Agent derivation |
| Header | `X-Device-ID` | Device ID; takes precedence over the cookie |
| Cookie | `conn.device.id` | Device ID; when missing, a UUID is generated and stored in a 90-day cookie |

### Response Outputs

| Location | Name | When |
|----------|------|------|
| Set-Cookie | Access Token / Refresh ID | `Create()` and full reissue |
| Set-Cookie | Access Token | Access-Token-only re-sign |
| Header | `X-New-Access-Token` | Access-Token-only re-sign |
| Set-Cookie | `conn.device.id` | Every fingerprint computation without `X-Device-FP` |

## Usage

### Basic: net/http Login, Protected Route, Logout

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"

	goJwt "github.com/pardnchiu/go-jwt/core"
)

func main() {
	auth, err := goJwt.New(goJwt.Config{
		Redis: goJwt.Redis{Host: "localhost", Port: 6379},
	})
	if err != nil {
		log.Fatalf("failed to init go-jwt: %v", err)
	}
	defer auth.Close()

	mux := http.NewServeMux()

	// Login: issue Access Token and Refresh ID (also written to cookies)
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		result := auth.Create(w, r, &goJwt.Auth{
			ID:    "u_001",
			Name:  "Pardn",
			Email: "dev@example.com",
			Role:  "admin",
			Scope: []string{"read", "write"},
		})
		if !result.Success {
			http.Error(w, result.Error, result.StatusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result.Token)
	})

	// Protected route: the middleware responds with a JSON error on failure
	mux.Handle("GET /me", auth.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := goJwt.GetAuthDataFromHTTPRequest(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	})))

	// Logout: revoke the Access Token and clear cookies
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		result := auth.Revoke(w, r)
		if !result.Success {
			http.Error(w, result.Error, result.StatusCode)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

### Gin Middleware

```go
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	goJwt "github.com/pardnchiu/go-jwt/core"
)

func main() {
	auth, err := goJwt.New(goJwt.Config{
		Redis: goJwt.Redis{Host: "localhost", Port: 6379},
	})
	if err != nil {
		log.Fatalf("failed to init go-jwt: %v", err)
	}
	defer auth.Close()

	r := gin.Default()

	r.POST("/login", func(c *gin.Context) {
		result := auth.Create(c.Writer, c.Request, &goJwt.Auth{ID: "u_001", Name: "Pardn"})
		if !result.Success {
			c.JSON(result.StatusCode, gin.H{"error": result.Error, "tag": result.ErrorTag})
			return
		}
		c.JSON(http.StatusOK, result.Token)
	})

	api := r.Group("/api", auth.GinMiddleware())
	api.GET("/me", func(c *gin.Context) {
		user, ok := goJwt.GetAuthDataFromGinContext(c)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.JSON(http.StatusOK, user)
	})

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
```

### Advanced: Custom Options, Cookies, and User Check

```go
package main

import (
	"errors"
	"log"
	"net/http"
	"time"

	goJwt "github.com/pardnchiu/go-jwt/core"
)

var errUserBanned = errors.New("user banned")

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
		// Confirm on every refresh that the user still exists and is not banned
		CheckAuth: func(a goJwt.Auth) (bool, error) {
			if a.ID == "u_banned" {
				return false, errUserBanned
			}
			return true, nil
		},
	})
	if err != nil {
		log.Fatalf("failed to init go-jwt: %v", err)
	}
	defer auth.Close()
}
```

### Non-Browser Clients (API / Mobile App)

Without cookies, a User-Agent that matches no known OS or browser yields a different fingerprint on every request, so non-browser clients must send a stable `X-Device-FP`:

```bash
# Login
curl -X POST http://localhost:8080/login \
  -H "X-Device-FP: device-7f3a9c"

# Access with Access Token and Refresh ID
curl http://localhost:8080/me \
  -H "X-Device-FP: device-7f3a9c" \
  -H "Authorization: Bearer <token>" \
  -H "X-Refresh-ID: <refresh_id>" \
  -D -
```

When an expired Access Token is only re-signed, the new token arrives in the `X-New-Access-Token` header; a full reissue delivers new tokens through `Set-Cookie` only.

## API Reference

### Functions and Methods

| Signature | Description |
|-----------|-------------|
| `func New(c Config) (*JWTAuth, error)` | Applies defaults, loads or generates keys, connects to Redis, and returns an instance |
| `func (j *JWTAuth) Close() error` | Closes the Redis connection |
| `func (j *JWTAuth) Create(w http.ResponseWriter, r *http.Request, auth *Auth) JWTAuthResult` | Issues an Access Token and Refresh ID, writing cookies and Redis records |
| `func (j *JWTAuth) Verify(w http.ResponseWriter, r *http.Request) JWTAuthResult` | Verifies the Access Token; refreshes from the Refresh ID when it is expired or missing |
| `func (j *JWTAuth) Revoke(w http.ResponseWriter, r *http.Request) JWTAuthResult` | Clears cookies, revokes the Access Token, and expires the Refresh ID after 5 seconds |
| `func (j *JWTAuth) GinMiddleware() gin.HandlerFunc` | Gin middleware; on success passes `*Auth` via `c.Set("user", ...)` |
| `func (j *JWTAuth) HTTPMiddleware(next http.Handler) http.Handler` | net/http middleware; on success stores `*Auth` in the request context |
| `func GetAuthDataFromGinContext(c *gin.Context) (*Auth, bool)` | Reads user data from the Gin context |
| `func GetAuthDataFromHTTPRequest(r *http.Request) (*Auth, bool)` | Reads user data from the request context |

On verification failure, both middlewares respond with `result.StatusCode` and `{"error": "<message>"}`, then stop the chain.

### Types

```go
type Auth struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Email     string   `json:"email"`
	Thumbnail string   `json:"thumbnail,omitempty"`
	Scope     []string `json:"scope,omitempty"`
	Role      string   `json:"role,omitempty"`
	Level     int      `json:"level,omitempty"`
}

type JWTAuthResult struct {
	StatusCode int          `json:"status_code"`
	Success    bool         `json:"success"`
	Data       *Auth        `json:"data,omitempty"`
	Token      *TokenResult `json:"token,omitempty"`
	Error      string       `json:"error,omitempty"`
	ErrorTag   string       `json:"error_tag,omitempty"`
}

type TokenResult struct {
	Token     string `json:"token"`
	RefreshId string `json:"refresh_id"`
}

type RefreshData struct {
	Data        *Auth  `json:"data,omitempty"`
	Version     int    `json:"version"`
	Fingerprint string `json:"fp"`
	Exp         int64  `json:"exp"`
	Iat         int64  `json:"iat"`
	Jti         string `json:"jti"`
}
```

Every `Auth` field is written into the JWT claims; keep sensitive data out of it.

`RefreshId` (the input hashed into the Refresh ID: `ID`, `Name`, `Email`, `Fingerprint`, `Iat`, `Jti`) and `Pem` (the parsed ECDSA key pair, with unexported fields) are also exported; callers do not need them directly.

### Status Codes and Error Tags

| StatusCode | ErrorTag | Trigger |
|------------|----------|---------|
| `400` | `data_missing` | `Create()` without `Auth`; `Revoke()` without a Refresh ID |
| `400` | `data_invalid` | Access Token signature, `nbf`/`iat`, Refresh ID, fingerprint, or JTI check failed |
| `401` | `unauthorized` | Not logged in; Refresh ID invalid, expired, or fingerprint mismatch; `Revoke()` cannot find the Refresh ID |
| `401` | `revoked` | Access Token has been revoked |
| `401` | (empty) | `CheckAuth` returned `false` or an error |
| `429` | `failed_to_update` | Another request is refreshing the same Refresh ID |
| `500` | `failed_to_create` | Refresh ID or refresh data serialization failed |
| `500` | `failed_to_sign` | JWT signing failed |
| `500` | `failed_to_store` | Redis write failed |
| `500` | `failed_to_get` | Redis read failed |

### Redis Keys

| Key | Value | TTL |
|-----|-------|-----|
| `refresh:<refreshID>` | `RefreshData` JSON | `RefreshIdExpires`; refreshes keep the remaining TTL |
| `jti:<jti>` | `"1"` | `AccessTokenExpires` |
| `lock:refresh:<refreshID>` | Lock holder UUID | 3 seconds |
| `revoke:<accessToken>` | `"1"` | `AccessTokenExpires` |

### Logging

`New()` points the package-level logger to syslog (`LOG_LOCAL0`, JSON format) and falls back to stderr text output when syslog is unavailable.

***

©️ 2025 [邱敬幃 Pardn Chiu](https://www.linkedin.com/in/pardnchiu)
