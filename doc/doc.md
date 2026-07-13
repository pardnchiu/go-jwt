# go-jwt - Documentation

> Back to [README](../README.md)

## Prerequisites

- Go 1.24 or higher
- Redis server

## Installation

### Using go get

```bash
go get github.com/pardnchiu/go-jwt
```

### From Source

```bash
git clone https://github.com/pardnchiu/go-jwt.git
cd go-jwt
go build ./...
```

## Configuration

### Config Structure

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `Redis` | `Redis` | Yes | Redis connection settings |
| `File` | `*File` | No | PEM key file paths |
| `Option` | `*Option` | No | Token parameter tuning |
| `Cookie` | `*Cookie` | No | Cookie attribute settings |
| `CheckAuth` | `func(Auth) (bool, error)` | No | Custom user validation callback |

### Redis Settings

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `Host` | `string` | Yes | Redis host address |
| `Port` | `int` | Yes | Redis port |
| `Password` | `string` | No | Redis password |
| `DB` | `int` | Yes | Redis database number |

### Option Defaults

| Field | Default | Description |
|-------|---------|-------------|
| `AccessTokenExpires` | `15m` | Access Token expiration |
| `RefreshIdExpires` | `7d` | Refresh ID expiration |
| `AccessTokenCookieKey` | `access_token` | Access Token cookie key |
| `RefreshIdCookieKey` | `refresh_id` | Refresh ID cookie key |
| `MaxVersion` | `5` | Refresh count before Refresh ID rebuild |
| `RefreshTTL` | `0.5` | TTL ratio threshold for Refresh ID rebuild |

### Cookie Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Domain` | `*string` | None | Cookie domain |
| `Path` | `*string` | `/` | Cookie path |
| `SameSite` | `*http.SameSite` | `Lax` | SameSite attribute |
| `Secure` | `*bool` | `false` | HTTPS only |
| `HttpOnly` | `*bool` | `true` | HttpOnly flag |

### PEM Keys

Three configuration methods are supported, in priority order:

1. `File.PrivateKeyPath` / `File.PublicKeyPath` — specify file paths
2. `Option.PrivateKey` / `Option.PublicKey` — provide PEM text directly
3. Auto-detect `./keys/private-key.pem` and `./keys/public-key.pem`; generates a new ECDSA P-256 key pair if not found

## Usage

### Basic

```go
package main

import (
	"log"
	"net/http"

	"github.com/pardnchiu/go-jwt/core"
)

func main() {
	jwtAuth, err := goJwt.New(goJwt.Config{
		Redis: goJwt.Redis{
			Host: "localhost",
			Port: 6379,
			DB:   0,
		},
	})
	if err != nil {
		log.Fatalf("init failed: %v", err)
	}
	defer jwtAuth.Close()

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		result := jwtAuth.Create(w, r, &goJwt.Auth{
			ID:    "user-1",
			Name:  "Alice",
			Email: "alice@example.com",
			Role:  "admin",
		})
		if !result.Success {
			http.Error(w, result.Error, result.StatusCode)
			return
		}
		w.WriteHeader(result.StatusCode)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Advanced

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pardnchiu/go-jwt/core"
)

func main() {
	secure := true
	jwtAuth, err := goJwt.New(goJwt.Config{
		Redis: goJwt.Redis{
			Host:     "localhost",
			Port:     6379,
			Password: "secret",
			DB:       1,
		},
		Option: &goJwt.Option{
			AccessTokenExpires: 10 * time.Minute,
			RefreshIdExpires:   14 * 24 * time.Hour,
			MaxVersion:         3,
			RefreshTTL:         0.4,
		},
		Cookie: &goJwt.Cookie{
			Secure: &secure,
		},
		CheckAuth: func(auth goJwt.Auth) (bool, error) {
			// return false when the user no longer exists
			return auth.ID != "", nil
		},
	})
	if err != nil {
		log.Fatalf("init failed: %v", err)
	}
	defer jwtAuth.Close()

	r := gin.Default()
	r.POST("/login", func(c *gin.Context) {
		result := jwtAuth.Create(c.Writer, c.Request, &goJwt.Auth{
			ID:    "user-1",
			Name:  "Alice",
			Email: "alice@example.com",
			Scope: []string{"read", "write"},
		})
		if !result.Success {
			c.JSON(result.StatusCode, gin.H{"error": result.Error})
			return
		}
		c.JSON(result.StatusCode, gin.H{
			"token":      result.Token.Token,
			"refresh_id": result.Token.RefreshId,
		})
	})

	auth := r.Group("/")
	auth.Use(jwtAuth.GinMiddleware())
	auth.GET("/me", func(c *gin.Context) {
		user, ok := goJwt.GetAuthDataFromGinContext(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusOK, user)
	})
	auth.POST("/logout", func(c *gin.Context) {
		result := jwtAuth.Revoke(c.Writer, c.Request)
		c.JSON(result.StatusCode, gin.H{"success": result.Success, "error": result.Error})
	})

	log.Fatal(r.Run(":8080"))
}
```

## API Reference

### New

```go
func New(c Config) (*JWTAuth, error)
```

Creates a JWTAuth instance, connects Redis, and loads or generates ECDSA keys.

### Close

```go
func (j *JWTAuth) Close() error
```

Closes the Redis connection.

### Create

```go
func (j *JWTAuth) Create(w http.ResponseWriter, r *http.Request, auth *Auth) JWTAuthResult
```

Issues Access Token and Refresh ID, sets cookies, and stores refresh state plus JTI in Redis.

### Verify

```go
func (j *JWTAuth) Verify(w http.ResponseWriter, r *http.Request) JWTAuthResult
```

Verifies the Access Token, checks revocation and device fingerprint, and refreshes transparently when expired.

### Revoke

```go
func (j *JWTAuth) Revoke(w http.ResponseWriter, r *http.Request) JWTAuthResult
```

Revokes the current session: clears cookies, shortens Refresh ID TTL, and marks the Access Token as revoked.

### GinMiddleware

```go
func (j *JWTAuth) GinMiddleware() gin.HandlerFunc
```

Gin middleware that runs Verify and stores `*Auth` under the `user` context key.

### HTTPMiddleware

```go
func (j *JWTAuth) HTTPMiddleware(next http.Handler) http.Handler
```

Standard library middleware that runs Verify and stores `*Auth` in `request.Context`.

### GetAuthDataFromGinContext

```go
func GetAuthDataFromGinContext(c *gin.Context) (*Auth, bool)
```

Reads authenticated user data from a Gin context.

### GetAuthDataFromHTTPRequest

```go
func GetAuthDataFromHTTPRequest(r *http.Request) (*Auth, bool)
```

Reads authenticated user data from an `http.Request` context.

### Auth

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | User ID |
| `Name` | `string` | Display name |
| `Email` | `string` | Email |
| `Thumbnail` | `string` | Avatar URL |
| `Scope` | `[]string` | Permission scopes |
| `Role` | `string` | Role |
| `Level` | `int` | Level |

### JWTAuthResult

| Field | Type | Description |
|-------|------|-------------|
| `StatusCode` | `int` | HTTP status code |
| `Success` | `bool` | Whether the operation succeeded |
| `Data` | `*Auth` | Authenticated user data |
| `Token` | `*TokenResult` | Issued token pair |
| `Error` | `string` | Error message |
| `ErrorTag` | `string` | Machine-readable error tag |

### Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| `Authorization: Bearer <token>` | Request | Access Token (cookie alternative) |
| `X-Refresh-ID` | Request | Refresh ID (cookie alternative) |
| `X-Device-FP` | Request | Override device fingerprint |
| `X-Device-ID` | Request | Stable device ID |
| `X-New-Access-Token` | Response | New Access Token after refresh |
| `X-New-Refresh-ID` | Response | New Refresh ID after full rebuild |

***

©️ 2025 [邱敬幃 Pardn Chiu](https://www.linkedin.com/in/pardnchiu)
