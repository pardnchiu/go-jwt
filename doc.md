# go-jwt - Documentation

> Back to [README](./README.md)

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
| `CheckAuth` | `func(Auth) (bool, error)` | No | Custom user validation function |

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

### Basic Initialization

```go
package main

import (
    "fmt"
    "log"

    goJwt "github.com/pardnchiu/go-jwt"
)

func main() {
    jwt, err := goJwt.New(goJwt.Config{
        Redis: goJwt.Redis{
            Host: "localhost",
            Port: 6379,
            DB:   0,
        },
    })
    if err != nil {
        log.Fatalf("initialization failed: %v", err)
    }
    defer jwt.Close()

    fmt.Println("JWT auth service started")
}
```

### With Gin

```go
package main

import (
    "net/http"

    "github.com/gin-gonic/gin"
    goJwt "github.com/pardnchiu/go-jwt"
)

func main() {
    jwt, err := goJwt.New(goJwt.Config{
        Redis: goJwt.Redis{
            Host: "localhost",
            Port: 6379,
            DB:   0,
        },
        CheckAuth: func(auth goJwt.Auth) (bool, error) {
            // Custom user validation logic
            return auth.ID != "", nil
        },
    })
    if err != nil {
        panic(err)
    }
    defer jwt.Close()

    r := gin.Default()

    // Login endpoint
    r.POST("/login", func(c *gin.Context) {
        result := jwt.Create(c.Writer, c.Request, &goJwt.Auth{
            ID:    "user-001",
            Name:  "Alice",
            Email: "alice@example.com",
            Role:  "admin",
        })
        c.JSON(result.StatusCode, result)
    })

    // Protected route group
    protected := r.Group("/api", jwt.GinMiddleware())
    protected.GET("/profile", func(c *gin.Context) {
        user, ok := goJwt.GetAuthDataFromGinContext(c)
        if !ok {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
            return
        }
        c.JSON(http.StatusOK, user)
    })

    // Logout endpoint
    r.POST("/logout", jwt.GinMiddleware(), func(c *gin.Context) {
        result := jwt.Revoke(c.Writer, c.Request)
        c.JSON(result.StatusCode, result)
    })

    r.Run(":8080")
}
```

### With Standard net/http

```go
package main

import (
    "encoding/json"
    "net/http"

    goJwt "github.com/pardnchiu/go-jwt"
)

func main() {
    jwt, err := goJwt.New(goJwt.Config{
        Redis: goJwt.Redis{
            Host: "localhost",
            Port: 6379,
            DB:   0,
        },
    })
    if err != nil {
        panic(err)
    }
    defer jwt.Close()

    mux := http.NewServeMux()

    // Login endpoint
    mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        result := jwt.Create(w, r, &goJwt.Auth{
            ID:    "user-001",
            Name:  "Alice",
            Email: "alice@example.com",
        })
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(result.StatusCode)
        json.NewEncoder(w).Encode(result)
    })

    // Protected endpoint
    profileHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user, ok := goJwt.GetAuthDataFromHTTPRequest(r)
        if !ok {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(user)
    })
    mux.Handle("/api/profile", jwt.HTTPMiddleware(profileHandler))

    http.ListenAndServe(":8080", mux)
}
```

### Custom Token Parameters

```go
import "time"

jwt, err := goJwt.New(goJwt.Config{
    Redis: goJwt.Redis{
        Host: "localhost",
        Port: 6379,
        DB:   0,
    },
    Option: &goJwt.Option{
        AccessTokenExpires:   30 * time.Minute,
        RefreshIdExpires:     14 * 24 * time.Hour,
        AccessTokenCookieKey: "token",
        RefreshIdCookieKey:   "rid",
        MaxVersion:           10,
        RefreshTTL:           0.3,
    },
    Cookie: &goJwt.Cookie{
        Domain:   strPtr("example.com"),
        Secure:   boolPtr(true),
        SameSite: sameSitePtr(http.SameSiteStrictMode),
    },
})
```

## API Reference

### New

```go
func New(c Config) (*JWTAuth, error)
```

Create and initialize a JWTAuth instance. Validates config, loads or generates ECDSA keys, and establishes the Redis connection.

### JWTAuth.Create

```go
func (j *JWTAuth) Create(w http.ResponseWriter, r *http.Request, auth *Auth) JWTAuthResult
```

Create a new Access Token and Refresh ID, set cookies, and store Refresh Data in Redis.

### JWTAuth.Verify

```go
func (j *JWTAuth) Verify(w http.ResponseWriter, r *http.Request) JWTAuthResult
```

Verify Access Token validity. Automatically triggers the refresh flow if the token is expired and the Refresh ID is valid.

### JWTAuth.Revoke

```go
func (j *JWTAuth) Revoke(w http.ResponseWriter, r *http.Request) JWTAuthResult
```

Revoke Access Token and Refresh ID, clear cookies, and mark the revocation record in Redis.

### JWTAuth.Close

```go
func (j *JWTAuth) Close() error
```

Close the Redis connection.

### JWTAuth.GinMiddleware

```go
func (j *JWTAuth) GinMiddleware() gin.HandlerFunc
```

Return a Gin middleware that automatically verifies tokens and stores user data in the Gin context.

### JWTAuth.HTTPMiddleware

```go
func (j *JWTAuth) HTTPMiddleware(next http.Handler) http.Handler
```

Return a standard `net/http` middleware that automatically verifies tokens and stores user data in the request context.

### GetAuthDataFromGinContext

```go
func GetAuthDataFromGinContext(c *gin.Context) (*Auth, bool)
```

Retrieve authenticated user data from the Gin context.

### GetAuthDataFromHTTPRequest

```go
func GetAuthDataFromHTTPRequest(r *http.Request) (*Auth, bool)
```

Retrieve authenticated user data from the HTTP request context.

### Type Definitions

#### Auth

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
```

User authentication data structure, embedded in JWT claims.

#### JWTAuthResult

```go
type JWTAuthResult struct {
    StatusCode int          `json:"status_code"`
    Success    bool         `json:"success"`
    Data       *Auth        `json:"data,omitempty"`
    Token      *TokenResult `json:"token,omitempty"`
    Error      string       `json:"error,omitempty"`
    ErrorTag   string       `json:"error_tag,omitempty"`
}
```

Unified return structure for all JWT operations.

#### TokenResult

```go
type TokenResult struct {
    Token     string `json:"token"`
    RefreshId string `json:"refresh_id"`
}
```

Result after token creation or refresh.

### HTTP Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| `X-Device-FP` | Request | Custom device fingerprint (overrides auto-detection) |
| `X-Device-ID` | Request | Device identifier |
| `X-Refresh-ID` | Request | Refresh ID (alternative to cookie) |
| `X-New-Access-Token` | Response | New Access Token after refresh |
| `X-New-Refresh-ID` | Response | New Refresh ID after refresh |

### Error Tags

| Tag | Description |
|-----|-------------|
| `data_missing` | Required data is missing |
| `data_invalid` | Invalid data format |
| `unauthorized` | Not authenticated or session expired |
| `revoked` | Token has been revoked |
| `not_found` | Resource not found |
| `not_matched` | Data mismatch |
| `failed_to_create` | Creation operation failed |
| `failed_to_sign` | JWT signing failed |
| `failed_to_store` | Redis store failed |
| `failed_to_get` | Redis query failed |
| `failed_to_update` | Update operation failed |

***

©️ 2025 [邱敬幃 Pardn Chiu](https://linkedin.com/in/pardnchiu)
