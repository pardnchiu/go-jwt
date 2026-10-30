# API Reference

Every exported function, method, and type in `github.com/pardnchiu/go-jwt/core` (package `goJwt`).

## Functions

| Signature | Description |
|---|---|
| `func New(c Config) (*JWTAuth, error)` | Apply defaults, load or generate keys, connect to Redis and `PING`, return an instance |
| `func GetAuthDataFromGinContext(c *gin.Context) (*Auth, bool)` | Read the user data stored by `GinMiddleware` |
| `func GetAuthDataFromHTTPRequest(r *http.Request) (*Auth, bool)` | Read the user data `HTTPMiddleware` stored in the request context |

## JWTAuth Methods

| Signature | Description |
|---|---|
| `func (j *JWTAuth) Create(w http.ResponseWriter, r *http.Request, auth *Auth) JWTAuthResult` | Issue an Access Token and Refresh ID, writing cookies and Redis; a `nil` `auth` returns `400 data_missing` |
| `func (j *JWTAuth) Verify(w http.ResponseWriter, r *http.Request) JWTAuthResult` | Verify the request, refreshing transparently when needed (see [Verification Flow](/verification)) |
| `func (j *JWTAuth) Revoke(w http.ResponseWriter, r *http.Request) JWTAuthResult` | Clear cookies, revoke the Access Token, expire the Refresh ID after 5 seconds (see [Revocation](/revocation)) |
| `func (j *JWTAuth) GinMiddleware() gin.HandlerFunc` | Gin middleware (see [Middleware](/middleware)) |
| `func (j *JWTAuth) HTTPMiddleware(next http.Handler) http.Handler` | `net/http` middleware |
| `func (j *JWTAuth) Close() error` | Close the Redis connection |

`JWTAuth` has no exported fields; one instance can be shared across goroutines.

## Configuration Types

| Type | Description |
|---|---|
| `Config` | Top-level settings: `Redis`, `File`, `Option`, `Cookie`, `CheckAuth` |
| `Redis` | `Host`, `Port`, `Password`, `DB` |
| `File` | `PrivateKeyPath`, `PublicKeyPath` |
| `Option` | Key contents, lifetimes, cookie names, `MaxVersion`, `RefreshTTL` |
| `Cookie` | `Domain`, `Path`, `SameSite`, `Secure`, `HttpOnly` (all pointers) |

See [Configuration](/configuration) for fields and defaults.

## Result and Data Types

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
```

| Field | When set |
|---|---|
| `JWTAuthResult.Data` | On successful `Create` and `Verify` |
| `JWTAuthResult.Token` | On successful `Create`; on `Verify` when a refresh happened and succeeded |
| `JWTAuthResult.ErrorTag` | On failure; values in [Status Codes and Error Tags](/error-codes) |

## Internal State Types

These types are exported but callers rarely need them directly:

| Type | Description |
|---|---|
| `RefreshData` | Content of Redis `refresh:<id>`: `Data`, `Version`, `Fingerprint`, `Exp`, `Iat`, `Jti` (see [Token Model](/core-concepts)) |
| `RefreshId` | Input hashed into the Refresh ID: `ID`, `Name`, `Email`, `Fingerprint`, `Iat`, `Jti` |
| `Pem` | Parsed ECDSA key pair; its `private` and `public` fields are unexported, so it cannot be built or read from outside |
