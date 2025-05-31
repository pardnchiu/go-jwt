# JWT Auth (Golang)

> A JWT authentication package providing both Access Token and Refresh Token mechanisms, featuring fingerprint recognition, Redis storage, and automatic refresh functionality.<br>
> version Node.js can get [here](https://github.com/pardnchiu/nodejs-jwt-auth)

[![version](https://img.shields.io/github/v/tag/pardnchiu/golang-jwt-auth)](https://github.com/pardnchiu/golang-jwt-auth)

## Feature

- ### Dual Token System
  - Access Token (short-term) + Refresh Token (long-term)
  - Automatic token refresh without requiring re-login
  - ES256 algorithm (Elliptic Curve Digital Signature)
- ### Device Fingerprinting
  - Generates unique fingerprints based on User-Agent, Device ID, OS, and Browser
  - Prevents token misuse across different devices
  - Automatic device type detection (Desktop, Mobile, Tablet)
- ### Token Revocation
  - Adds Access Token to blacklist upon logout
  - Redis TTL automatically cleans expired revocation records
  - Prevents reuse of logged-out tokens
- ### Version Control Protection
  - Refresh Token version tracking
  - Auto-generates new Refresh ID after 5 refresh attempts
  - Prevents replay attacks
- ### Smart Refresh Strategy
  - Auto-regenerates when Refresh Token has less than half lifetime remaining
  - 5-second grace period for old tokens to reduce concurrency issues
  - Minimizes database queries
- ### Multiple Authentication Methods
  - Automatic cookie reading
  - Authorization Bearer Header
  - Custom Headers (X-Device-ID, X-Refresh-ID)
- ### Flexible Configuration
  - Supports file paths or direct key content
  - Customizable Cookie names
  - Production/Development environment auto-switching

## How to use

- ### Installation
  ```bash
  go get github.com/pardnchiu/golang-jwt-auth
  ```
- ### Initialize
  ```go
  package main

  import (
    "log"
    "time"

    "github.com/pardnchiu/golang-jwt-auth"
  )

  func main() {
    config := &golangJwtAuth.Config{
      PrivateKeyPath:       "./keys/private.pem",
      PublicKeyPath:        "./keys/public.pem", 
      // Or provide keys directly:
      // PrivateKey:           "-----BEGIN EC PRIVATE KEY-----...",
      // PublicKey:            "-----BEGIN PUBLIC KEY-----...",
      AccessTokenExpires:   15 * time.Minute,
      RefreshIdExpires:     7 * 24 * time.Hour,
      // true: domain=Domain, samesite=none, secure=true
      // false: domain=localhost, samesite=lax, secure=false
      IsProd:               false,
      Domain:               "pardn.io",
      // Cookie key names, defaults to access_token/refresh_id
      AccessTokenCookieKey: "access_token",
      RefreshIdCookieKey:   "refresh_id",
      // Redis storage configuration
      Redis: golangJwtAuth.RedisConfig{
        Host:     "localhost",
        Port:     6379,
        Password: "",
        DB:       0,
      },
      CheckUserExists: func(user golangJwtAuth.AuthData) (bool, error) {
        // Return true if user exists, false otherwise
        return true, nil
      },
      // Maximum version threshold, default 5
      MaxVersion: 5,
      // TTL threshold, default 0.5
      RefreshTTL: 0.5
    }

    jwtAuth, err := golangJwtAuth.New(config)
    if err != nil {
      log.Fatal("failed to init:", err)
    }
    defer jwtAuth.Close()
  }
  ```

### Create()

```go
func loginHandler(jwtAuth *golangJwtAuth.JWTAuth) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    // after verifying user login info...
    
    userData := &golangJwtAuth.AuthData{
      ID:        "user123",
      Name:      "John Doe",
      Email:     "john@example.com",
      Thumbnail: "avatar.jpg",
      Role:      "user",
      Level:     1,
      Scope:     []string{"read", "write"},
    }

    tokenResult, err := jwtAuth.Create(r, w, userData)
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    // automatically set in cookies
    json.NewEncoder(w).Encode(map[string]interface{}{
      "success":    true,
      "token":      tokenResult.Token,
      "refresh_id": tokenResult.RefreshId,
    })
  }
}
```

### Verify()

```go
func protectedHandler(jwtAuth *golangJwtAuth.JWTAuth) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    result := jwtAuth.Verify(r, w)
    
    if !result.Success {
      w.WriteHeader(result.StatusCode)
      json.NewEncoder(w).Encode(map[string]string{
        "error": result.Error,
      })
      return
    }

    // Use the authenticated user data
    user := result.Data
    json.NewEncoder(w).Encode(map[string]interface{}{
      "message": "Protected resource accessed",
      "user":    user,
    })
  }
}
```

### Revoke()

```go
func logoutHandler(jwtAuth *golangJwtAuth.JWTAuth) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    err := jwtAuth.Revoke(r, w)
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }

    json.NewEncoder(w).Encode(map[string]string{
      "message": "Successfully logged out",
    })
  }
}
```

### GinMiddleware

```go
package main

import (
  "github.com/gin-gonic/gin"
  "github.com/pardnchiu/golang-jwt-auth"
)

func main() {
  // Initialize jwtAuth...
  
  r := gin.Default()
  
  // Apply as a global middleware
  r.Use(jwtAuth.GinMiddleware())
  
  // Or apply to specific route groups
  protected := r.Group("/api/protected")
  protected.Use(jwtAuth.GinMiddleware())
  {
    protected.GET("/profile", func(c *gin.Context) {
      // Get user data from Context
      user, exists := golangJwtAuth.GetAuthDataFromGinContext(c)
      if !exists {
        c.JSON(500, gin.H{"error": "Failed to get user data"})
        return
      }
      
      c.JSON(200, gin.H{
        "user": user,
      })
    })
  }
  
  r.Run(":8080")
}
```

### HTTPMiddleware

```go
package main

import (
  "net/http"
  "github.com/pardnchiu/golang-jwt-auth"
)

func main() {
  // Initialize jwtAuth...
  
  mux := http.NewServeMux()
  
  // Protected route
  mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
    // Get user data from Request Context
    user, exists := golangJwtAuth.GetAuthDataFromHTTPRequest(r)
    if !exists {
      http.Error(w, "Failed to get user data", http.StatusInternalServerError)
      return
    }
    
    json.NewEncoder(w).Encode(map[string]interface{}{
      "user": user,
    })
  })
  
  // Apply middleware
  server := &http.Server{
    Addr:    ":8080",
    Handler: jwtAuth.HTTPMiddleware(mux),
  }
  
  server.ListenAndServe()
}
```

## Configuration

### Config
- `PrivateKeyPath` / `PrivateKey`: private key file path or content
- `PublicKeyPath` / `PublicKey`: public key file path or content  
- `AccessTokenExpires`: access token expire time
- `RefreshIdExpires`: refresh id expire time
- `IsProd`: is production or not (affects cookie setting)
- `Domain`: cookie domain
- `Redis`: redis connection
  - `Host`: redis host
  - `Port`: redis port
  - `Password`: redis password (optional)
  - `Db`: redis db (optional)
- `CheckUserExists`: user existence check function
- `AccessTokenCookieKey`: access token cookie name (default: 'access_token')
- `RefreshTokenCookieKey`: refresh id cookie name (default: 'refresh_id')
- `MaxVersion`: Version threshold (default: 5)
- `RefreshTTL`: TTL threshold (default: 0.5)
- `LogPath`: Custom log path (default: './logs/golangJWTAuth')

### Supported methods

1. **Cookie**: Automatically reads token from cookie
2. **Authorization Header**: `Authorization: Bearer <token>`
3. **Custom Headers**: 
   - `X-Session-FP`: Custom fingerprint
   - `X-Refresh-ID`: Custom Refresh ID
   - `X-Device-ID`: Device ID

## Token refresh

The new tokens are returned via:
- HTTP Header: `X-New-Access-Token`
- HTTP Header: `X-New-Refresh-ID`
- Cookie auto-update

## Security features

- **Fingerprint recognition**: Generates a unique fingerprint based on User-Agent, Device-ID, OS, Browser, and Device type
- **Token revocation**: Adds token to a blacklist on logout
- **Automatic expiration**: Supports TTL to automatically clean up expired tokens
- **Version control**: Tracks Refresh Token versions to prevent replay attacks
- **Fingerprint validation**: Ensures tokens are used from the same device/browser

## Error handling

All main methods return an `AuthResult` struct, including:
- `Success`: Whether the operation succeeded
- `StatusCode`: HTTP status code
- `Error`: Error message
- `Data`: User data (on success)