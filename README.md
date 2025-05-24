# JWT Auth Golang Package

A Go JWT authentication package providing both Access Token and Refresh Token mechanisms, featuring fingerprint recognition, Redis storage, and automatic refresh functionality.

## How to use

### New()

```go
package main

import (
  "log"
  "time"
  "github.com/pardnltd-tools/golang-jwt-auth"
)

func main() {
  config := &golangJwtAuth.Config{
    PrivateKeyPath:       "./keys/private.pem",
    PublicKeyPath:        "./keys/public.pem", 
    AccessTokenExpires:   15 * time.Minute,
    RefreshIdExpires:     7 * 24 * time.Hour,
    IsProd:               false,
    Domain:               "localhost",
    AccessTokenCoolieKey: "access_token",
    RefreshIdCookieKey:   "refresh_id",
    Redis: golangJwtAuth.RedisConfig{
      Host:     "localhost",
      Port:     6379,
      Password: "",
      DB:       0,
    },
    CheckUserExists: func(user golangJwtAuth.AuthData) (bool, error) {
      // Implement user existence check logic
      return true, nil
    },
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
    // After verifying user login info...
    
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

    // Token is automatically set in the cookie, and can also be returned to the frontend
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
  "github.com/pardnltd-tools/golang-jwt-auth"
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
  "github.com/pardnltd-tools/golang-jwt-auth"
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

### Config struct parameters

- `PrivateKeyPath` / `PrivateKey`: EC private key file path or content
- `PublicKeyPath` / `PublicKey`: EC public key file path or content  
- `AccessTokenExpires`: Access Token expiration duration
- `RefreshIdExpires`: Refresh Token expiration duration
- `IsProd`: Whether in production environment (affects cookie security settings)
- `Domain`: Cookie domain setting
- `Redis`: Redis connection settings
- `CheckUserExists`: User existence check function

### Supported authentication methods

1. **Cookie**: Automatically reads token from cookie
2. **Authorization Header**: `Authorization: Bearer <token>`
3. **Custom Headers**: 
   - `X-Session-FP`: Custom fingerprint
   - `X-Refresh-ID`: Custom Refresh ID
   - `X-Device-ID`: Device ID

## Token refresh mechanism

The system automatically generates a new Refresh ID in the following cases:
- Refresh version exceeds 5 times
- Remaining Refresh Token time is less than half

The new Refresh ID is returned via:
- HTTP Header: `X-New-Refresh-ID`
- HTTP Header: `X-New-Access-Token`
- Cookie auto-update

## Security features

- **Fingerprint recognition**: Generates a unique fingerprint based on User-Agent, Device-ID, OS, and Browser
- **Token revocation**: Adds token to a blacklist on logout
- **Automatic expiration**: Supports TTL to automatically clean up expired tokens
- **Version control**: Tracks Refresh Token versions to prevent replay attacks

## Error handling

All main methods return an `AuthResult` struct, including:
- `Success`: Whether the operation succeeded
- `StatusCode`: HTTP status code
- `Error`: Error message
- `Data`: User data (on success)

Common error types:
- `unauthorized`: Unauthorized
- `token revoked`: Token has been revoked  
- `fingerprint invalid`: Fingerprint mismatch
- `refresh id invalid`: Invalid Refresh ID
- `access token invalid`: Invalid Access Token

## Notes

1. Ensure Redis service is running properly
2. Set up EC key pairs correctly
3. Set correct domain and HTTPS in production
4. Implement the `CheckUserExists` function to verify user status