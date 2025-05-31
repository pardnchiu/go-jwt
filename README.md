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
      AccessTokenExpires:   15 * time.Minute,
      RefreshIdExpires:     7 * 24 * time.Hour,
      IsProd:               false,
      Domain:               "pardn.io",
      Redis: golangJwtAuth.RedisConfig{
        Host: "localhost",
        Port: 6379,
      },
      CheckUserExists: func(user golangJwtAuth.AuthData) (bool, error) {
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

- ### Create
  <details>
  <summary>Flow</summary>
  
  ```mermaid
  flowchart TD
    CreateStart([Create Token Request]) --> ValidateAuthData{Validate User Data}
    ValidateAuthData -->|Invalid| CreateError[Return Error]
    ValidateAuthData -->|Valid| GenerateJTI[Generate JTI]
    GenerateJTI --> GenerateFingerprint[Generate Fingerprint]
    GenerateFingerprint --> CreateRefreshId[Create Refresh ID]
    CreateRefreshId --> CreateAccessToken[Create Access Token]
    CreateAccessToken --> StoreRedisData[Store Redis Data]
    StoreRedisData --> SetTokenCookies[Set Token Cookies]
    SetTokenCookies --> CreateSuccess[Creation Success]
  ```
  
  </details>


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
- ### Verify
  <details>
  <summary>Flow</summary>
  
  ```mermaid
  flowchart TD
    Start([Request Start]) --> Auth{Has Access Token?}
    
    Auth -->|Yes| CheckRevoke[Check Token Revocation]
    Auth -->|No| HasRefresh{Has Refresh ID?}
    
    HasRefresh -->|No| Unauthorized[Return 401 Unauthorized]
    HasRefresh -->|Yes| ValidateRefresh[Validate Refresh ID]
    
    CheckRevoke --> IsRevoked{Token Revoked?}
    IsRevoked -->|Yes| Unauthorized
    IsRevoked -->|No| ParseToken[Parse Access Token]
    
    ParseToken --> TokenValid{Token Valid?}
    TokenValid -->|Yes| ValidateClaims[Validate Claims]
    TokenValid -->|No| IsExpired{Token Expired?}
    
    IsExpired -->|Yes| ParseExpiredToken[Parse Expired Token]
    IsExpired -->|No| InvalidToken[Return 400 Invalid Token]
    
    ParseExpiredToken --> ValidateExpiredClaims[Validate Expired Token Claims]
    ValidateExpiredClaims --> ExpiredClaimsValid{Refresh ID & Fingerprint Match?}
    ExpiredClaimsValid -->|No| InvalidClaims[Return 400 Invalid Claims]
    ExpiredClaimsValid -->|Yes| RefreshFlow[Enter Refresh Flow]
    
    ValidateClaims --> ClaimsValid{Claims Match?}
    ClaimsValid -->|No| InvalidClaims
    ClaimsValid -->|Yes| CheckJTI[Check JTI]
    
    CheckJTI --> JTIValid{JTI Valid?}
    JTIValid -->|No| Unauthorized
    JTIValid -->|Yes| Success[Return 200 Success]
    
    ValidateRefresh --> RefreshValid{Refresh ID Valid?}
    RefreshValid -->|No| Unauthorized
    RefreshValid -->|Yes| RefreshFlow
    
    RefreshFlow --> AcquireLock[Acquire Refresh Lock]
    AcquireLock --> LockSuccess{Lock Acquired?}
    LockSuccess -->|No| TooManyRequests[Return 429 Too Many Requests]
    LockSuccess -->|Yes| GetRefreshData[Get Refresh Data]
    
    GetRefreshData --> CheckTTL[Check TTL]
    CheckTTL --> NeedNewRefresh{Need New Refresh ID?}
    
    NeedNewRefresh -->|Yes| CreateNewRefresh[Create New Refresh ID]
    NeedNewRefresh -->|No| UpdateVersion[Update Version]
    
    CreateNewRefresh --> SetOldRefreshExpire[Set Old Refresh ID to Expire in 5s]
    SetOldRefreshExpire --> SetNewRefreshData[Set New Refresh Data]
    UpdateVersion --> SetNewRefreshData
    
    SetNewRefreshData --> CheckUserExists{User Exists Check}
    CheckUserExists -->|No| Unauthorized
    CheckUserExists -->|Yes| GenerateNewToken[Generate New Access Token]
    
    GenerateNewToken --> StoreJTI[Store New JTI]
    StoreJTI --> SetCookies[Set Cookies]
    SetCookies --> ReleaseLock[Release Lock]
    ReleaseLock --> RefreshSuccess[Return Refresh Success]
  ```
  
  </details>

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
- ### Revoke
  <details>
  <summary>Flow</summary>
  
  ```mermaid
  flowchart TD
    RevokeStart([Revoke Request]) --> ClearCookies[Clear Cookies]
    ClearCookies --> GetTokens[Get Token Info]
    GetTokens --> HasRefreshId{Has Refresh ID?}
    HasRefreshId -->|No| RevokeSuccess[Revocation Success]
    HasRefreshId -->|Yes| GetRefreshData2[Get Refresh Data from Redis]
    GetRefreshData2 --> RefreshExists{Refresh Data Exists?}
    RefreshExists -->|No| RevokeSuccess
    RefreshExists -->|Yes| SetOldRefreshExpire2[Set Refresh ID to Expire in 5s]
    SetOldRefreshExpire2 --> CheckAccessTTL[Check Access Token TTL]
    CheckAccessTTL --> TTLValid{TTL > 0?}
    TTLValid -->|No| RevokeSuccess
    TTLValid -->|Yes| AddToRevokeList[Add Access Token to Revoke List]
    AddToRevokeList --> RevokeSuccess
  ```
  
  </details>

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
- ### GinMiddleware
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
- ### HTTPMiddleware
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

### Config Parameters
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

### Supported Authentication Methods

1. **Cookie**: Automatically reads token from cookie
2. **Authorization Header**: `Authorization: Bearer <token>`
3. **Custom Headers**: 
   - `X-Session-FP`: Custom fingerprint
   - `X-Refresh-ID`: Custom Refresh ID
   - `X-Device-ID`: Device ID

### Token Refresh Response

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

## License

This source code project is licensed under the [MIT](https://github.com/pardnchiu/FlexPlyr/blob/main/LICENSE) license.

## Creator

<img src="https://avatars.githubusercontent.com/u/25631760" align="left" width="96" height="96" style="margin-right: 0.5rem;">

<h4 style="padding-top: 0">邱敬幃 Pardn Chiu</h4>

<a href="mailto:dev@pardn.io" target="_blank">
    <img src="https://pardn.io/image/email.svg" width="48" height="48">
</a> <a href="https://linkedin.com/in/pardnchiu" target="_blank">
    <img src="https://pardn.io/image/linkedin.svg" width="48" height="48">
</a>

***

©️ 2025 [邱敬幃 Pardn Chiu](https://pardn.io)
