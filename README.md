# JWT Authentication

> 一個提供存取權杖和更新權杖的 Golang JWT 身份驗證套件，具備指紋識別、Redis 儲存和自動更新功能。<br>
> A Golang JWT authentication package providing access tokens and refresh tokens with fingerprinting, Redis storage, and automatic refresh capabilities.<br>
>
> Node.js version [here](https://github.com/pardnchiu/node-jwt-auth)

![](https://img.shields.io/github/languages/top/pardnchiu/go-jwt)
[![license](https://img.shields.io/github/license/pardnchiu/go-jwt)](LICENSE)
[![version](https://img.shields.io/github/v/tag/pardnchiu/go-jwt)](https://github.com/pardnchiu/go-jwt/releases)

## 三大主軸

### 雙權杖系統 / Dual Token
Access Token 搭配 Refresh ID，並具備自動更新機制<br>
Access Token paired with Refresh ID, and provide automatic refresh mechanism

### 裝置指紋識別 / Fingerprint Verify
基於 `User-Agent`、`Device ID`、作業系統和瀏覽器生成唯一指紋，防止權杖在不同裝置間濫用<br>
Generates unique fingerprint based on `User-Agent`, `Device ID`, operating system, and browser to prevent token abuse across different devices

### 安全防護 / Security Protection
權杖撤銷、版本控制、智能更新，以及使用 Redis 鎖定機制的併發保護<br>
Token revocation, version control, intelligent refresh, and concurrency protection using Redis locking mechanism

## 流程圖 / Flow

<details>
<summary>點擊顯示</summary>

```mermaid
flowchart TD
  Start([Request Start]) --> Auth{Has Access Token?}
  Auth -->|Yes| CheckRevoke[Check if token is revoked]
  Auth -->|No| HasRefresh{Has Refresh ID?}
  HasRefresh -->|No| Unauthorized[Return 401 Unauthorized]
  HasRefresh -->|Yes| ValidateRefresh[Validate Refresh ID]
  CheckRevoke --> IsRevoked{Token revoked?}
  IsRevoked -->|Yes| Unauthorized
  IsRevoked -->|No| ParseToken[Parse access token]
  ParseToken --> TokenValid{Token valid?}
  TokenValid -->|Yes| ValidateClaims[Validate claims]
  TokenValid -->|No| IsExpired{Token expired?}
  IsExpired -->|Yes| ParseExpiredToken[Parse expired token]
  IsExpired -->|No| InvalidToken[Return 400 Invalid Token]
  ParseExpiredToken --> ValidateExpiredClaims[Validate expired token claims]
  ValidateExpiredClaims --> ExpiredClaimsValid{Refresh ID and fingerprint match?}
  ExpiredClaimsValid -->|No| InvalidClaims[Return 400 Invalid Claims]
  ExpiredClaimsValid -->|Yes| RefreshFlow[Enter refresh flow]
  ValidateClaims --> ClaimsValid{Claims match?}
  ClaimsValid -->|No| InvalidClaims
  ClaimsValid -->|Yes| CheckJTI[Check JTI]
  CheckJTI --> JTIValid{JTI valid?}
  JTIValid -->|No| Unauthorized
  JTIValid -->|Yes| Success[Return 200 Success]
  ValidateRefresh --> RefreshValid{Refresh ID valid?}
  RefreshValid -->|No| Unauthorized
  RefreshValid -->|Yes| RefreshFlow
  RefreshFlow --> AcquireLock[Acquire refresh lock]
  AcquireLock --> LockSuccess{Lock acquired?}
  LockSuccess -->|No| TooManyRequests[Return 429 Too Many Requests]
  LockSuccess -->|Yes| GetRefreshData[Get refresh data]
  GetRefreshData --> CheckTTL[Check TTL]
  CheckTTL --> NeedNewRefresh{Need new Refresh ID?}
  NeedNewRefresh -->|Yes| CreateNewRefresh[Create new Refresh ID]
  NeedNewRefresh -->|No| UpdateVersion[Update version number]
  CreateNewRefresh --> SetOldRefreshExpire[Set old Refresh ID to expire in 5 seconds]
  SetOldRefreshExpire --> SetNewRefreshData[Set new refresh data]
  UpdateVersion --> SetNewRefreshData
  SetNewRefreshData --> CheckUserExists{Check if user exists}
  CheckUserExists -->|No| Unauthorized
  CheckUserExists -->|Yes| GenerateNewToken[Generate new access token]
  GenerateNewToken --> StoreJTI[Store new JTI]
  StoreJTI --> SetCookies[Set Cookies]
  SetCookies --> ReleaseLock[Release lock]
  ReleaseLock --> RefreshSuccess[Return refresh success]
```

</details>

## 依賴套件 / Dependencies

- [`github.com/gin-gonic/gin`](https://github.com/gin-gonic/gin)
- [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt/v5)
- [`github.com/redis/go-redis/v9`](https://github.com/redis/go-redis/v9)
- [`github.com/pardnchiu/go-logger`](https://github.com/pardnchiu/go-logger)<br>
  如果你不需要，你可以 fork 然後使用你熟悉的取代。更可以到[這裡](https://forms.gle/EvNLwzpHfxWR2gmP6)進行投票讓我知道。<br>
  If you don't need this, you can fork the project and replace it. You can also vote [here](https://forms.gle/EvNLwzpHfxWR2gmP6) to let me know your thought.

## 使用方法 / How to use

### 安裝 / Installation
```bash
go get github.com/pardnchiu/go-jwt
```

### 初始化 / Initialization
```go
package main

import (
  "log"
  "net/http"
  
  "github.com/gin-gonic/gin"
  goJwt "github.com/pardnchiu/go-jwt"
)

func main() {
  config := goJwt.Config{
    Redis: goJwt.Redis{
      Host:     "localhost",
      Port:     6379,
      Password: "password",
      DB:       0,
    },
    CheckAuth: func(userData goJwt.Auth) (bool, error) {
      // Custom user validation logic
      return userData.ID != "", nil
    },
  }

  auth, err := goJwt.New(config)
  if err != nil {
    log.Fatal("Initialization failed:", err)
  }
  defer auth.Close()

  r := gin.Default()

  // Login endpoint
  r.POST("/login", func(c *gin.Context) {
    // After validating login credentials...
    user := &goJwt.Auth{
      ID:    "user123",
      Name:  "John Doe",
      Email: "john@example.com",
      Scope: []string{"read", "write"},
    }

    result := auth.Create(c.Writer, c.Request, user)
    if !result.Success {
      c.JSON(result.StatusCode, gin.H{"error": result.Error})
      return
    }

    c.JSON(http.StatusOK, gin.H{
      "success": true,
      "token":   result.Token.Token,
      "user":    result.Data,
    })
  })

  // Protected routes
  protected := r.Group("/api")
  protected.Use(auth.GinMiddleware())
  {
    protected.GET("/profile", func(c *gin.Context) {
      user, _ := goJwt.GetAuthDataFromGinContext(c)
      c.JSON(http.StatusOK, gin.H{"user": user})
    })
  }

  // Logout
  r.POST("/logout", func(c *gin.Context) {
    result := auth.Revoke(c.Writer, c.Request)
    if !result.Success {
      c.JSON(result.StatusCode, gin.H{"error": result.Error})
      return
    }
    c.JSON(http.StatusOK, gin.H{"message": "成功登出"})
  })

  r.Run(":8080")
}
```

### 配置說明 / Configuration
```go
type Config struct {
  Redis     Redis                    // Redis configuration (required)
  File      *File                    // File configuration for key management (optional)
  Log       *Log                     // Logging configuration (optional)
  Option    *Option                  // System parameters and token settings (optional)
  Cookie    *Cookie                  // Cookie security settings (optional)
  CheckAuth func(Auth) (bool, error) // User authentication function (optional)
}

type Redis struct {
  Host     string // Redis server host address (required)
  Port     int    // Redis server port number (required)
  Password string // Redis authentication password (optional, empty string means no auth)
  DB       int    // Redis database index (required, usually 0-15)
}

type File struct {
  PrivateKeyPath string // ECDSA private key file path for JWT signing
  PublicKeyPath  string // ECDSA public key file path for JWT verification
}

type Log struct {
  Path      string // Log directory path (default: ./logs/jwtAuth)
  Stdout    bool   // Enable console log output (default: false)
  MaxSize   int64  // Maximum size before log file rotation (bytes) (default: 16MB)
  MaxBackup int    // Number of rotated log files to retain (default: 5)
  Type      string // Output format: "json" for slog standard, "text" for tree format (default: "text")
}

type Option struct {
  PrivateKey           string        // ECDSA private key content (auto-generates P-256 if not provided)
  PublicKey            string        // ECDSA public key content (auto-generates P-256 if not provided)
  AccessTokenExpires   time.Duration // Access token expiration time (default: 15 minutes)
  RefreshIdExpires     time.Duration // Refresh ID expiration time (default: 7 days)
  AccessTokenCookieKey string        // Access token cookie name (default: "access_token")
  RefreshIdCookieKey   string        // Refresh ID cookie name (default: "refresh_id")
  MaxVersion           int           // Maximum version count for refresh tokens (default: 5)
  RefreshTTL           float64       // Refresh threshold as proportion of TTL (default: 0.5)
}

type Cookie struct {
  Domain   *string        // Cookie domain scope (nil means current domain)
  Path     *string        // Cookie path scope (default: "/")
  SameSite *http.SameSite // Cookie SameSite policy (default: Lax for CSRF prevention)
  Secure   *bool          // Cookie secure flag, HTTPS only (default: false)
  HttpOnly *bool          // Cookie HttpOnly flag for XSS prevention (default: true)
}
```

## 可用函式 / Functions

### 實例管理 / Instance Management

- `New()` - 建立新的實例 / Create a new instance
  ```go
  auth, err := goJwt.New(config)
  ```
  - 初始化 Redis 連線<br>
    Initialize Redis connection
  - 設定日誌系統<br>
    Setup logging system
  - 若未提供則自動生成 ECDSA 金鑰<br>
    Auto-generate ECDSA keys if not provided
  - 驗證配置<br>
    Validate configuration

- `Close()` - 關閉實例 / Close instance
  ```go
  err := auth.Close()
  ```
  - 關閉 Redis 連線<br>
    Close Redis connection
  - 釋放系統資源<br>
    Release system resources

### JWT 管理 / JWT Management

- `Create()` - 生成新的 JWT / Generate a new JWT
  ```go
  result := auth.Create(w, r, userData)
  ```
  - 生成存取權杖和更新 ID<br>
    Generate access token and refresh ID
  - 設定安全 cookies<br>
    Set secure cookies
  - 在 Redis 中儲存會話資料<br>
    Store session data in Redis

- `Verify()` - 驗證 JWT / Verify JWT
  ```go
  result := auth.Verify(w, r)
  ```
  - 解析和驗證 JWT 權杖<br>
    Parse and validate JWT tokens
  - 檢查裝置指紋<br>
    Check device fingerprint
  - 如需要則自動更新<br>
    Auto-refresh if needed
  - 返回用戶資料<br>
    Return user data

- `Revoke()` - 終止 JWT / Revoke JWT
  ```go
  result := auth.Revoke(w, r)
  ```
  - 清除 cookies<br>
    Clear cookies
  - 將權杖加入黑名單<br>
    Blacklist tokens
  - 更新 Redis 記錄<br>
    Update Redis records

### 中間件 / Middleware

```go
// Gin framework middleware
protected.Use(auth.GinMiddleware())

// Standard HTTP middleware
server := &http.Server{
  Handler: auth.HTTPMiddleware(handler),
}

// Get user data from context
user, exists := goJwt.GetAuthDataFromGinContext(c)
user, exists := goJwt.GetAuthDataFromHTTPRequest(r)
```

### 支持多種驗證方法 / Support Multiple Methods

#### 自定義標頭 / Custom headers
```
r.Header.Set("X-Device-FP", fingerprint)
r.Header.Set("X-Refresh-ID", refreshID)
r.Header.Set("Authorization", "Bearer "+token)
```

#### Cookies 自動管理 / automatically managed
```
access_token、refresh_id cookies
```

## 錯誤處理 / Error Handling
> 所有方法都返回 [`JWTAuthResult`](type.go) 結構<br>
> All methods return a [`JWTAuthResult`](type.go) structure
```go
type JWTAuthResult struct {
  StatusCode int          // HTTP status code
  Success    bool         // Whether operation succeeded
  Data       *Auth        // User data
  Token      *TokenResult // Token information
  Error      string       // Error message
  ErrorTag   string       // Error category tag
}
```

### 錯誤標籤 / Error Tags
- `data_missing` - 缺少必要資料 / Missing required data
- `data_invalid` - 無效的資料格式 / Invalid data format
- `unauthorized` - 身份驗證失敗 / Authentication failed
- `revoked` - 權杖已被撤銷 / Token has been revoked
- `failed_to_update` - 更新操作失敗 / Update operation failed
- `failed_to_create` - 建立操作失敗 / Create operation failed
- `failed_to_sign` - 權杖簽署失敗 / Token signing failed
- `failed_to_store` - 儲存操作失敗 / Storage operation failed
- `failed_to_get` - 取得操作失敗 / Get operation failed

## 授權條款 / License

此原始碼專案採用 [MIT](LICENSE) 授權條款。<br>
This source code project is licensed under the [MIT](LICENSE) license.

## 作者 / Author

<img src="https://avatars.githubusercontent.com/u/25631760" align="left" width="96" height="96" style="margin-right: 0.5rem;">

<h4 style="padding-top: 0">邱敬幃 Pardn Chiu</h4>

<a href="mailto:dev@pardn.io" target="_blank">
  <img src="https://pardn.io/image/email.svg" width="48" height="48">
</a> <a href="https://linkedin.com/in/pardnchiu" target="_blank">
  <img src="https://pardn.io/image/linkedin.svg" width="48" height="48">
</a>

***

©️ 2025 [邱敬幃 Pardn Chiu](https://pardn.io)