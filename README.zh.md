# JWT Authentication

> 一個提供存取權杖和更新權杖的 Golang JWT 身份驗證套件，具備指紋識別、Redis 儲存和自動更新功能。

[![pkg](https://pkg.go.dev/badge/github.com/pardnchiu/go-jwt.svg)](https://pkg.go.dev/github.com/pardnchiu/go-jwt)
[![card](https://goreportcard.com/badge/github.com/pardnchiu/go-jwt)](https://goreportcard.com/report/github.com/pardnchiu/go-jwt)
[![codecov](https://img.shields.io/codecov/c/github/pardnchiu/go-jwt)](https://app.codecov.io/github/pardnchiu/go-jwt)
[![version](https://img.shields.io/github/v/tag/pardnchiu/go-jwt?label=release)](https://github.com/pardnchiu/go-jwt/releases)
[![license](https://img.shields.io/github/license/pardnchiu/go-jwt)](LICENSE)<br>
[![readme](https://img.shields.io/badge/readme-EN-white)](README.md)
[![readme](https://img.shields.io/badge/readme-ZH-white)](README.zh.md)

## 三大主軸

### 雙權杖系統
Access Token 搭配 Refresh ID，並具備自動更新機制

### 裝置指紋識別
基於 `User-Agent`、`Device ID`、作業系統和瀏覽器生成唯一指紋，防止權杖在不同裝置間濫用

### 安全防護
權杖撤銷、版本控制、智能更新，以及使用 Redis 鎖定機制的併發保護

## 流程圖

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

## 依賴套件

- [`github.com/gin-gonic/gin`](https://github.com/gin-gonic/gin)
- [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt/v5)
- [`github.com/redis/go-redis/v9`](https://github.com/redis/go-redis/v9)
- ~~[`github.com/pardnchiu/go-logger`](https://github.com/pardnchiu/go-logger)~~ (< v1.0.1)<br>
  為了效能與穩定度，`v1.0.1` 起棄用非標準庫套件，改用 `log/slog`

## 使用方法

### 安裝
```bash
go get github.com/pardnchiu/go-jwt
```

### 初始化
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

### 配置說明
```go
type Config struct {
  Redis     Redis                    // Redis configuration (required)
  File      *File                    // File configuration for key management (optional)
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

## 可用函式

### 實例管理

- `New()` - 建立新的實例
  ```go
  auth, err := goJwt.New(config)
  ```
  - 初始化 Redis 連線
  - 若未提供則自動生成 ECDSA 金鑰
  - 驗證配置

- `Close()` - 關閉實例
  ```go
  err := auth.Close()
  ```
  - 關閉 Redis 連線
  - 釋放系統資源

### JWT 管理

- `Create()` - 生成新的 JWT
  ```go
  result := auth.Create(w, r, userData)
  ```
  - 生成存取權杖和更新 ID
  - 設定安全 cookies
  - 在 Redis 中儲存會話資料

- `Verify()` - 驗證 JWT
  ```go
  result := auth.Verify(w, r)
  ```
  - 解析和驗證 JWT 權杖
  - 檢查裝置指紋
  - 如需要則自動更新
  - 返回用戶資料

- `Revoke()` - 終止 JWT
  ```go
  result := auth.Revoke(w, r)
  ```
  - 清除 cookies
  - 將權杖加入黑名單
  - 更新 Redis 記錄

### 中間件

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

### 支持多種驗證方法

#### 自定義標頭
```
r.Header.Set("X-Device-FP", fingerprint)
r.Header.Set("X-Refresh-ID", refreshID)
r.Header.Set("Authorization", "Bearer "+token)
```

#### Cookies 自動管理
```
access_token、refresh_id cookies
```

## 錯誤處理
> 所有方法都返回 [`JWTAuthResult`](type.go) 結構
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

### 錯誤標籤
- `data_missing` - 缺少必要資料
- `data_invalid` - 無效的資料格式
- `unauthorized` - 身份驗證失敗
- `revoked` - 權杖已被撤銷
- `failed_to_update` - 更新操作失敗
- `failed_to_create` - 建立操作失敗
- `failed_to_sign` - 權杖簽署失敗
- `failed_to_store` - 儲存操作失敗
- `failed_to_get` - 取得操作失敗

## 授權條款

此原始碼專案採用 [MIT](LICENSE) 授權條款。

## 星

[![Star](https://api.star-history.com/svg?repos=pardnchiu/go-jwt&type=Date)](https://www.star-history.com/#pardnchiu/go-jwt&Date)

## 作者

<img src="https://avatars.githubusercontent.com/u/25631760" align="left" width="96" height="96" style="margin-right: 0.5rem;">

<h4 style="padding-top: 0">邱敬幃 Pardn Chiu</h4>

<a href="mailto:dev@pardn.io" target="_blank">
  <img src="https://pardn.io/image/email.svg" width="48" height="48">
</a> <a href="https://linkedin.com/in/pardnchiu" target="_blank">
  <img src="https://pardn.io/image/linkedin.svg" width="48" height="48">
</a>

***

©️ 2025 [邱敬幃 Pardn Chiu](https://pardn.io)
