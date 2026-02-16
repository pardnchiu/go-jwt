# go-jwt - 技術文件

> 返回 [README](./README.zh.md)

## 前置需求

- Go 1.24 或更高版本
- Redis 伺服器

## 安裝

### 使用 go get

```bash
go get github.com/pardnchiu/go-jwt
```

### 從原始碼建置

```bash
git clone https://github.com/pardnchiu/go-jwt.git
cd go-jwt
go build ./...
```

## 設定

### Config 結構

| 欄位 | 型別 | 必要 | 說明 |
|------|------|------|------|
| `Redis` | `Redis` | 是 | Redis 連線設定 |
| `File` | `*File` | 否 | PEM 金鑰檔案路徑 |
| `Option` | `*Option` | 否 | Token 參數調整 |
| `Cookie` | `*Cookie` | 否 | Cookie 屬性設定 |
| `CheckAuth` | `func(Auth) (bool, error)` | 否 | 自訂使用者驗證函式 |

### Redis 設定

| 欄位 | 型別 | 必要 | 說明 |
|------|------|------|------|
| `Host` | `string` | 是 | Redis 主機位址 |
| `Port` | `int` | 是 | Redis 連接埠 |
| `Password` | `string` | 否 | Redis 密碼 |
| `DB` | `int` | 是 | Redis 資料庫編號 |

### Option 預設值

| 欄位 | 預設值 | 說明 |
|------|--------|------|
| `AccessTokenExpires` | `15m` | Access Token 有效期限 |
| `RefreshIdExpires` | `7d` | Refresh ID 有效期限 |
| `AccessTokenCookieKey` | `access_token` | Access Token Cookie 鍵名 |
| `RefreshIdCookieKey` | `refresh_id` | Refresh ID Cookie 鍵名 |
| `MaxVersion` | `5` | 觸發 Refresh ID 重建的刷新次數 |
| `RefreshTTL` | `0.5` | 觸發 Refresh ID 重建的 TTL 閾值比例 |

### Cookie 設定

| 欄位 | 型別 | 預設值 | 說明 |
|------|------|--------|------|
| `Domain` | `*string` | 無 | Cookie 網域 |
| `Path` | `*string` | `/` | Cookie 路徑 |
| `SameSite` | `*http.SameSite` | `Lax` | SameSite 屬性 |
| `Secure` | `*bool` | `false` | 是否僅 HTTPS |
| `HttpOnly` | `*bool` | `true` | 是否 HttpOnly |

### PEM 金鑰

金鑰支援三種配置方式，優先順序如下：

1. `File.PrivateKeyPath` / `File.PublicKeyPath` — 指定檔案路徑
2. `Option.PrivateKey` / `Option.PublicKey` — 直接提供 PEM 文字內容
3. 自動偵測 `./keys/private-key.pem` 與 `./keys/public-key.pem`，若不存在則自動生成 ECDSA P-256 金鑰對

## 使用方式

### 基礎初始化

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
        log.Fatalf("初始化失敗: %v", err)
    }
    defer jwt.Close()

    fmt.Println("JWT 認證服務已啟動")
}
```

### 搭配 Gin 使用

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
            // 自訂使用者驗證邏輯
            return auth.ID != "", nil
        },
    })
    if err != nil {
        panic(err)
    }
    defer jwt.Close()

    r := gin.Default()

    // 登入端點
    r.POST("/login", func(c *gin.Context) {
        result := jwt.Create(c.Writer, c.Request, &goJwt.Auth{
            ID:    "user-001",
            Name:  "Alice",
            Email: "alice@example.com",
            Role:  "admin",
        })
        c.JSON(result.StatusCode, result)
    })

    // 受保護的路由群組
    protected := r.Group("/api", jwt.GinMiddleware())
    protected.GET("/profile", func(c *gin.Context) {
        user, ok := goJwt.GetAuthDataFromGinContext(c)
        if !ok {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
            return
        }
        c.JSON(http.StatusOK, user)
    })

    // 登出端點
    r.POST("/logout", jwt.GinMiddleware(), func(c *gin.Context) {
        result := jwt.Revoke(c.Writer, c.Request)
        c.JSON(result.StatusCode, result)
    })

    r.Run(":8080")
}
```

### 搭配標準 net/http 使用

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

    // 登入端點
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

    // 受保護的端點
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

### 自訂 Token 參數

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

## API 參考

### New

```go
func New(c Config) (*JWTAuth, error)
```

建立並初始化 JWTAuth 實例。驗證設定、載入或生成 ECDSA 金鑰、建立 Redis 連線。

### JWTAuth.Create

```go
func (j *JWTAuth) Create(w http.ResponseWriter, r *http.Request, auth *Auth) JWTAuthResult
```

建立新的 Access Token 與 Refresh ID，設定 Cookie，並將 Refresh Data 存入 Redis。

### JWTAuth.Verify

```go
func (j *JWTAuth) Verify(w http.ResponseWriter, r *http.Request) JWTAuthResult
```

驗證 Access Token 的有效性。若 Token 過期且 Refresh ID 有效，自動觸發刷新流程。

### JWTAuth.Revoke

```go
func (j *JWTAuth) Revoke(w http.ResponseWriter, r *http.Request) JWTAuthResult
```

撤銷 Access Token 與 Refresh ID，清除 Cookie，並在 Redis 中標記撤銷記錄。

### JWTAuth.Close

```go
func (j *JWTAuth) Close() error
```

關閉 Redis 連線。

### JWTAuth.GinMiddleware

```go
func (j *JWTAuth) GinMiddleware() gin.HandlerFunc
```

回傳 Gin Middleware，自動驗證 Token 並將使用者資料存入 Gin Context。

### JWTAuth.HTTPMiddleware

```go
func (j *JWTAuth) HTTPMiddleware(next http.Handler) http.Handler
```

回傳標準 `net/http` Middleware，自動驗證 Token 並將使用者資料存入 Request Context。

### GetAuthDataFromGinContext

```go
func GetAuthDataFromGinContext(c *gin.Context) (*Auth, bool)
```

從 Gin Context 中取得已驗證的使用者資料。

### GetAuthDataFromHTTPRequest

```go
func GetAuthDataFromHTTPRequest(r *http.Request) (*Auth, bool)
```

從 HTTP Request Context 中取得已驗證的使用者資料。

### 型別定義

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

使用者認證資料結構，嵌入 JWT Claims 中。

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

所有 JWT 操作的統一回傳結構。

#### TokenResult

```go
type TokenResult struct {
    Token     string `json:"token"`
    RefreshId string `json:"refresh_id"`
}
```

Token 建立或刷新後的結果。

### HTTP Headers

| Header | 方向 | 說明 |
|--------|------|------|
| `X-Device-FP` | Request | 自訂設備指紋（覆蓋自動偵測） |
| `X-Device-ID` | Request | 設備識別碼 |
| `X-Refresh-ID` | Request | Refresh ID（替代 Cookie） |
| `X-New-Access-Token` | Response | 刷新後的新 Access Token |
| `X-New-Refresh-ID` | Response | 刷新後的新 Refresh ID |

### Error Tags

| Tag | 說明 |
|-----|------|
| `data_missing` | 必要資料缺失 |
| `data_invalid` | 資料格式無效 |
| `unauthorized` | 未認證或認證過期 |
| `revoked` | Token 已被撤銷 |
| `not_found` | 資源不存在 |
| `not_matched` | 資料不匹配 |
| `failed_to_create` | 建立操作失敗 |
| `failed_to_sign` | JWT 簽署失敗 |
| `failed_to_store` | Redis 儲存失敗 |
| `failed_to_get` | Redis 查詢失敗 |
| `failed_to_update` | 更新操作失敗 |

***

©️ 2025 [邱敬幃 Pardn Chiu](https://linkedin.com/in/pardnchiu)
