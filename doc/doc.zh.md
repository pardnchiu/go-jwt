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

### 從原始碼

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

| 欄位 | 預設 | 說明 |
|------|------|------|
| `AccessTokenExpires` | `15m` | Access Token 有效期限 |
| `RefreshIdExpires` | `7d` | Refresh ID 有效期限 |
| `AccessTokenCookieKey` | `access_token` | Access Token Cookie 鍵名 |
| `RefreshIdCookieKey` | `refresh_id` | Refresh ID Cookie 鍵名 |
| `MaxVersion` | `5` | 重建 Refresh ID 前的刷新次數 |
| `RefreshTTL` | `0.5` | 觸發 Refresh ID 重建的 TTL 比例門檻 |

### Cookie 設定

| 欄位 | 型別 | 預設 | 說明 |
|------|------|------|------|
| `Domain` | `*string` | 無 | Cookie 網域 |
| `Path` | `*string` | `/` | Cookie 路徑 |
| `SameSite` | `*http.SameSite` | `Lax` | SameSite 屬性 |
| `Secure` | `*bool` | `false` | 僅 HTTPS |
| `HttpOnly` | `*bool` | `true` | HttpOnly 旗標 |

### PEM 金鑰

支援三種設定方式，優先順序如下：

1. `File.PrivateKeyPath` / `File.PublicKeyPath` — 指定檔案路徑
2. `Option.PrivateKey` / `Option.PublicKey` — 直接提供 PEM 文字
3. 自動偵測 `./keys/private-key.pem` 與 `./keys/public-key.pem`；若不存在則產生新的 ECDSA P-256 金鑰對

## 使用方式

### 基本初始化

```go
package main

import (
    "fmt"
    "log"

    "github.com/pardnchiu/go-jwt/core"
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

    fmt.Println("JWT 驗證已就緒")
}
```

### 建立 Token

```go
result := jwt.Create(w, r, &goJwt.Auth{
    ID:    "user-001",
    Name:  "Alice",
    Email: "alice@example.com",
    Role:  "admin",
    Level: 10,
    Scope: []string{"read", "write"},
})
if !result.Success {
    http.Error(w, result.Error, result.StatusCode)
    return
}

// result.Token.Token      → Access Token
// result.Token.RefreshId  → Refresh ID
// Cookie 會自動寫入
```

### 驗證 Token

```go
result := jwt.Verify(w, r)
if !result.Success {
    http.Error(w, result.Error, result.StatusCode)
    return
}

user := result.Data
fmt.Printf("已驗證: %s <%s>\n", user.Name, user.Email)
```

### 撤銷 Token

```go
result := jwt.Revoke(w, r)
if !result.Success {
    http.Error(w, result.Error, result.StatusCode)
    return
}
// Cookie 已清除，Access Token 已列入撤銷清單
```

### Gin 中介層

```go
r := gin.Default()
r.Use(jwt.GinMiddleware())

r.GET("/me", func(c *gin.Context) {
    user, ok := goJwt.GetAuthDataFromGinContext(c)
    if !ok {
        c.JSON(401, gin.H{"error": "未授權"})
        return
    }
    c.JSON(200, user)
})
```

### net/http 中介層

```go
mux := http.NewServeMux()
mux.Handle("/me", jwt.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user, ok := goJwt.GetAuthDataFromHTTPRequest(r)
    if !ok {
        http.Error(w, "未授權", http.StatusUnauthorized)
        return
    }
    json.NewEncoder(w).Encode(user)
})))
```

### 進階：自訂 CheckAuth 與 Cookie

```go
domain := "example.com"
secure := true
sameSite := http.SameSiteStrictMode

jwt, err := goJwt.New(goJwt.Config{
    Redis: goJwt.Redis{
        Host:     "localhost",
        Port:     6379,
        Password: "secret",
        DB:       1,
    },
    Option: &goJwt.Option{
        AccessTokenExpires: 30 * time.Minute,
        RefreshIdExpires:   14 * 24 * time.Hour,
        MaxVersion:         10,
        RefreshTTL:         0.3,
    },
    Cookie: &goJwt.Cookie{
        Domain:   &domain,
        Secure:   &secure,
        SameSite: &sameSite,
    },
    CheckAuth: func(auth goJwt.Auth) (bool, error) {
        // 刷新期間回傳 false 可強制登出
        return userExists(auth.ID)
    },
})
if err != nil {
    log.Fatalf("初始化失敗: %v", err)
}
```

## API 參考

### New

```go
func New(c Config) (*JWTAuth, error)
```

初始化 JWTAuth、連線 Redis，並載入或產生 ECDSA 金鑰。

### Close

```go
func (j *JWTAuth) Close() error
```

關閉 Redis 用戶端。

### Create

```go
func (j *JWTAuth) Create(w http.ResponseWriter, r *http.Request, auth *Auth) JWTAuthResult
```

簽署 Access Token、建立 Refresh ID、寫入 Cookie，並將狀態存入 Redis。

### Verify

```go
func (j *JWTAuth) Verify(w http.ResponseWriter, r *http.Request) JWTAuthResult
```

驗證 Access Token；過期或缺失時自動走刷新流程。

### Revoke

```go
func (j *JWTAuth) Revoke(w http.ResponseWriter, r *http.Request) JWTAuthResult
```

清除 Cookie，將 Access Token 標記為已撤銷，並縮短 Refresh ID 存活時間。

### GinMiddleware

```go
func (j *JWTAuth) GinMiddleware() gin.HandlerFunc
```

Gin 中介層：驗證後將 `*Auth` 寫入 context 鍵 `user`。

### HTTPMiddleware

```go
func (j *JWTAuth) HTTPMiddleware(next http.Handler) http.Handler
```

標準 `net/http` 中介層：驗證後將 `*Auth` 寫入 request context。

### GetAuthDataFromGinContext

```go
func GetAuthDataFromGinContext(c *gin.Context) (*Auth, bool)
```

從 Gin context 取出驗證後的使用者。

### GetAuthDataFromHTTPRequest

```go
func GetAuthDataFromHTTPRequest(r *http.Request) (*Auth, bool)
```

從 HTTP request context 取出驗證後的使用者。

### 型別

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

### Token 來源優先順序

| 項目 | 優先來源 | 次要來源 |
|------|----------|----------|
| Access Token | Cookie `access_token` | `Authorization: Bearer ...` |
| Refresh ID | Header `X-Refresh-ID` | Cookie `refresh_id` |
| 裝置指紋 | Header `X-Device-FP` | 由 User-Agent + 裝置 ID 衍生 |

### 刷新回應標頭

成功透明刷新時，回應可能包含：

| 標頭 | 說明 |
|------|------|
| `X-New-Access-Token` | 新簽署的 Access Token |

***

©️ 2025 [邱敬幃 Pardn Chiu](https://www.linkedin.com/in/pardnchiu)
