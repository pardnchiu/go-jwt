# go-jwt - 技術文件

> 返回 [README](./README.zh.md)

## 前置需求

- Go 1.24 以上
- Redis 伺服器（透過 `github.com/redis/go-redis/v9` 連線）
- 使用 `GinMiddleware()` 時需 `github.com/gin-gonic/gin`

## 安裝

### 使用 go get

```bash
go get github.com/pardnchiu/go-jwt@latest
```

套件位於 `core/` 子目錄，package 名稱為 `goJwt`：

```go
import goJwt "github.com/pardnchiu/go-jwt/core"
```

### 從原始碼

```bash
git clone https://github.com/pardnchiu/go-jwt.git
cd go-jwt
go build ./...
```

### 執行測試

測試需要可連線的 Redis（`localhost:6379`）：

```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
go test -race ./...
```

## 設定

所有設定透過 `goJwt.New(goJwt.Config{...})` 傳入，無環境變數。

### Config

| 欄位 | 型別 | 必要 | 說明 |
|------|------|------|------|
| `Redis` | `Redis` | 是 | Redis 連線設定 |
| `File` | `*File` | 否 | PEM 金鑰檔案路徑 |
| `Option` | `*Option` | 否 | Token 參數；`nil` 時全部套用預設值 |
| `Cookie` | `*Cookie` | 否 | Cookie 屬性覆寫；`nil` 時使用預設屬性 |
| `CheckAuth` | `func(Auth) (bool, error)` | 否 | 每次刷新時檢查使用者是否仍有效；回傳 `false` 或 error 即拒絕刷新 |

### Redis

| 欄位 | 型別 | 說明 |
|------|------|------|
| `Host` | `string` | 主機位址 |
| `Port` | `int` | 連接埠 |
| `Password` | `string` | 密碼（可空） |
| `DB` | `int` | 資料庫編號 |

`New()` 會先執行 `PING`，連線失敗直接回傳 error。

### Option

| 欄位 | 型別 | 預設值 | 說明 |
|------|------|--------|------|
| `PrivateKey` | `string` | — | ECDSA 私鑰 PEM 內容（PKCS#8） |
| `PublicKey` | `string` | — | ECDSA 公鑰 PEM 內容（PKIX） |
| `AccessTokenExpires` | `time.Duration` | `15 * time.Minute` | Access Token 有效期 |
| `RefreshIdExpires` | `time.Duration` | `7 * 24 * time.Hour` | Refresh ID 有效期 |
| `AccessTokenCookieKey` | `string` | `access_token` | Access Token Cookie 名稱 |
| `RefreshIdCookieKey` | `string` | `refresh_id` | Refresh ID Cookie 名稱，同時是 JWT 內存放 Refresh ID 的 claim 名稱 |
| `MaxVersion` | `int` | `5` | 刷新次數超過此值即整組重發 Refresh ID |
| `RefreshTTL` | `float64` | `0.5` | Refresh ID 剩餘 TTL 低於 `RefreshIdExpires × RefreshTTL` 時整組重發 |

零值或負值一律回退至預設值。

### Cookie

| 欄位 | 型別 | 預設值 |
|------|------|--------|
| `Domain` | `*string` | 未設定 |
| `Path` | `*string` | `/` |
| `SameSite` | `*http.SameSite` | `http.SameSiteLaxMode` |
| `Secure` | `*bool` | `false` |
| `HttpOnly` | `*bool` | `true` |

只有非 `nil` 的欄位會覆寫預設值。正式環境走 HTTPS 時應設 `Secure: true`。

### 金鑰載入順序

| 優先序 | 條件 | 行為 |
|--------|------|------|
| 1 | `File.PrivateKeyPath` / `File.PublicKeyPath` 有值 | 讀檔並覆寫 `Option.PrivateKey` / `Option.PublicKey`；讀檔失敗回傳 error |
| 2 | `Option.PrivateKey` 與 `Option.PublicKey` 皆有值 | 直接使用 |
| 3 | 兩者皆空且 `./keys/private-key.pem`、`./keys/public-key.pem` 存在 | 讀取既有檔案 |
| 4 | 兩者皆空且上述檔案不存在 | 產生 P-256 金鑰對並寫入 `./keys/`（私鑰 `0600`、公鑰 `0644`） |
| — | 只提供其中一把 | 回傳 error |

載入後會驗證兩把金鑰皆為 ECDSA 且彼此配對。多實例部署須共用同一組金鑰，否則各實例自動產生的金鑰互不承認。

### 請求輸入

| 來源 | 名稱 | 用途 |
|------|------|------|
| Cookie | `access_token`（可設定） | Access Token，優先於 Authorization header |
| Header | `Authorization: Bearer <token>` | Access Token（無 Cookie 時） |
| Header | `X-Refresh-ID` | Refresh ID，優先於 Cookie |
| Cookie | `refresh_id`（可設定） | Refresh ID |
| Header | `X-Device-FP` | 直接指定裝置指紋，略過 User-Agent 推算 |
| Header | `X-Device-ID` | 裝置 ID，優先於 Cookie |
| Cookie | `conn.device.id` | 裝置 ID；缺少時自動產生 UUID 並寫入 90 天 Cookie |

### 回應輸出

| 位置 | 名稱 | 時機 |
|------|------|------|
| Set-Cookie | Access Token / Refresh ID | `Create()`、整組重發 |
| Set-Cookie | Access Token | 僅重簽 Access Token 時 |
| Header | `X-New-Access-Token` | 僅重簽 Access Token 時 |
| Set-Cookie | `conn.device.id` | 每次計算指紋（未帶 `X-Device-FP` 時） |

## 使用方式

### 基礎：net/http 登入、受保護路由、登出

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"

	goJwt "github.com/pardnchiu/go-jwt/core"
)

func main() {
	auth, err := goJwt.New(goJwt.Config{
		Redis: goJwt.Redis{Host: "localhost", Port: 6379},
	})
	if err != nil {
		log.Fatalf("初始化 go-jwt 失敗: %v", err)
	}
	defer auth.Close()

	mux := http.NewServeMux()

	// 登入：簽發 Access Token 與 Refresh ID（同時寫入 Cookie）
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		result := auth.Create(w, r, &goJwt.Auth{
			ID:    "u_001",
			Name:  "Pardn",
			Email: "dev@example.com",
			Role:  "admin",
			Scope: []string{"read", "write"},
		})
		if !result.Success {
			http.Error(w, result.Error, result.StatusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result.Token)
	})

	// 受保護路由：中介層驗證失敗時直接回傳 JSON error
	mux.Handle("GET /me", auth.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := goJwt.GetAuthDataFromHTTPRequest(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	})))

	// 登出：撤銷 Access Token 並清除 Cookie
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		result := auth.Revoke(w, r)
		if !result.Success {
			http.Error(w, result.Error, result.StatusCode)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

### Gin 中介層

```go
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	goJwt "github.com/pardnchiu/go-jwt/core"
)

func main() {
	auth, err := goJwt.New(goJwt.Config{
		Redis: goJwt.Redis{Host: "localhost", Port: 6379},
	})
	if err != nil {
		log.Fatalf("初始化 go-jwt 失敗: %v", err)
	}
	defer auth.Close()

	r := gin.Default()

	r.POST("/login", func(c *gin.Context) {
		result := auth.Create(c.Writer, c.Request, &goJwt.Auth{ID: "u_001", Name: "Pardn"})
		if !result.Success {
			c.JSON(result.StatusCode, gin.H{"error": result.Error, "tag": result.ErrorTag})
			return
		}
		c.JSON(http.StatusOK, result.Token)
	})

	api := r.Group("/api", auth.GinMiddleware())
	api.GET("/me", func(c *gin.Context) {
		user, ok := goJwt.GetAuthDataFromGinContext(c)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.JSON(http.StatusOK, user)
	})

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
```

### 進階：自訂參數、Cookie 與使用者檢查

```go
package main

import (
	"errors"
	"log"
	"net/http"
	"time"

	goJwt "github.com/pardnchiu/go-jwt/core"
)

var errUserBanned = errors.New("user banned")

func main() {
	domain := "example.com"
	secure := true
	sameSite := http.SameSiteStrictMode

	auth, err := goJwt.New(goJwt.Config{
		Redis: goJwt.Redis{Host: "redis.internal", Port: 6379, Password: "secret", DB: 1},
		File: &goJwt.File{
			PrivateKeyPath: "/etc/app/keys/private-key.pem",
			PublicKeyPath:  "/etc/app/keys/public-key.pem",
		},
		Option: &goJwt.Option{
			AccessTokenExpires: 10 * time.Minute,
			RefreshIdExpires:   30 * 24 * time.Hour,
			MaxVersion:         10,
			RefreshTTL:         0.3,
		},
		Cookie: &goJwt.Cookie{
			Domain:   &domain,
			Secure:   &secure,
			SameSite: &sameSite,
		},
		// 每次刷新時確認使用者仍存在且未被停權
		CheckAuth: func(a goJwt.Auth) (bool, error) {
			if a.ID == "u_banned" {
				return false, errUserBanned
			}
			return true, nil
		},
	})
	if err != nil {
		log.Fatalf("初始化 go-jwt 失敗: %v", err)
	}
	defer auth.Close()
}
```

### 非瀏覽器客戶端（API / 行動 App）

非瀏覽器客戶端無 Cookie 時，User-Agent 若無法辨識 OS／瀏覽器，指紋每次請求都會不同，必須帶固定的 `X-Device-FP`：

```bash
# 登入
curl -X POST http://localhost:8080/login \
  -H "X-Device-FP: device-7f3a9c"

# 帶 Access Token 與 Refresh ID 存取
curl http://localhost:8080/me \
  -H "X-Device-FP: device-7f3a9c" \
  -H "Authorization: Bearer <token>" \
  -H "X-Refresh-ID: <refresh_id>" \
  -D -
```

Access Token 過期而僅重簽時，新 Token 由 `X-New-Access-Token` header 回傳；整組重發時新 Token 只透過 `Set-Cookie` 下發。

## API 參考

### 函式與方法

| 簽章 | 說明 |
|------|------|
| `func New(c Config) (*JWTAuth, error)` | 套用預設值、載入或產生金鑰、連線 Redis 並回傳實例 |
| `func (j *JWTAuth) Close() error` | 關閉 Redis 連線 |
| `func (j *JWTAuth) Create(w http.ResponseWriter, r *http.Request, auth *Auth) JWTAuthResult` | 簽發 Access Token 與 Refresh ID，寫入 Cookie 與 Redis |
| `func (j *JWTAuth) Verify(w http.ResponseWriter, r *http.Request) JWTAuthResult` | 驗證 Access Token；過期或缺少時以 Refresh ID 自動刷新 |
| `func (j *JWTAuth) Revoke(w http.ResponseWriter, r *http.Request) JWTAuthResult` | 清除 Cookie、撤銷 Access Token 並讓 Refresh ID 於 5 秒後失效 |
| `func (j *JWTAuth) GinMiddleware() gin.HandlerFunc` | Gin 中介層；成功時以 `c.Set("user", *Auth)` 傳遞 |
| `func (j *JWTAuth) HTTPMiddleware(next http.Handler) http.Handler` | net/http 中介層；成功時將 `*Auth` 放入 request context |
| `func GetAuthDataFromGinContext(c *gin.Context) (*Auth, bool)` | 從 Gin context 取出使用者資料 |
| `func GetAuthDataFromHTTPRequest(r *http.Request) (*Auth, bool)` | 從 request context 取出使用者資料 |

中介層驗證失敗時以 `result.StatusCode` 回應 `{"error": "<訊息>"}` 並中止後續處理。

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

type RefreshData struct {
	Data        *Auth  `json:"data,omitempty"`
	Version     int    `json:"version"`
	Fingerprint string `json:"fp"`
	Exp         int64  `json:"exp"`
	Iat         int64  `json:"iat"`
	Jti         string `json:"jti"`
}
```

`Auth` 的所有欄位都寫入 JWT claims，不應放入敏感資料。

`RefreshId`（計算 Refresh ID 雜湊的輸入：`ID`、`Name`、`Email`、`Fingerprint`、`Iat`、`Jti`）與 `Pem`（解析後的 ECDSA 金鑰對，欄位未匯出）也有匯出，呼叫端通常不需要直接使用。

### 狀態碼與錯誤標籤

| StatusCode | ErrorTag | 觸發情境 |
|------------|----------|----------|
| `400` | `data_missing` | `Create()` 未提供 `Auth`；`Revoke()` 缺少 Refresh ID |
| `400` | `data_invalid` | Access Token 簽章、`nbf`／`iat`、Refresh ID、指紋或 JTI 驗證失敗 |
| `401` | `unauthorized` | 未登入、Refresh ID 無效／過期／指紋不符、`Revoke()` 找不到 Refresh ID |
| `401` | `revoked` | Access Token 已被撤銷 |
| `401` | （空） | `CheckAuth` 回傳 `false` 或 error |
| `429` | `failed_to_update` | 同一 Refresh ID 正在被其他請求刷新 |
| `500` | `failed_to_create` | Refresh ID 或刷新資料序列化失敗 |
| `500` | `failed_to_sign` | JWT 簽署失敗 |
| `500` | `failed_to_store` | Redis 寫入失敗 |
| `500` | `failed_to_get` | Redis 讀取失敗 |

### Redis Key

| Key | 值 | TTL |
|-----|----|-----|
| `refresh:<refreshID>` | `RefreshData` JSON | `RefreshIdExpires`；刷新後沿用剩餘 TTL |
| `jti:<jti>` | `"1"` | `AccessTokenExpires` |
| `lock:refresh:<refreshID>` | 鎖持有者 UUID | 3 秒 |
| `revoke:<accessToken>` | `"1"` | `AccessTokenExpires` |

### 日誌

`New()` 會將 package 層級 logger 指向 syslog（`LOG_LOCAL0`，JSON 格式）；syslog 不可用時回退至 stderr 文字格式。

***

©️ 2025 [邱敬幃 Pardn Chiu](https://www.linkedin.com/in/pardnchiu)
