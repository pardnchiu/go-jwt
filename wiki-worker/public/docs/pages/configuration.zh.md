# 設定

所有設定都透過 `goJwt.New(goJwt.Config{...})` 傳入，本函式庫不讀任何環境變數；金鑰相關設定見 [金鑰管理](/zh/key-management)。

## Config

| 欄位 | 型別 | JSON tag | 必要 | 說明 |
|---|---|---|---|---|
| `Redis` | `Redis` | `redis` | 是 | Redis 連線設定 |
| `File` | `*File` | `file` | 否 | PEM 金鑰檔案路徑 |
| `Option` | `*Option` | `parameter` | 否 | Token 參數；`nil` 時全部套用預設值 |
| `Cookie` | `*Cookie` | `cookie` | 否 | Cookie 屬性覆寫；`nil` 時使用預設屬性 |
| `CheckAuth` | `func(Auth) (bool, error)` | 不序列化 | 否 | 每次刷新時呼叫，回傳 `false` 或 error 即拒絕刷新（見 [透明刷新](/zh/refresh)） |

`Option` 的 JSON tag 是 `parameter`，從 JSON 載入設定時要用這個鍵名。

## Redis

| 欄位 | 型別 | 說明 |
|---|---|---|
| `Host` | `string` | 主機位址 |
| `Port` | `int` | 連接埠 |
| `Password` | `string` | 密碼，可空 |
| `DB` | `int` | 資料庫編號 |

`New()` 以 `Host:Port`、`Password` 與 `DB` 建立 `go-redis` client 後執行 `PING`；`PING` 失敗時 `New()` 回傳 error。

## Option

| 欄位 | 型別 | 預設值 | 說明 |
|---|---|---|---|
| `PrivateKey` | `string` | — | ECDSA 私鑰 PEM 內容 |
| `PublicKey` | `string` | — | ECDSA 公鑰 PEM 內容 |
| `AccessTokenExpires` | `time.Duration` | `15 * time.Minute` | Access Token 與 JTI 的有效期 |
| `RefreshIdExpires` | `time.Duration` | `7 * 24 * time.Hour` | Refresh ID 有效期 |
| `AccessTokenCookieKey` | `string` | `access_token` | Access Token Cookie 名稱 |
| `RefreshIdCookieKey` | `string` | `refresh_id` | Refresh ID Cookie 名稱，同時是 JWT 內存放 Refresh ID 的 claim 名稱 |
| `MaxVersion` | `int` | `5` | 僅重簽次數上限，超過即整組重發 |
| `RefreshTTL` | `float64` | `0.5` | Refresh ID 剩餘 TTL 低於 `RefreshIdExpires × RefreshTTL` 時整組重發 |

零值或負值一律回退至預設值。`Verify()` 以目前的 `RefreshIdCookieKey` 讀取 Refresh ID claim，且型別斷言未檢查；修改後，以舊名稱簽發且尚未過期的 Access Token 會在 `Verify()` 內 panic（`gin.Default()` 內建的 recovery 中介層回 500，純 `net/http` server 則中斷該請求）。請與金鑰輪替一起修改，或等以舊名稱簽發的 Access Token 全部過期後再修改。

## Cookie

| 欄位 | 型別 | 預設值 |
|---|---|---|
| `Domain` | `*string` | 未設定（僅限發出的主機） |
| `Path` | `*string` | `/` |
| `SameSite` | `*http.SameSite` | `http.SameSiteLaxMode` |
| `Secure` | `*bool` | `false` |
| `HttpOnly` | `*bool` | `true` |

只有非 `nil` 的欄位會覆寫預設值，套用於 `access_token`、`refresh_id`、`conn.device.id` 三個 Cookie。

## 完整範例

```go
package main

import (
	"log"
	"net/http"
	"time"

	goJwt "github.com/pardnchiu/go-jwt/core"
)

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
	})
	if err != nil {
		log.Fatalf("初始化 go-jwt 失敗: %v", err)
	}
	defer auth.Close()
}
```

## 日誌

`New()` 將 package 層級的 `slog` logger 指向 syslog（priority `LOG_INFO|LOG_LOCAL0`、tag `goCron`、JSON 格式）；syslog 無法連線時改輸出到 stderr（文字格式）。在 syslog 以 `goCron` tag 過濾即可找到 go-jwt 的紀錄。
