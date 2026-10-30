# 快速開始

本頁從安裝到跑起第一個受保護路由：啟動 Redis、建立 `JWTAuth`、登入、存取、登出。

## 前置需求

| 項目 | 版本 |
|---|---|
| Go | 1.24 以上（`go.mod` 宣告 `go 1.24.3`） |
| Redis | 任一支援 `SETEX`／`SETNX`／`EVAL`／`MULTI` 的版本（CI 使用 `redis:7-alpine`） |
| Gin | 僅在使用 `GinMiddleware()` 時需要 |

## 安裝

```bash
go get github.com/pardnchiu/go-jwt@latest
```

套件位於 `core/` 子目錄，package 名稱為 `goJwt`。v1.0.3 起匯入路徑為 `github.com/pardnchiu/go-jwt/core`，舊路徑的符號對照見 [已移除 API](/zh/removed-api)。

```go
import goJwt "github.com/pardnchiu/go-jwt/core"
```

## 啟動 Redis

```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

## 第一個伺服器

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

	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		result := auth.Create(w, r, &goJwt.Auth{ID: "u_001", Name: "Pardn", Email: "dev@example.com"})
		if !result.Success {
			http.Error(w, result.Error, result.StatusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result.Token)
	})

	mux.Handle("GET /me", auth.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := goJwt.GetAuthDataFromHTTPRequest(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	})))

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

第一次啟動時，若沒有設定金鑰且 `./keys/` 下沒有 PEM 檔，`New()` 會產生一組 P-256 金鑰對寫入 `./keys/private-key.pem` 與 `./keys/public-key.pem`（相對於工作目錄）。細節見 [金鑰管理](/zh/key-management)。

## 驗證流程

用 cookie jar 模擬瀏覽器。User-Agent 必須是可辨識的瀏覽器字串，或改帶固定的 `X-Device-FP`，否則指紋每次請求都不同（見 [裝置指紋](/zh/device-fingerprint)）：

```bash
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"

# 登入：回應寫入 access_token、refresh_id、conn.device.id 三個 Cookie
curl -s -A "$UA" -c jar.txt -b jar.txt -X POST http://localhost:8080/login

# 存取受保護路由
curl -s -A "$UA" -c jar.txt -b jar.txt http://localhost:8080/me

# 登出：清除 Cookie 並撤銷 Access Token
curl -s -A "$UA" -c jar.txt -b jar.txt -X POST http://localhost:8080/logout -o /dev/null -w "%{http_code}\n"
```

## 下一步

| 想做的事 | 頁面 |
|---|---|
| 了解 Access Token、Refresh ID、JTI 的分工 | [Token 模型](/zh/core-concepts) |
| 調整有效期、Cookie 屬性 | [設定](/zh/configuration) |
| 接 Gin | [中介層](/zh/middleware) |
| 接行動 App 或 API 客戶端 | [客戶端整合](/zh/client-integration) |
