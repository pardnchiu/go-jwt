# 中介層

go-jwt 提供 Gin 與 `net/http` 兩種中介層（Middleware），都以 `Verify()` 驗證請求，成功時把 `*Auth` 交給後續 handler。

## 行為

| 項目 | `GinMiddleware()` | `HTTPMiddleware(next)` |
|---|---|---|
| 驗證 | `Verify(c.Writer, c.Request)` | `Verify(w, r)` |
| 失敗回應 | `c.JSON(StatusCode, {"error": ...})` 後 `c.Abort()` | `Content-Type: application/json`、`StatusCode`、`{"error": ...}`，不呼叫 `next` |
| 成功時存放 | `c.Set("user", *Auth)` | `context.WithValue(r.Context(), "user", *Auth)` |
| 取出 | `GetAuthDataFromGinContext(c)` | `GetAuthDataFromHTTPRequest(r)` |

失敗回應只含 `error`，不含 `ErrorTag`；需要依錯誤類型分流時，改在自己的 handler 直接呼叫 `Verify()`。

刷新發生在中介層內部，新 Token 透過 `Set-Cookie`（以及僅重簽時的 `X-New-Access-Token`）隨後續 handler 的回應一起送出。

## Gin

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

## net/http

```go
mux := http.NewServeMux()
mux.Handle("GET /me", auth.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	user, ok := goJwt.GetAuthDataFromHTTPRequest(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
})))
```

## Context key

`HTTPMiddleware` 以字串 `"user"` 作為 context key。若應用程式其他地方也用字串 `"user"` 存值，會互相覆蓋；一律透過 `GetAuthDataFromHTTPRequest()` 讀取，它會在型別不是 `*Auth` 時回傳 `false`。

## 依角色或範圍授權

中介層只負責身分驗證。`Auth.Role`、`Auth.Scope`、`Auth.Level` 由應用程式自行判斷：

```go
func requireScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := goJwt.GetAuthDataFromHTTPRequest(r)
		if !ok || !slices.Contains(user.Scope, scope) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

mux.Handle("POST /posts", auth.HTTPMiddleware(requireScope("write", createPost)))
```

`createPost` 為示意的應用程式 handler。
