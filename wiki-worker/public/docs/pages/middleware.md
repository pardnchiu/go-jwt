# Middleware

go-jwt ships Gin and `net/http` middleware; both verify the request with `Verify()` and hand `*Auth` to the next handler on success.

## Behavior

| Item | `GinMiddleware()` | `HTTPMiddleware(next)` |
|---|---|---|
| Verification | `Verify(c.Writer, c.Request)` | `Verify(w, r)` |
| Failure response | `c.JSON(StatusCode, {"error": ...})` then `c.Abort()` | `Content-Type: application/json`, `StatusCode`, `{"error": ...}`; `next` is not called |
| Stored on success | `c.Set("user", *Auth)` | `context.WithValue(r.Context(), "user", *Auth)` |
| Read back | `GetAuthDataFromGinContext(c)` | `GetAuthDataFromHTTPRequest(r)` |

The failure response carries only `error`, not `ErrorTag`; to branch on the error type, call `Verify()` directly in your own handler.

Refresh happens inside the middleware; new tokens leave with the downstream handler's response via `Set-Cookie` (plus `X-New-Access-Token` on re-sign only).

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
		log.Fatalf("failed to init go-jwt: %v", err)
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

## Context Key

`HTTPMiddleware` uses the plain string `"user"` as the context key. Anything else in the application that stores a value under the string `"user"` collides with it; always read through `GetAuthDataFromHTTPRequest()`, which returns `false` when the value is not `*Auth`.

## Authorizing by Role or Scope

The middleware only authenticates. `Auth.Role`, `Auth.Scope`, and `Auth.Level` are checked by the application:

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

`createPost` stands for your application's handler.
