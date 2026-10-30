# Getting Started

This page goes from install to a working protected route: start Redis, create `JWTAuth`, log in, access, log out.

## Prerequisites

| Item | Version |
|---|---|
| Go | 1.24 or higher (`go.mod` declares `go 1.24.3`) |
| Redis | Any version supporting `SETEX`/`SETNX`/`EVAL`/`MULTI` (CI uses `redis:7-alpine`) |
| Gin | Only when using `GinMiddleware()` |

## Installation

```bash
go get github.com/pardnchiu/go-jwt@latest
```

The package lives in the `core/` subdirectory with package name `goJwt`. Since v1.0.3 the import path is `github.com/pardnchiu/go-jwt/core`; see [Removed API](/removed-api) for the old-path symbol mapping.

```go
import goJwt "github.com/pardnchiu/go-jwt/core"
```

## Start Redis

```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

## First Server

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
		log.Fatalf("failed to init go-jwt: %v", err)
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

On first start, when no keys are configured and no PEM files exist under `./keys/`, `New()` generates a P-256 key pair into `./keys/private-key.pem` and `./keys/public-key.pem` (relative to the working directory). See [Key Management](/key-management).

## Try the Flow

Use a cookie jar to mimic a browser. The User-Agent must be a recognizable browser string, or send a stable `X-Device-FP`; otherwise the fingerprint changes on every request (see [Device Fingerprint](/device-fingerprint)):

```bash
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"

# Login: the response sets access_token, refresh_id, and conn.device.id cookies
curl -s -A "$UA" -c jar.txt -b jar.txt -X POST http://localhost:8080/login

# Access the protected route
curl -s -A "$UA" -c jar.txt -b jar.txt http://localhost:8080/me

# Logout: clears cookies and revokes the Access Token
curl -s -A "$UA" -c jar.txt -b jar.txt -X POST http://localhost:8080/logout -o /dev/null -w "%{http_code}\n"
```

## Next Steps

| Goal | Page |
|---|---|
| Understand Access Token, Refresh ID, and JTI | [Token Model](/core-concepts) |
| Tune lifetimes and cookie attributes | [Configuration](/configuration) |
| Use Gin | [Middleware](/middleware) |
| Serve mobile apps or API clients | [Client Integration](/client-integration) |
