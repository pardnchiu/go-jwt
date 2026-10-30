# Removed API

This page lists public symbols removed or renamed across versions, with the removal version and the replacement, for use while upgrading.

## v1.0.3: Import Path Moved to `core/`

v1.0.3 moved the implementation into the `core/` subpackage; the root package `github.com/pardnchiu/go-jwt` exports nothing. Symbol names and behavior are unchanged; only the import path changes:

```go
// Old
import goJwt "github.com/pardnchiu/go-jwt"
// New
import goJwt "github.com/pardnchiu/go-jwt/core"
```

| Symbol | Package | Status | Last present | Replacement |
|---|---|---|---|---|
| `Auth`, `Config`, `Cookie`, `File`, `JWTAuth`, `JWTAuthResult`, `Option`, `Pem`, `Redis`, `RefreshData`, `RefreshId`, `TokenResult` | `go-jwt` | Removed in v1.0.3 | v1.0.2 | Same-named types in `core` |
| `New`, `GetAuthDataFromGinContext`, `GetAuthDataFromHTTPRequest` | `go-jwt` | Removed in v1.0.3 | v1.0.2 | Same-named functions in `core` |
| `JWTAuth.Close`, `JWTAuth.Create`, `JWTAuth.GinMiddleware`, `JWTAuth.HTTPMiddleware`, `JWTAuth.Revoke`, `JWTAuth.Verify` | `go-jwt` | Removed in v1.0.3 | v1.0.2 | Same-named methods in `core` |

## v1.0.1: Logging Moved to log/slog

| Symbol | Package | Status | Last present | Replacement |
|---|---|---|---|---|
| `Log` | `go-jwt` | Removed in v1.0.1 | v1.0.0 | No public replacement; logging goes through internal `log/slog` to syslog |
| `Logger` | `go-jwt` | Removed in v1.0.1 | v1.0.0 | No public replacement |

## v0.6.1: Logging Moved to go-logger

| Symbol | Package | Status | Last present | Replacement |
|---|---|---|---|---|
| `LoggerConfig` | `go-jwt` | Removed in v0.6.1 | v0.6.0 | No public replacement |
| `Logger.Close`, `Logger.Critical`, `Logger.Debug`, `Logger.Error`, `Logger.Fatal`, `Logger.Flush`, `Logger.Info`, `Logger.Notice`, `Logger.Trace`, `Logger.Warning` | `go-jwt` | Removed in v0.6.1 | v0.6.0 | No public replacement |

## v0.6.0: Configuration Restructure

| Symbol | Package | Status | Last present | Replacement |
|---|---|---|---|---|
| `AuthData` | `go-jwt` | Removed in v0.6.0 | v0.5.0 | `Auth` |
| `AuthResult` | `go-jwt` | Removed in v0.6.0 | v0.5.0 | `JWTAuthResult` |
| `RedisConfig` | `go-jwt` | Removed in v0.6.0 | v0.5.0 | `Redis` |
| `RefreshID` | `go-jwt` | Removed in v0.6.0 | v0.5.0 | `RefreshId` |
| `JWTAuth.Refresh` | `go-jwt` | Removed in v0.6.0 | v0.5.0 | Triggered automatically by `Verify` (see [Transparent Refresh](/refresh)) |

## v0.5.0: Logger API Changes

| Symbol | Package | Status | Last present | Replacement |
|---|---|---|---|---|
| `NewLogger` | `go-jwt` | Removed in v0.5.0 | v0.4.0 | No public replacement |
| `Logger.Create`, `Logger.Init`, `Logger.Refresh`, `Logger.Verify` | `go-jwt` | Removed in v0.5.0 | v0.4.0 | No public replacement |

## v0.4.0: Internal Methods Unexported

| Symbol | Package | Status | Last present | Replacement |
|---|---|---|---|---|
| `JWTAuth.ClearCookie`, `JWTAuth.SetCookie` | `go-jwt` | Removed in v0.4.0 | v0.3.0 | Handled inside `Create`/`Revoke`; set cookie attributes via `Config.Cookie` |
| `JWTAuth.CreateRefreshId`, `JWTAuth.GetRefreshData`, `JWTAuth.GetRefreshId` | `go-jwt` | Removed in v0.4.0 | v0.3.0 | No public replacement |
| `JWTAuth.GetAccessToken`, `JWTAuth.GetFingerprint`, `JWTAuth.GetUserData` | `go-jwt` | Removed in v0.4.0 | v0.3.0 | No public replacement; user data comes from `Data` returned by `Verify` |
