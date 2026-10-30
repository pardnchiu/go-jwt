# 已移除 API

本頁列出歷次版本移除或改名的公開符號、移除版本與替代做法，供升級時對照。

## v1.0.3：匯入路徑移至 `core/`

v1.0.3 把所有實作搬到 `core/` 子套件，根套件 `github.com/pardnchiu/go-jwt` 不再匯出任何符號。符號名稱與行為不變，只需改匯入路徑：

```go
// 舊
import goJwt "github.com/pardnchiu/go-jwt"
// 新
import goJwt "github.com/pardnchiu/go-jwt/core"
```

| 符號 | 套件 | 狀態 | 最後存在版本 | 替代 |
|---|---|---|---|---|
| `Auth`、`Config`、`Cookie`、`File`、`JWTAuth`、`JWTAuthResult`、`Option`、`Pem`、`Redis`、`RefreshData`、`RefreshId`、`TokenResult` | `go-jwt` | 移除於 v1.0.3 | v1.0.2 | `core` 同名型別 |
| `New`、`GetAuthDataFromGinContext`、`GetAuthDataFromHTTPRequest` | `go-jwt` | 移除於 v1.0.3 | v1.0.2 | `core` 同名函式 |
| `JWTAuth.Close`、`JWTAuth.Create`、`JWTAuth.GinMiddleware`、`JWTAuth.HTTPMiddleware`、`JWTAuth.Revoke`、`JWTAuth.Verify` | `go-jwt` | 移除於 v1.0.3 | v1.0.2 | `core` 同名方法 |

## v1.0.1：日誌改用 log/slog

| 符號 | 套件 | 狀態 | 最後存在版本 | 替代 |
|---|---|---|---|---|
| `Log` | `go-jwt` | 移除於 v1.0.1 | v1.0.0 | 無公開替代；日誌改由內部 `log/slog` 輸出至 syslog |
| `Logger` | `go-jwt` | 移除於 v1.0.1 | v1.0.0 | 無公開替代 |

## v0.6.1：日誌改用 go-logger

| 符號 | 套件 | 狀態 | 最後存在版本 | 替代 |
|---|---|---|---|---|
| `LoggerConfig` | `go-jwt` | 移除於 v0.6.1 | v0.6.0 | 無公開替代 |
| `Logger.Close`、`Logger.Critical`、`Logger.Debug`、`Logger.Error`、`Logger.Fatal`、`Logger.Flush`、`Logger.Info`、`Logger.Notice`、`Logger.Trace`、`Logger.Warning` | `go-jwt` | 移除於 v0.6.1 | v0.6.0 | 無公開替代 |

## v0.6.0：設定結構重整

| 符號 | 套件 | 狀態 | 最後存在版本 | 替代 |
|---|---|---|---|---|
| `AuthData` | `go-jwt` | 移除於 v0.6.0 | v0.5.0 | `Auth` |
| `AuthResult` | `go-jwt` | 移除於 v0.6.0 | v0.5.0 | `JWTAuthResult` |
| `RedisConfig` | `go-jwt` | 移除於 v0.6.0 | v0.5.0 | `Redis` |
| `RefreshID` | `go-jwt` | 移除於 v0.6.0 | v0.5.0 | `RefreshId` |
| `JWTAuth.Refresh` | `go-jwt` | 移除於 v0.6.0 | v0.5.0 | 由 `Verify` 自動觸發（見 [透明刷新](/zh/refresh)） |

## v0.5.0：日誌 API 調整

| 符號 | 套件 | 狀態 | 最後存在版本 | 替代 |
|---|---|---|---|---|
| `NewLogger` | `go-jwt` | 移除於 v0.5.0 | v0.4.0 | 無公開替代 |
| `Logger.Create`、`Logger.Init`、`Logger.Refresh`、`Logger.Verify` | `go-jwt` | 移除於 v0.5.0 | v0.4.0 | 無公開替代 |

## v0.4.0：內部方法改為未匯出

| 符號 | 套件 | 狀態 | 最後存在版本 | 替代 |
|---|---|---|---|---|
| `JWTAuth.ClearCookie`、`JWTAuth.SetCookie` | `go-jwt` | 移除於 v0.4.0 | v0.3.0 | 由 `Create`／`Revoke` 內部處理，Cookie 屬性改用 `Config.Cookie` |
| `JWTAuth.CreateRefreshId`、`JWTAuth.GetRefreshData`、`JWTAuth.GetRefreshId` | `go-jwt` | 移除於 v0.4.0 | v0.3.0 | 無公開替代 |
| `JWTAuth.GetAccessToken`、`JWTAuth.GetFingerprint`、`JWTAuth.GetUserData` | `go-jwt` | 移除於 v0.4.0 | v0.3.0 | 無公開替代；使用者資料以 `Verify` 回傳的 `Data` 取得 |
