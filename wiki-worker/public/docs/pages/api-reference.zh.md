# API 參考

`github.com/pardnchiu/go-jwt/core`（package `goJwt`）所有匯出的函式、方法與型別。

## 函式

| 簽章 | 說明 |
|---|---|
| `func New(c Config) (*JWTAuth, error)` | 套用預設值、載入或產生金鑰、連線 Redis 並 `PING`，回傳實例 |
| `func GetAuthDataFromGinContext(c *gin.Context) (*Auth, bool)` | 讀取 `GinMiddleware` 存入的使用者資料 |
| `func GetAuthDataFromHTTPRequest(r *http.Request) (*Auth, bool)` | 讀取 `HTTPMiddleware` 存入 request context 的使用者資料 |

## JWTAuth 方法

| 簽章 | 說明 |
|---|---|
| `func (j *JWTAuth) Create(w http.ResponseWriter, r *http.Request, auth *Auth) JWTAuthResult` | 簽發 Access Token 與 Refresh ID，寫入 Cookie 與 Redis；`auth` 為 `nil` 時回 `400 data_missing` |
| `func (j *JWTAuth) Verify(w http.ResponseWriter, r *http.Request) JWTAuthResult` | 驗證請求，必要時透明刷新（見 [驗證流程](/zh/verification)） |
| `func (j *JWTAuth) Revoke(w http.ResponseWriter, r *http.Request) JWTAuthResult` | 清除 Cookie、撤銷 Access Token、Refresh ID 5 秒後失效（見 [撤銷](/zh/revocation)） |
| `func (j *JWTAuth) GinMiddleware() gin.HandlerFunc` | Gin 中介層（見 [中介層](/zh/middleware)） |
| `func (j *JWTAuth) HTTPMiddleware(next http.Handler) http.Handler` | `net/http` 中介層 |
| `func (j *JWTAuth) Close() error` | 關閉 Redis 連線 |

`JWTAuth` 的欄位皆未匯出；同一個實例可在多個 goroutine 間共用。

## 設定型別

| 型別 | 說明 |
|---|---|
| `Config` | 頂層設定：`Redis`、`File`、`Option`、`Cookie`、`CheckAuth` |
| `Redis` | `Host`、`Port`、`Password`、`DB` |
| `File` | `PrivateKeyPath`、`PublicKeyPath` |
| `Option` | 金鑰內容、有效期、Cookie 名稱、`MaxVersion`、`RefreshTTL` |
| `Cookie` | `Domain`、`Path`、`SameSite`、`Secure`、`HttpOnly`（皆為指標） |

欄位與預設值見 [設定](/zh/configuration)。

## 結果與資料型別

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

| 型別 | 何時有值 |
|---|---|
| `JWTAuthResult.Data` | `Create`、`Verify` 成功時 |
| `JWTAuthResult.Token` | `Create` 成功時；`Verify` 觸發刷新並成功時 |
| `JWTAuthResult.ErrorTag` | 失敗時，值見 [狀態碼與錯誤標籤](/zh/error-codes) |

## 內部狀態型別

這些型別有匯出，但呼叫端通常不需要直接使用：

| 型別 | 說明 |
|---|---|
| `RefreshData` | Redis `refresh:<id>` 的內容：`Data`、`Version`、`Fingerprint`、`Exp`、`Iat`、`Jti`（見 [Token 模型](/zh/core-concepts)） |
| `RefreshId` | 計算 Refresh ID 雜湊的輸入：`ID`、`Name`、`Email`、`Fingerprint`、`Iat`、`Jti` |
| `Pem` | 解析後的 ECDSA 金鑰對；欄位 `private`、`public` 未匯出，無法從外部建立或讀取 |
