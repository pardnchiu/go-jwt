# Token 模型

go-jwt 以三種憑證管理一個登入工作階段（Session）：短效的 Access Token、長效的 Refresh ID，以及存在 Redis 的 JTI 白名單。

## 三種憑證

| 憑證 | 形式 | 預設有效期 | 存放位置 | 用途 |
|---|---|---|---|---|
| Access Token | ES256 簽章的 JWT | 15 分鐘（`AccessTokenExpires`） | Cookie `access_token`，或 `Authorization: Bearer` | 每次請求驗證身分 |
| Refresh ID | 64 字元十六進位字串（SHA-256） | 7 天（`RefreshIdExpires`） | Cookie `refresh_id`，或 `X-Refresh-ID` header | Access Token 過期時換發新 Token |
| JTI | UUID v4 | 與 Access Token 相同 | Redis `jti:<jti>` | 讓已簽發的 Access Token 可被伺服器端作廢 |

Refresh ID 本身不帶資料，它是 Redis `refresh:<id>` 的鍵；使用者資料、版本號與裝置指紋都存在伺服器端的 `RefreshData`。

## Access Token claims

`signJWT()` 寫入的 claims：

| Claim | 來源 |
|---|---|
| `id`、`name`、`email`、`thumbnail`、`scope`、`role`、`level` | `Auth` 各欄位 |
| `fp` | 本次請求的裝置指紋 |
| `jti` | 新產生的 UUID |
| `exp` | 簽發時間 ＋ `AccessTokenExpires` |
| `iat`、`nbf` | 簽發時間 |
| `refresh_id`（名稱取自 `RefreshIdCookieKey`） | 綁定的 Refresh ID |

JWT 只做簽章不加密，`Auth` 的所有欄位都能被持有者解碼讀取，不要放敏感資料。

## Refresh ID 的產生

`createRefreshId()` 把 `{id, name, email, fp, iat, jti}` 序列化成 JSON 後取 SHA-256，輸出十六進位字串。因為含 `jti` 與當下時間，同一使用者每次登入都會得到不同的 Refresh ID。

## RefreshData

Redis `refresh:<id>` 的值：

| 欄位 | 說明 |
|---|---|
| `data` | `Auth` |
| `version` | 簽發時為 1，每次刷新加 1；超過 `MaxVersion` 時整組重發 |
| `fp` | 簽發時的裝置指紋；刷新時必須相符 |
| `exp`、`iat` | 首次簽發時的時間，刷新時沿用不更新 |
| `jti` | 最近一次簽發的 JTI |

## 一次工作階段的生命週期

| 階段 | 觸發 | 頁面 |
|---|---|---|
| 簽發 | 應用程式呼叫 `Create()` | [API 參考](/zh/api-reference) |
| 驗證 | 每次請求，`Verify()` 或中介層 | [驗證流程](/zh/verification) |
| 刷新 | Access Token 過期或缺少、Refresh ID 仍有效 | [透明刷新](/zh/refresh) |
| 撤銷 | 應用程式呼叫 `Revoke()` | [撤銷](/zh/revocation) |
