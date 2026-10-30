# 驗證流程

本頁說明 `Verify()` 對一個請求依序做的檢查，以及每一步失敗時的回應。

## 取得憑證

| 憑證 | 讀取順序 |
|---|---|
| Access Token | 1. Cookie `access_token`（`AccessTokenCookieKey`） 2. `Authorization: Bearer <token>` |
| Refresh ID | 1. Header `X-Refresh-ID` 2. Cookie `refresh_id`（`RefreshIdCookieKey`） |
| 裝置指紋 | 見 [裝置指紋](/zh/device-fingerprint) |

## 檢查順序

| # | 檢查 | 失敗時 |
|---|---|---|
| 1 | 有 Access Token | 有 Refresh ID → 進入 [透明刷新](/zh/refresh)；兩者皆無 → `401 unauthorized` |
| 2 | Redis `revoke:<accessToken>` 不存在 | 存在 → `401 revoked`；Redis 錯誤 → `500 failed_to_get` |
| 3 | 簽章演算法為 ECDSA 且以公鑰驗章通過 | `400 data_invalid` |
| 4 | 未過期（`exp`） | 過期 → 進入 [透明刷新](/zh/refresh) |
| 5 | `nbf` 不晚於現在 | `400 data_invalid` |
| 6 | `iat` 不超過現在 5 分鐘以上 | `400 data_invalid` |
| 7 | claim `refresh_id` 等於請求帶的 Refresh ID | `400 data_invalid` |
| 8 | claim `fp` 等於本次指紋 | `400 data_invalid` |
| 9 | Redis `jti:<jti>` 存在 | `400 data_invalid` |

全部通過時回傳 `200`，`Data` 為由 claims 還原的 `Auth`。

## 行為重點

- **Access Token 必須搭配 Refresh ID**：第 7 步要求 claim 內的 Refresh ID 與請求相符，只帶 `Authorization` 不帶 Refresh ID 的請求會失敗。
- **過期判斷優先於其他錯誤**：簽章驗證錯誤訊息含 `expired` 時一律走刷新，不回 400。
- **撤銷檢查以 Access Token 字串為鍵**：撤銷的是那一個 Token，不是使用者。

## 範例

```go
result := auth.Verify(w, r)
switch {
case result.Success:
	log.Printf("user %s", result.Data.ID)
case result.ErrorTag == "revoked":
	http.Error(w, "session revoked", result.StatusCode)
default:
	http.Error(w, result.Error, result.StatusCode)
}
```

`Verify` 可能寫入 Cookie 與 header（刷新時），必須在寫入回應主體之前呼叫。完整錯誤對照見 [狀態碼與錯誤標籤](/zh/error-codes)。
