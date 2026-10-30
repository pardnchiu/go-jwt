# 狀態碼與錯誤標籤

所有方法以 `JWTAuthResult` 回報結果；本頁列出每個 `StatusCode` 與 `ErrorTag` 組合的觸發情境。

## 對照表

| StatusCode | ErrorTag | 來源 | 觸發情境 |
|---|---|---|---|
| `400` | `data_missing` | `Create` | `auth` 為 `nil` |
| `400` | `data_missing` | `Revoke` | 請求沒有 Refresh ID |
| `400` | `data_invalid` | `Verify` | 簽章錯誤、`nbf` 未到、`iat` 在未來 5 分鐘以上、claim 的 Refresh ID 或指紋不符、JTI 不在 Redis 或 `EXISTS jti:` 呼叫失敗 |
| `401` | `unauthorized` | `Verify` | 沒有 Access Token 也沒有 Refresh ID |
| `401` | `unauthorized` | 刷新 | Refresh ID 不存在、已過期或指紋不符 |
| `401` | `unauthorized` | `Revoke` | Refresh ID 不存在或已過期 |
| `401` | `revoked` | `Verify` | Access Token 已被撤銷 |
| `401` | （空） | 刷新 | `CheckAuth` 回傳 `false` 或 error |
| `429` | `failed_to_update` | 刷新 | 同一 Refresh ID 的刷新鎖被占用，或 `SETNX` 呼叫失敗 |
| `500` | `failed_to_create` | `Create`、刷新 | Refresh ID 或刷新資料序列化失敗 |
| `500` | `failed_to_sign` | `Create`、刷新 | JWT 簽署失敗（例如金鑰不是 P-256） |
| `500` | `failed_to_store` | `Create`、刷新、`Revoke` | Redis 寫入失敗 |
| `500` | `failed_to_get` | `Verify`、`Revoke` | Redis 讀取失敗 |

「刷新」指由 `Verify` 內部觸發的 [透明刷新](/zh/refresh)，結果經 `Verify` 回傳。

## Error 欄位

`Error` 是給人讀的訊息，內容可能包含底層錯誤字串（例如 Redis 或 JWT 函式庫的訊息），不應直接回傳給終端使用者，也不應用來做程式判斷；程式判斷一律用 `StatusCode` 與 `ErrorTag`。

中介層失敗時只回 `{"error": Error}`，不含 `ErrorTag`（見 [中介層](/zh/middleware)）。

## 依標籤處理

```go
result := auth.Verify(w, r)
if !result.Success {
	switch result.ErrorTag {
	case "revoked", "unauthorized", "":
		http.Error(w, "please sign in", http.StatusUnauthorized)
	case "failed_to_update":
		w.Header().Set("Retry-After", "1")
		http.Error(w, "retry", http.StatusTooManyRequests)
	case "data_invalid", "data_missing":
		http.Error(w, "invalid credentials", http.StatusBadRequest)
	default:
		log.Printf("go-jwt: %s", result.Error)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
	return
}
```
