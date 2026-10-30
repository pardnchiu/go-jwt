# 撤銷

`Revoke()` 實作登出：清除 Cookie、讓目前的 Access Token 立即失效，並讓 Refresh ID 在 5 秒後失效。

## 流程

| # | 步驟 | 失敗時 |
|---|---|---|
| 1 | 送出清除 `access_token` 與 `refresh_id` Cookie 的 `Set-Cookie`（不論後續成敗） | — |
| 2 | 取得 Refresh ID | 無 → `400 data_missing` |
| 3 | 讀取 `refresh:<id>` | 不存在 → `401 unauthorized`；Redis 錯誤 → `500 failed_to_get` |
| 4 | 讀取 TTL | `TTL ≤ 0` → `401 unauthorized` |
| 5 | `MULTI`：`refresh:<id>` TTL 改為 5 秒、寫入 `revoke:<accessToken>`（TTL `AccessTokenExpires`） | `500 failed_to_store` |

成功時回傳 `200`，`Success` 為 `true`。

## 範例

```go
mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
	result := auth.Revoke(w, r)
	if !result.Success && result.StatusCode >= 500 {
		http.Error(w, result.Error, result.StatusCode)
		return
	}
	w.WriteHeader(http.StatusNoContent)
})
```

`400`／`401` 代表工作階段已不存在，Cookie 也已清除，對使用者而言等同已登出，上例因此只把 5xx 當成錯誤。

## 邊界

| 情境 | 行為 |
|---|---|
| Refresh ID 保留 5 秒 | 撤銷後 5 秒內，帶同一 Refresh ID（例如透過 `X-Refresh-ID`）且沒有 Access Token 的請求仍可刷新成功 |
| 撤銷範圍 | 只作廢請求中的那一個 Access Token；同一使用者在其他裝置的工作階段不受影響 |
| 未帶 Access Token | 仍會寫入 `revoke:`（鍵為空字串），Refresh ID 照常失效 |
| 重複登出 | 第二次因 Cookie 已清除而回 `400 data_missing` |

撤銷後的驗證結果見 [驗證流程](/zh/verification) 第 2 步。
