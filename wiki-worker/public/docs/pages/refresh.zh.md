# 透明刷新

Access Token 過期或缺少時，`Verify()` 會以 Refresh ID 自動換發，呼叫端與使用者都不需要額外處理；本頁說明換發的條件、兩種結果與並行行為。

## 觸發條件

- 請求沒有 Access Token 但有 Refresh ID
- Access Token 驗章時回報過期

## 流程

| # | 步驟 | 失敗時 |
|---|---|---|
| 1 | 讀取 `refresh:<id>` 與其 TTL，比對 `fp` 與本次指紋 | `401 unauthorized` |
| 2 | `SETNX lock:refresh:<id>`，鎖 3 秒 | `429 failed_to_update` |
| 3 | 呼叫 `CheckAuth(Auth)`（有設定時） | 回傳 `false` 或 error → `401`（`ErrorTag` 為空） |
| 4 | 判斷是否超過閾值，決定僅重簽或整組重發 | — |
| 5 | 以 Lua 比對鎖值後 `DEL` 鎖（`defer`，任何結果都會執行） | — |

## 兩種結果

| 條件 | 結果 | 新 Token 的下發方式 |
|---|---|---|
| `version ≤ MaxVersion` 且剩餘 TTL ≥ `RefreshIdExpires × RefreshTTL` | **僅重簽 Access Token**：沿用 Refresh ID，`version + 1`，新 JTI；`refresh:<id>` 保留原剩餘 TTL | `X-New-Access-Token` header ＋ `Set-Cookie: access_token` |
| `version > MaxVersion`，或剩餘 TTL 低於閾值 | **整組重發**：舊 `refresh:<id>` TTL 縮為 3 秒，再呼叫 `Create()` 產生新 Refresh ID 與 Access Token | 只有 `Set-Cookie: access_token` 與 `refresh_id`，**不設** `X-New-Access-Token` |

以預設值 `MaxVersion = 5` 為例：登入時 `version = 1`，前 5 次刷新僅重簽，第 6 次刷新整組重發。僅重簽不會延長 Refresh ID 的 TTL，所以長時間使用的工作階段最終一定會因 TTL 閾值觸發整組重發。

## 並行請求

同一個 Refresh ID 同時只有一個請求能持有刷新鎖，鎖被占用期間抵達的請求回 `429`。鎖在刷新完成後立即釋放，因此同時送出的多個請求中，可能有不只一個成功刷新，其餘收到 429。前端收到 429 時應稍候重送：重送時帶的是剛更新的 Cookie，會直接通過驗證。

## CheckAuth

`CheckAuth` 在每次刷新都會呼叫（包含僅重簽），適合確認使用者是否被停權或刪除；一般請求的驗證不會呼叫它。

```go
auth, err := goJwt.New(goJwt.Config{
	Redis: goJwt.Redis{Host: "localhost", Port: 6379},
	CheckAuth: func(a goJwt.Auth) (bool, error) {
		active, err := userRepo.IsActive(context.Background(), a.ID)
		if err != nil {
			return false, fmt.Errorf("check user %s: %w", a.ID, err)
		}
		return active, nil
	},
})
```

`userRepo` 為示意的應用程式資料層。

## 相關設定

| 欄位 | 預設 | 影響 |
|---|---|---|
| `MaxVersion` | `5` | 僅重簽的次數上限 |
| `RefreshTTL` | `0.5` | 剩餘 TTL 低於 `RefreshIdExpires × RefreshTTL` 時整組重發 |
| `RefreshIdExpires` | 7 天 | 整組重發時新 Refresh ID 的 TTL |

完整欄位見 [設定](/zh/configuration)。
