# 客戶端整合

本頁列出客戶端要送哪些 Cookie／header、會收到哪些回應，以及瀏覽器與非瀏覽器客戶端各自的串接方式。

## 請求輸入

| 來源 | 名稱 | 用途 |
|---|---|---|
| Cookie | `access_token`（`AccessTokenCookieKey`） | Access Token，優先於 Authorization header |
| Header | `Authorization: Bearer <token>` | Access Token（無 Cookie 時） |
| Header | `X-Refresh-ID` | Refresh ID，優先於 Cookie |
| Cookie | `refresh_id`（`RefreshIdCookieKey`） | Refresh ID |
| Header | `X-Device-FP` | 直接指定裝置指紋 |
| Header | `X-Device-ID` | 裝置 ID，優先於 Cookie |
| Cookie | `conn.device.id` | 裝置 ID |

## 回應輸出

| 時機 | `Set-Cookie` | Header |
|---|---|---|
| `Create()` 登入 | `access_token`、`refresh_id`、`conn.device.id` | — |
| 刷新：僅重簽 | `access_token` | `X-New-Access-Token` |
| 刷新：整組重發 | `access_token`、`refresh_id` | — |
| `Revoke()` | 清除 `access_token`、`refresh_id` | — |
| 每次計算指紋（未帶 `X-Device-FP`） | `conn.device.id`（90 天） | — |

Cookie 預設 HttpOnly、`http.SameSiteLaxMode`、Path `/`、非 Secure，可由 [設定](/zh/configuration) 的 `Cookie` 覆寫。

## 瀏覽器

同網域的網頁不需要任何額外處理：Cookie 自動帶上與更新，刷新對前端透明。需要注意：

| 情境 | 處理 |
|---|---|
| 跨網域 API | 前端以 `credentials: "include"` 送出；後端 CORS 允許 credentials，Cookie 設 `http.SameSiteNoneMode` 與 Secure |
| Access Token 過期時同時送出多個請求 | 部分請求會收到 `429`，稍候重送即可（見 [透明刷新](/zh/refresh)） |
| 正式環境 | `Cookie.Secure` 設為 `true` |

```javascript
async function api(path, init = {}) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await fetch(path, { ...init, credentials: "include" });
    if (res.status !== 429) return res;
    await new Promise(r => setTimeout(r, 300));
  }
  throw new Error(`refresh contention on ${path}`);
}
```

## 非瀏覽器客戶端（行動 App、CLI、服務）

| 要求 | 原因 |
|---|---|
| 每個裝置產生一個固定值，每次請求帶 `X-Device-FP` | UA 無法辨識時指紋每次都不同（見 [裝置指紋](/zh/device-fingerprint)） |
| 同時送 Access Token 與 Refresh ID | 驗證會比對 Token 內的 Refresh ID（見 [驗證流程](/zh/verification) 第 7 步） |
| 解析每個回應的 `Set-Cookie` | 整組重發時新的 Refresh ID **只**出現在 `Set-Cookie: refresh_id`，沒有對應 header |
| 收到 `X-New-Access-Token` 時更新本地 Access Token | 僅重簽時的新 Token |

使用支援 Cookie 的 HTTP client（例如 Go 的 `net/http/cookiejar`、OkHttp 的 cookie jar）並讓它保存 `access_token`／`refresh_id`，是最不容易漏掉整組重發的作法。

```bash
# 登入
curl -s -H "X-Device-FP: device-7f3a9c" -c jar.txt -b jar.txt -X POST http://localhost:8080/login

# 之後每次請求都帶同一指紋，並把回應的 Cookie 寫回 jar
curl -s -H "X-Device-FP: device-7f3a9c" -c jar.txt -b jar.txt http://localhost:8080/me -D -
```

以 header 傳遞時：

```bash
curl -s http://localhost:8080/me \
  -H "X-Device-FP: device-7f3a9c" \
  -H "Authorization: Bearer <token>" \
  -H "X-Refresh-ID: <refresh_id>" \
  -D -
```

## 錯誤處理建議

| 狀態碼 | 客戶端動作 |
|---|---|
| `401` | 導向登入 |
| `429` | 稍候重送 |
| `400` | 憑證與裝置不符或格式錯誤；清除本地憑證後重新登入 |
| `5xx` | 伺服器或 Redis 異常，可重試 |

完整對照見 [狀態碼與錯誤標籤](/zh/error-codes)。
