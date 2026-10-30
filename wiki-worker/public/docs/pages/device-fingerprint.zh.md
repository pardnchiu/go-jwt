# 裝置指紋

每個請求都會算出一個裝置指紋（Device Fingerprint），Access Token 與 Refresh ID 簽發時寫入該值，之後每次驗證與刷新都必須相符，被竊的 Token 換到其他裝置即失效。

## 計算方式

`getFingerprint()` 依序判斷：

| # | 來源 | 結果 |
|---|---|---|
| 1 | Header `X-Device-FP` 有值 | 直接當作指紋，略過以下步驟 |
| 2 | 裝置 ID：Header `X-Device-ID` → Cookie `conn.device.id` → 新產生的 UUID | 寫回 Cookie `conn.device.id`（90 天） |
| 3 | 由 User-Agent 推算 OS、瀏覽器、裝置類型 | 見下表 |
| 4 | `{os, browser, device, deviceId}` 的 JSON 取 SHA-256 | 64 字元十六進位指紋 |

## User-Agent 對應

| 欄位 | 可辨識值 | 判斷依據 |
|---|---|---|
| OS | `Windows`、`MacOS`、`Linux`、`Android`、`iOS` | UA 含 `Windows`／`Macintosh`、`Mac OS X`／`Linux`／`Android`／`iPhone`、`iPad`、`iPod` |
| 瀏覽器 | `Edge`、`Opera`、`Chrome`、`Firefox`、`Safari` | UA 含 `Edge`、`Edg`／`Opera`、`OPR`／`Chrome`／`Firefox`／`Safari`（且不含 `Chrome`） |
| 裝置 | `Tablet`、`Mobile`、`Desktop` | `iPad` → Tablet；`iPhone`、`iPod`、`Android`＋`Mobile`、`BlackBerry`、`IEMobile`、`Opera Mini` → Mobile；其餘 Desktop |

判斷以 `switch` 由上而下比對，第一個符合即採用。因此 Android 的 UA（含 `Linux; Android`）OS 判為 `Linux`；iPhone／iPad 的 UA（含 `like Mac OS X`）OS 判為 `MacOS`，`Android`、`iOS` 兩個分支實際上不會命中。指紋仍然穩定，只是 OS 欄位不精確。

## 無法辨識的 User-Agent

OS 或瀏覽器任一項對不到時，對不到的欄位為**每次請求新產生的 UUID**，指紋因此每次都不同，驗證必定失敗（`400 data_invalid`，訊息 `fingerprint does not match`）。curl、行動 App 的 HTTP 函式庫、伺服器間呼叫都屬這種情況，必須帶固定的 `X-Device-FP`。

```bash
# 失敗：curl 的 UA 無法辨識，兩次請求指紋不同
curl -s -c jar.txt -b jar.txt -X POST http://localhost:8080/login
curl -s -c jar.txt -b jar.txt http://localhost:8080/me

# 成功：帶固定指紋
curl -s -H "X-Device-FP: device-7f3a9c" -c jar.txt -b jar.txt -X POST http://localhost:8080/login
curl -s -H "X-Device-FP: device-7f3a9c" -c jar.txt -b jar.txt http://localhost:8080/me
```

## X-Test-Mode

請求帶 `X-Test-Mode: true` 時，無法辨識的 OS／瀏覽器改用固定字串 `TestOS`／`TestBrowser`，指紋因此穩定。這是測試用途的 header，任何客戶端都能送出，指紋綁定的強度不應建立在它不被使用的前提上。

## 安全性取捨

| 指紋來源 | 綁定強度 |
|---|---|
| 瀏覽器 UA ＋ `conn.device.id` Cookie | Cookie 與 Token 一起被竊時可重放；換瀏覽器或清 Cookie 即需重新登入 |
| 客戶端自帶 `X-Device-FP` | 強度取決於客戶端如何產生並保存該值；伺服器端不驗證來源 |

非瀏覽器客戶端的完整串接方式見 [客戶端整合](/zh/client-integration)。
