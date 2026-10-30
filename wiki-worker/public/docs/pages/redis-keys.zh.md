# Redis Key

go-jwt 在 Redis 中使用四種 key；本頁列出每種 key 的值、TTL，以及各操作如何讀寫它們。

## Key 一覽

| Key | 值 | TTL | 用途 |
|---|---|---|---|
| `refresh:<refreshID>` | `RefreshData` JSON | `RefreshIdExpires`；僅重簽時保留剩餘 TTL | 工作階段資料 |
| `jti:<jti>` | `"1"` | `AccessTokenExpires` | Access Token 白名單 |
| `lock:refresh:<refreshID>` | 鎖持有者 UUID | 3 秒 | 刷新互斥鎖 |
| `revoke:<accessToken>` | `"1"` | `AccessTokenExpires` | 撤銷紀錄 |

Key 名稱固定。多個應用程式共用同一個 Redis DB 時，以 `Config.Redis.DB` 分開，避免 `refresh:`、`lock:` 等名稱衝突。

## 各操作的讀寫

| 操作 | 讀 | 寫 |
|---|---|---|
| `Create` | — | `MULTI`：`SETEX refresh:<id>`、`SETEX jti:<jti>` |
| `Verify` | `GET revoke:<token>`、`EXISTS jti:<jti>` | — |
| 刷新：僅重簽 | `GET`＋`TTL refresh:<id>` | `SETNX lock:`；`MULTI`：`SETEX refresh:<id>`（剩餘 TTL）、`SETEX jti:<新 jti>`；`EVAL` 解鎖 |
| 刷新：整組重發 | `GET`＋`TTL refresh:<id>` | `SETNX lock:`；`SETEX refresh:<舊 id>` 3 秒；再執行 `Create` 的寫入；`EVAL` 解鎖 |
| `Revoke` | `GET`＋`TTL refresh:<id>` | `MULTI`：`SETEX refresh:<id>` 5 秒、`SETEX revoke:<token>` |

## 容量估算

每個登入中的工作階段至少佔一筆 `refresh:`，加上 Access Token 有效期內的 `jti:` 一到數筆（僅重簽產生新 JTI 時舊的不會刪除，等 TTL 自然過期）。`revoke:` 的鍵含完整 JWT 字串，每筆約數百位元組，數量等於有效期內的登出次數。

## 解鎖腳本

```lua
if redis.call("get", KEYS[1]) == ARGV[1] then
	return redis.call("del", KEYS[1])
else
	return 0
end
```

只有鎖值等於自己的 UUID 時才刪除，避免刷新超過 3 秒、鎖已被其他請求取得時誤刪別人的鎖。
