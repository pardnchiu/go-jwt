# Redis Keys

go-jwt uses four kinds of Redis keys; this page lists each key's value and TTL and how every operation reads and writes them.

## Keys

| Key | Value | TTL | Purpose |
|---|---|---|---|
| `refresh:<refreshID>` | `RefreshData` JSON | `RefreshIdExpires`; re-sign only keeps the remaining TTL | Session data |
| `jti:<jti>` | `"1"` | `AccessTokenExpires` | Access Token whitelist |
| `lock:refresh:<refreshID>` | Lock holder UUID | 3 seconds | Refresh mutex |
| `revoke:<accessToken>` | `"1"` | `AccessTokenExpires` | Revocation record |

Key names are fixed. When several applications share one Redis, separate them with `Config.Redis.DB` to avoid collisions on names like `refresh:` and `lock:`.

## Reads and Writes per Operation

| Operation | Reads | Writes |
|---|---|---|
| `Create` | — | `MULTI`: `SETEX refresh:<id>`, `SETEX jti:<jti>` |
| `Verify` | `GET revoke:<token>`, `EXISTS jti:<jti>` | — |
| Refresh: re-sign only | `GET` + `TTL refresh:<id>` | `SETNX lock:`; `MULTI`: `SETEX refresh:<id>` (remaining TTL), `SETEX jti:<new jti>`; `EVAL` unlock |
| Refresh: full reissue | `GET` + `TTL refresh:<id>` | `SETNX lock:`; `SETEX refresh:<old id>` 3 seconds; then `Create`'s writes; `EVAL` unlock |
| `Revoke` | `GET` + `TTL refresh:<id>` | `MULTI`: `SETEX refresh:<id>` 5 seconds, `SETEX revoke:<token>` |

## Capacity

Each active session holds at least one `refresh:` entry plus one or more `jti:` entries within the Access Token lifetime (re-signing creates a new JTI and leaves the old one to expire by TTL). A `revoke:` key contains the full JWT string, a few hundred bytes each, one per logout within the lifetime.

## Unlock Script

```lua
if redis.call("get", KEYS[1]) == ARGV[1] then
	return redis.call("del", KEYS[1])
else
	return 0
end
```

It deletes the lock only when the value equals its own UUID, so a refresh running past 3 seconds never deletes a lock another request has since acquired.
