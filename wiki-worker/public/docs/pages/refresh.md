# Transparent Refresh

When the Access Token is expired or missing, `Verify()` reissues it from the Refresh ID without any work from the caller or the user; this page covers when that happens, the two outcomes, and concurrent behavior.

## Triggers

- The request has no Access Token but has a Refresh ID
- Signature verification reports the Access Token as expired

## Flow

| # | Step | On failure |
|---|---|---|
| 1 | Read `refresh:<id>` and its TTL; compare `fp` with this request's fingerprint | `401 unauthorized` |
| 2 | `SETNX lock:refresh:<id>` with a 3-second lock | `429 failed_to_update` |
| 3 | Call `CheckAuth(Auth)` when configured | Returns `false` or an error → `401` (empty `ErrorTag`) |
| 4 | Compare against thresholds; re-sign only or reissue the full pair | — |
| 5 | `DEL` the lock after a Lua value check (`defer`, runs on every outcome) | — |

## Two Outcomes

| Condition | Result | How new tokens are delivered |
|---|---|---|
| `version ≤ MaxVersion` and remaining TTL ≥ `RefreshIdExpires × RefreshTTL` | **Re-sign the Access Token only**: keep the Refresh ID, `version + 1`, new JTI; `refresh:<id>` keeps its remaining TTL | `X-New-Access-Token` header + `Set-Cookie: access_token` |
| `version > MaxVersion`, or remaining TTL below the threshold | **Full reissue**: shrink the old `refresh:<id>` TTL to 3 seconds, then call `Create()` for a new Refresh ID and Access Token | Only `Set-Cookie: access_token` and `refresh_id`; `X-New-Access-Token` is **not** set |

With the default `MaxVersion = 5`: login sets `version = 1`, the first 5 refreshes only re-sign, and the 6th refresh reissues the full pair. Re-signing never extends the Refresh ID TTL, so a long-running session eventually reaches the TTL threshold and gets a full reissue.

## Concurrent Requests

Only one request at a time can hold the refresh lock for a given Refresh ID; requests arriving while it is held get `429`. The lock is released as soon as the refresh finishes, so among several simultaneous requests more than one may refresh successfully and the rest receive 429. On 429 the frontend should retry after a short delay: the retry carries the freshly updated cookies and passes verification directly.

## CheckAuth

`CheckAuth` runs on every refresh (including re-sign only), which makes it the place to check whether a user was suspended or deleted; regular request verification does not call it.

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

`userRepo` stands for your application's data layer.

## Related Settings

| Field | Default | Effect |
|---|---|---|
| `MaxVersion` | `5` | Maximum number of re-sign-only refreshes |
| `RefreshTTL` | `0.5` | Full reissue once the remaining TTL drops below `RefreshIdExpires × RefreshTTL` |
| `RefreshIdExpires` | 7 days | TTL of the new Refresh ID on full reissue |

See [Configuration](/configuration) for every field.
