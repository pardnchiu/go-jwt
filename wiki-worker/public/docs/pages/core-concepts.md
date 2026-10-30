# Token Model

go-jwt manages a login session with three credentials: a short-lived Access Token, a long-lived Refresh ID, and a JTI whitelist stored in Redis.

## Three Credentials

| Credential | Form | Default lifetime | Where it lives | Purpose |
|---|---|---|---|---|
| Access Token | ES256-signed JWT | 15 minutes (`AccessTokenExpires`) | Cookie `access_token`, or `Authorization: Bearer` | Authenticate every request |
| Refresh ID | 64-character hex string (SHA-256) | 7 days (`RefreshIdExpires`) | Cookie `refresh_id`, or `X-Refresh-ID` header | Obtain a new token when the Access Token expires |
| JTI | UUID v4 | Same as the Access Token | Redis `jti:<jti>` | Let the server invalidate an issued Access Token |

The Refresh ID carries no data; it is the key of Redis `refresh:<id>`. User data, version, and device fingerprint live server-side in `RefreshData`.

## Access Token Claims

Claims written by `signJWT()`:

| Claim | Source |
|---|---|
| `id`, `name`, `email`, `thumbnail`, `scope`, `role`, `level` | `Auth` fields |
| `fp` | Device fingerprint of this request |
| `jti` | Newly generated UUID |
| `exp` | Issue time + `AccessTokenExpires` |
| `iat`, `nbf` | Issue time |
| `refresh_id` (name taken from `RefreshIdCookieKey`) | Bound Refresh ID |

A JWT is signed, not encrypted; anyone holding it can decode every `Auth` field, so keep sensitive data out.

## How the Refresh ID Is Derived

`createRefreshId()` serializes `{id, name, email, fp, iat, jti}` to JSON, hashes it with SHA-256, and outputs hex. Because it includes `jti` and the current time, each login yields a different Refresh ID for the same user.

## RefreshData

The value of Redis `refresh:<id>`:

| Field | Description |
|---|---|
| `data` | `Auth` |
| `version` | 1 at issue, +1 per refresh; the pair is fully reissued once it exceeds `MaxVersion` |
| `fp` | Device fingerprint at issue; must match on refresh |
| `exp`, `iat` | Times of the first issue; kept unchanged on refresh |
| `jti` | JTI of the most recent issue |

## Session Lifecycle

| Stage | Trigger | Page |
|---|---|---|
| Issue | The application calls `Create()` | [API Reference](/api-reference) |
| Verify | Every request, via `Verify()` or middleware | [Verification Flow](/verification) |
| Refresh | Access Token expired or missing while the Refresh ID is still valid | [Transparent Refresh](/refresh) |
| Revoke | The application calls `Revoke()` | [Revocation](/revocation) |
