# Verification Flow

This page lists the checks `Verify()` runs on a request, in order, and the response when each one fails.

## Reading Credentials

| Credential | Lookup order |
|---|---|
| Access Token | 1. Cookie `access_token` (`AccessTokenCookieKey`) 2. `Authorization: Bearer <token>` |
| Refresh ID | 1. Header `X-Refresh-ID` 2. Cookie `refresh_id` (`RefreshIdCookieKey`) |
| Device fingerprint | See [Device Fingerprint](/device-fingerprint) |

## Check Order

| # | Check | On failure |
|---|---|---|
| 1 | An Access Token is present | With a Refresh ID → [Transparent Refresh](/refresh); with neither → `401 unauthorized` |
| 2 | Redis `revoke:<accessToken>` does not exist | Exists → `401 revoked`; Redis error → `500 failed_to_get` |
| 3 | Signing method is ECDSA and the signature verifies with the public key | `400 data_invalid` |
| 4 | Not expired (`exp`) | Expired → [Transparent Refresh](/refresh) |
| 5 | `nbf` is not later than now | `400 data_invalid` |
| 6 | `iat` is not more than 5 minutes in the future | `400 data_invalid` |
| 7 | Claim `refresh_id` equals the request's Refresh ID | `400 data_invalid` |
| 8 | Claim `fp` equals this request's fingerprint | `400 data_invalid` |
| 9 | Redis `jti:<jti>` exists | `400 data_invalid` |

When every check passes, the result is `200` with `Data` set to the `Auth` restored from the claims.

## Key Behaviors

- **An Access Token needs its Refresh ID**: step 7 requires the claim to match the request, so a request with `Authorization` but no Refresh ID fails.
- **Expiry wins over other errors**: when the signature error message contains `expired`, the flow refreshes instead of returning 400.
- **Revocation is keyed by the Access Token string**: it revokes that token, not the user.

## Example

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

`Verify` may write cookies and headers (on refresh), so call it before writing the response body. See [Status Codes and Error Tags](/error-codes) for the full mapping.
