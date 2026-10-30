# Status Codes and Error Tags

Every method reports through `JWTAuthResult`; this page lists what triggers each `StatusCode` and `ErrorTag` combination.

## Mapping

| StatusCode | ErrorTag | Source | Trigger |
|---|---|---|---|
| `400` | `data_missing` | `Create` | `auth` is `nil` |
| `400` | `data_missing` | `Revoke` | The request has no Refresh ID |
| `400` | `data_invalid` | `Verify` | Bad signature, `nbf` not reached, `iat` more than 5 minutes in the future, claim Refresh ID or fingerprint mismatch, JTI missing from Redis or the `EXISTS jti:` call failing |
| `401` | `unauthorized` | `Verify` | Neither an Access Token nor a Refresh ID |
| `401` | `unauthorized` | Refresh | Refresh ID absent, expired, or fingerprint mismatch |
| `401` | `unauthorized` | `Revoke` | Refresh ID absent or expired |
| `401` | `revoked` | `Verify` | The Access Token has been revoked |
| `401` | (empty) | Refresh | `CheckAuth` returned `false` or an error |
| `429` | `failed_to_update` | Refresh | The refresh lock for this Refresh ID is held, or the `SETNX` call fails |
| `500` | `failed_to_create` | `Create`, refresh | Refresh ID or refresh data serialization failed |
| `500` | `failed_to_sign` | `Create`, refresh | JWT signing failed (for example, the key is not P-256) |
| `500` | `failed_to_store` | `Create`, refresh, `Revoke` | Redis write failed |
| `500` | `failed_to_get` | `Verify`, `Revoke` | Redis read failed |

"Refresh" means the [Transparent Refresh](/refresh) triggered inside `Verify`; its result is returned by `Verify`.

## The Error Field

`Error` is a human-readable message that may embed underlying error strings (from Redis or the JWT library); do not return it to end users or branch on it. Branch on `StatusCode` and `ErrorTag` only.

On failure the middleware returns only `{"error": Error}`, without `ErrorTag` (see [Middleware](/middleware)).

## Handling by Tag

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
