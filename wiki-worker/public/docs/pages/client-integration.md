# Client Integration

This page lists which cookies and headers a client sends, which responses it receives, and how browser and non-browser clients each integrate.

## Request Inputs

| Source | Name | Purpose |
|---|---|---|
| Cookie | `access_token` (`AccessTokenCookieKey`) | Access Token; takes precedence over the Authorization header |
| Header | `Authorization: Bearer <token>` | Access Token when no cookie is present |
| Header | `X-Refresh-ID` | Refresh ID; takes precedence over the cookie |
| Cookie | `refresh_id` (`RefreshIdCookieKey`) | Refresh ID |
| Header | `X-Device-FP` | Supplies the device fingerprint directly |
| Header | `X-Device-ID` | Device ID; takes precedence over the cookie |
| Cookie | `conn.device.id` | Device ID |

## Response Outputs

| When | `Set-Cookie` | Header |
|---|---|---|
| `Create()` login | `access_token`, `refresh_id`, `conn.device.id` | — |
| Refresh: re-sign only | `access_token` | `X-New-Access-Token` |
| Refresh: full reissue | `access_token`, `refresh_id` | — |
| `Revoke()` | Clears `access_token`, `refresh_id` | — |
| Every fingerprint computation without `X-Device-FP` | `conn.device.id` (90 days) | — |

Cookies default to HttpOnly, `http.SameSiteLaxMode`, Path `/`, and not Secure; override them with `Cookie` in [Configuration](/configuration).

## Browsers

Same-site web pages need nothing extra: cookies are sent and updated automatically and refresh is transparent to the frontend. Watch for:

| Case | Handling |
|---|---|
| Cross-site API | Send with `credentials: "include"`; allow credentials in backend CORS and set cookies to `http.SameSiteNoneMode` with Secure |
| Several requests fired right after the Access Token expires | Some receive `429`; retry after a short delay (see [Transparent Refresh](/refresh)) |
| Production | Set `Cookie.Secure` to `true` |

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

## Non-Browser Clients (Mobile Apps, CLIs, Services)

| Requirement | Reason |
|---|---|
| Generate one stable value per device and send it as `X-Device-FP` on every request | With an unrecognized UA the fingerprint changes every time (see [Device Fingerprint](/device-fingerprint)) |
| Send both the Access Token and the Refresh ID | Verification compares the Refresh ID inside the token (step 7 of [Verification Flow](/verification)) |
| Parse `Set-Cookie` on every response | On full reissue the new Refresh ID appears **only** in `Set-Cookie: refresh_id`, with no matching header |
| Replace the local Access Token when `X-New-Access-Token` arrives | That is the new token on re-sign only |

An HTTP client with a cookie jar (Go's `net/http/cookiejar`, OkHttp's cookie jar) that stores `access_token`/`refresh_id` is the least error-prone way to catch full reissues.

```bash
# Login
curl -s -H "X-Device-FP: device-7f3a9c" -c jar.txt -b jar.txt -X POST http://localhost:8080/login

# Send the same fingerprint every time and write response cookies back to the jar
curl -s -H "X-Device-FP: device-7f3a9c" -c jar.txt -b jar.txt http://localhost:8080/me -D -
```

Passing credentials as headers:

```bash
curl -s http://localhost:8080/me \
  -H "X-Device-FP: device-7f3a9c" \
  -H "Authorization: Bearer <token>" \
  -H "X-Refresh-ID: <refresh_id>" \
  -D -
```

## Error Handling

| Status | Client action |
|---|---|
| `401` | Send the user to login |
| `429` | Retry after a short delay |
| `400` | Credentials do not match the device or are malformed; clear local credentials and log in again |
| `5xx` | Server or Redis failure; retryable |

See [Status Codes and Error Tags](/error-codes) for the full mapping.
