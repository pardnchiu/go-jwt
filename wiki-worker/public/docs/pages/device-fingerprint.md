# Device Fingerprint

Every request yields a device fingerprint; the Access Token and Refresh ID record it at issue, and every later verification and refresh must match, so a stolen token fails on another device.

## How It Is Computed

`getFingerprint()` decides in order:

| # | Source | Result |
|---|---|---|
| 1 | Header `X-Device-FP` is set | Used as the fingerprint directly; the remaining steps are skipped |
| 2 | Device ID: header `X-Device-ID` → cookie `conn.device.id` → a new UUID | Written back to cookie `conn.device.id` (90 days) |
| 3 | OS, browser, and device type derived from the User-Agent | See the table below |
| 4 | SHA-256 of the JSON `{os, browser, device, deviceId}` | 64-character hex fingerprint |

## User-Agent Mapping

| Field | Recognized values | Match rule |
|---|---|---|
| OS | `Windows`, `MacOS`, `Linux`, `Android`, `iOS` | UA contains `Windows` / `Macintosh`, `Mac OS X` / `Linux` / `Android` / `iPhone`, `iPad`, `iPod` |
| Browser | `Edge`, `Opera`, `Chrome`, `Firefox`, `Safari` | UA contains `Edge`, `Edg` / `Opera`, `OPR` / `Chrome` / `Firefox` / `Safari` (without `Chrome`) |
| Device | `Tablet`, `Mobile`, `Desktop` | `iPad` → Tablet; `iPhone`, `iPod`, `Android`+`Mobile`, `BlackBerry`, `IEMobile`, `Opera Mini` → Mobile; otherwise Desktop |

Each `switch` matches top to bottom and takes the first hit. As a result, Android UAs (containing `Linux; Android`) get OS `Linux`, and iPhone/iPad UAs (containing `like Mac OS X`) get OS `MacOS`; the `Android` and `iOS` branches never match in practice. The fingerprint stays stable; only the OS field is imprecise.

## Unrecognized User-Agents

When either the OS or the browser is unrecognized, the unrecognized field becomes **a new UUID on every request**, so the fingerprint changes each time and verification always fails (`400 data_invalid`, message `fingerprint does not match`). curl, mobile HTTP libraries, and server-to-server calls fall into this case and must send a stable `X-Device-FP`.

```bash
# Fails: curl's UA is unrecognized, so the two requests get different fingerprints
curl -s -c jar.txt -b jar.txt -X POST http://localhost:8080/login
curl -s -c jar.txt -b jar.txt http://localhost:8080/me

# Works: send a stable fingerprint
curl -s -H "X-Device-FP: device-7f3a9c" -c jar.txt -b jar.txt -X POST http://localhost:8080/login
curl -s -H "X-Device-FP: device-7f3a9c" -c jar.txt -b jar.txt http://localhost:8080/me
```

## X-Test-Mode

With `X-Test-Mode: true`, an unrecognized OS/browser uses the fixed strings `TestOS`/`TestBrowser`, which makes the fingerprint stable. This header exists for testing and any client can send it, so binding strength must not rely on it going unused.

## Security Trade-offs

| Fingerprint source | Binding strength |
|---|---|
| Browser UA + `conn.device.id` cookie | Replayable if the cookie is stolen together with the token; switching browsers or clearing cookies requires a new login |
| Client-supplied `X-Device-FP` | Depends on how the client generates and stores the value; the server does not verify its origin |

See [Client Integration](/client-integration) for wiring up non-browser clients.
