# Key Management

go-jwt signs Access Tokens with ES256 (ECDSA P-256 + SHA-256); this page covers key loading order, format requirements, and multi-instance deployment.

## Loading Order

| Priority | Condition | Behavior |
|---|---|---|
| 1 | `File.PrivateKeyPath` / `File.PublicKeyPath` set | Read the files and overwrite `Option.PrivateKey` / `Option.PublicKey`; a read failure returns an error |
| 2 | Both `Option.PrivateKey` and `Option.PublicKey` set | Use them directly |
| 3 | Both empty, and `./keys/private-key.pem` and `./keys/public-key.pem` both exist | Read those files |
| 4 | Both empty, and either file is missing | Generate a P-256 key pair into `./keys/` (directory `0755`, private `0600`, public `0644`); when only one file is missing, the existing one is overwritten too |
| — | Only one key provided | Return the error `Both private key and public key are required` |

`./keys/` is relative to the process working directory, not the binary's location.

## Format Requirements

| Key | PEM block | Encoding |
|---|---|---|
| Private | `PRIVATE KEY` | PKCS#8 |
| Public | `PUBLIC KEY` | PKIX (SubjectPublicKeyInfo) |

After loading, both keys must be ECDSA and form a matching pair, or an error is returned.

**The curve must be P-256.** `New()` accepts any ECDSA curve, but signing is fixed to ES256; with P-384 or another curve `New()` succeeds and `Create()` later returns `500 failed_to_sign` (`key is invalid`).

## Generating with OpenSSL

```bash
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
chmod 600 private-key.pem
```

`openssl ecparam -genkey` alone outputs SEC1 (`EC PRIVATE KEY`); it must go through `pkcs8 -topk8` to become PKCS#8.

## Loading from the Environment or a Secret Manager

The library reads no environment variables; the application reads them and passes them in `Option`:

```go
auth, err := goJwt.New(goJwt.Config{
	Redis: goJwt.Redis{Host: "localhost", Port: 6379},
	Option: &goJwt.Option{
		PrivateKey: os.Getenv("JWT_PRIVATE_KEY"),
		PublicKey:  os.Getenv("JWT_PUBLIC_KEY"),
	},
})
if err != nil {
	log.Fatalf("failed to init go-jwt: %v", err)
}
```

`JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` are names chosen by the application, not library settings.

## Multi-Instance Deployment

| Case | Result |
|---|---|
| Each instance auto-generates keys | Keys differ per instance; a token issued by A fails verification on B |
| Container without a mounted `./keys/` | A new key pair on every restart invalidates every existing token |
| All instances share one key pair and one Redis | Correct setup |

## Rotating Keys

An instance holds one key pair at a time. After switching keys:

| Request | Result |
|---|---|
| Carries an Access Token signed with the old key (expired or not) | `400 data_invalid`: signature verification runs before the expiry check, so no refresh happens |
| Carries only the Refresh ID | Refresh succeeds and signs with the new key |

The browser `access_token` cookie expires together with `AccessTokenExpires`; after that, requests carry only the Refresh ID and refresh automatically, while earlier requests get 400. To recover immediately, the client clears the Access Token on 400 and retries.
