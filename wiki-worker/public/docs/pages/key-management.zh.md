# 金鑰管理

go-jwt 以 ES256（ECDSA P-256 ＋ SHA-256）簽署 Access Token；本頁說明金鑰的載入順序、格式要求與多實例部署。

## 載入順序

| 優先序 | 條件 | 行為 |
|---|---|---|
| 1 | `File.PrivateKeyPath`／`File.PublicKeyPath` 有值 | 讀檔並覆寫 `Option.PrivateKey`／`Option.PublicKey`；讀檔失敗回傳 error |
| 2 | `Option.PrivateKey` 與 `Option.PublicKey` 皆有值 | 直接使用 |
| 3 | 兩者皆空，且 `./keys/private-key.pem`、`./keys/public-key.pem` 都存在 | 讀取這兩個檔案 |
| 4 | 兩者皆空，且上述檔案不齊 | 產生 P-256 金鑰對寫入 `./keys/`（目錄 `0755`、私鑰 `0600`、公鑰 `0644`）；只缺一個檔案時，既有的那個也會被覆寫 |
| — | 只提供其中一把 | 回傳 error `Both private key and public key are required` |

`./keys/` 是相對於程式的工作目錄，不是執行檔所在位置。

## 格式要求

| 金鑰 | PEM 區塊 | 編碼 |
|---|---|---|
| 私鑰 | `PRIVATE KEY` | PKCS#8 |
| 公鑰 | `PUBLIC KEY` | PKIX（SubjectPublicKeyInfo） |

載入後會檢查兩把都是 ECDSA 且互相配對，不符即回傳 error。

**曲線必須是 P-256。** `New()` 接受任何 ECDSA 曲線，但簽章固定使用 ES256；用 P-384 等其他曲線時 `New()` 會成功，直到 `Create()` 才回 `500 failed_to_sign`（`key is invalid`）。

## 用 OpenSSL 產生

```bash
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
chmod 600 private-key.pem
```

`openssl ecparam -genkey` 直接輸出的是 SEC1（`EC PRIVATE KEY`），必須經過 `pkcs8 -topk8` 轉成 PKCS#8。

## 從環境或密鑰管理服務載入

本函式庫不讀環境變數；由應用程式讀取後放進 `Option`：

```go
auth, err := goJwt.New(goJwt.Config{
	Redis: goJwt.Redis{Host: "localhost", Port: 6379},
	Option: &goJwt.Option{
		PrivateKey: os.Getenv("JWT_PRIVATE_KEY"),
		PublicKey:  os.Getenv("JWT_PUBLIC_KEY"),
	},
})
if err != nil {
	log.Fatalf("初始化 go-jwt 失敗: %v", err)
}
```

`JWT_PRIVATE_KEY`／`JWT_PUBLIC_KEY` 是應用程式自訂的名稱，不是本函式庫的設定。

## 多實例部署

| 情境 | 結果 |
|---|---|
| 各實例自動產生金鑰 | 每個實例的金鑰不同，A 簽發的 Token 在 B 驗證失敗 |
| 容器未掛載 `./keys/` | 每次重啟產生新金鑰，所有既有 Token 失效 |
| 所有實例共用同一組金鑰與同一個 Redis | 正確作法 |

## 輪替金鑰

一個實例同時只持有一組金鑰。換金鑰後：

| 請求 | 結果 |
|---|---|
| 帶舊金鑰簽的 Access Token（不論是否過期） | `400 data_invalid`：驗章先於過期判斷，不會進入刷新 |
| 只帶 Refresh ID | 刷新成功，以新金鑰簽發 |

瀏覽器的 `access_token` Cookie 期限與 `AccessTokenExpires` 相同，到期後請求只剩 Refresh ID，會自動換發；在那之前的請求都會收到 400。要立即恢復，客戶端收到 400 時清除 Access Token 並重送即可。
