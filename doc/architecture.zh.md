# go-jwt - 架構

> 返回 [README](./README.zh.md)

## 概覽

```mermaid
graph TB
    REQ[HTTP 請求] --> MW[中介層]
    MW --> V[Verify]
    V -->|有效| AUTH[回傳 Auth]
    V -->|過期| RF[Refresh]
    V -->|無 Token| DENY[拒絕]
    RF --> REDIS[(Redis)]
    V --> FP[裝置指紋]
```

## Module: JWTAuth

`JWTAuth` 是對外主入口，持有 Config、Redis client 與 ECDSA 金鑰。

```mermaid
graph TB
    subgraph JWTAuth
        New[New] --> PEM[handlePEM / parsePEM]
        New --> Redis[Redis Client]
        Create[Create] --> Sign[signJWT ES256]
        Create --> Store[Redis Pipeline]
        Verify[Verify] --> Parse[parseJWT]
        Verify --> RevokeCheck[撤銷檢查]
        Verify --> Refresh[refresh]
        Refresh --> Lock[SetNX 分散鎖]
        Refresh --> Sign
        Revoke[Revoke] --> Clear[clearCookie + 撤銷鍵]
    end
    Client[呼叫端] --> New
    Client --> Create
    Client --> Verify
    Client --> Revoke
    RedisDB[(Redis)] --> Store
    RedisDB --> RevokeCheck
    RedisDB --> Lock
```

## Module: Middleware

Gin 與 net/http 中介層包裝 `Verify`，成功後將 `Auth` 寫入 context。

```mermaid
graph LR
    subgraph Middleware
        Gin[GinMiddleware] --> Verify
        HTTP[HTTPMiddleware] --> Verify
        GetGin[GetAuthDataFromGinContext]
        GetHTTP[GetAuthDataFromHTTPRequest]
    end
    Verify[Verify] --> Auth[Auth in context]
```

## Module: PEM

金鑰載入優先序：檔案路徑 → 內嵌 PEM 字串 → 預設路徑自動產生 ECDSA P-256。

```mermaid
graph TB
    Start[handlePEM] --> File{File 路徑?}
    File -->|是| ReadFile[讀取 PEM 檔]
    File -->|否| Inline{Option 內嵌?}
    Inline -->|是| UseInline[使用字串]
    Inline -->|否| Default{預設檔存在?}
    Default -->|是| ReadDefault[讀取 ./keys]
    Default -->|否| Create[createPEM P-256]
    ReadFile --> Parse[parsePEM]
    UseInline --> Parse
    ReadDefault --> Parse
    Create --> Parse
```

## 資料流

```mermaid
sequenceDiagram
    participant C as Client
    participant M as Middleware
    participant V as Verify
    participant R as Redis
    participant P as PEM
    C->>M: HTTP Request
    M->>V: Verify(w, r)
    V->>R: 檢查 revoke / jti
    alt Token 有效
        V->>P: parseJWT ES256
        V-->>M: Auth
        M-->>C: 放行 + context
    else Token 過期
        V->>R: SetNX 鎖 + getRefreshData
        V->>P: signJWT
        V->>R: 更新 refresh / jti
        V-->>M: Auth + 新 Token
        M-->>C: 放行
    else 無 Token / 撤銷
        V-->>M: Unauthorized
        M-->>C: 401/錯誤 JSON
    end
```

***

©️ 2025 [邱敬幃 Pardn Chiu](https://www.linkedin.com/in/pardnchiu)
