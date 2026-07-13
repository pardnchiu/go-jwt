# go-jwt - Architecture

> Back to [README](../README.md)

## Overview

```mermaid
graph TB
    REQ[HTTP Request] --> MW[Middleware]
    MW --> V[Verify]
    V -->|Valid| AUTH[Return Auth]
    V -->|Expired| RF[Refresh]
    V -->|No Token| DENY[Deny]
    RF --> REDIS[(Redis)]
    V --> FP[Device Fingerprint]
```

## Module: JWTAuth

`JWTAuth` is the public entry point holding Config, Redis client, and ECDSA keys.

```mermaid
graph TB
    subgraph JWTAuth
        New[New] --> PEM[handlePEM / parsePEM]
        New --> Redis[Redis Client]
        Create[Create] --> Sign[signJWT ES256]
        Create --> Store[Redis Pipeline]
        Verify[Verify] --> Parse[parseJWT]
        Verify --> RevokeCheck[Revocation check]
        Verify --> Refresh[refresh]
        Refresh --> Lock[SetNX distributed lock]
        Refresh --> Sign
        Revoke[Revoke] --> Clear[clearCookie + revoke key]
    end
    Client[Caller] --> New
    Client --> Create
    Client --> Verify
    Client --> Revoke
    RedisDB[(Redis)] --> Store
    RedisDB --> RevokeCheck
    RedisDB --> Lock
```

## Module: Middleware

Gin and net/http middleware wrap `Verify` and store `Auth` in context on success.

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

Key load order: file path → inline PEM string → default path auto-generate ECDSA P-256.

```mermaid
graph TB
    Start[handlePEM] --> File{File path?}
    File -->|yes| ReadFile[Read PEM files]
    File -->|no| Inline{Option inline?}
    Inline -->|yes| UseInline[Use strings]
    Inline -->|no| Default{Default files exist?}
    Default -->|yes| ReadDefault[Read ./keys]
    Default -->|no| Create[createPEM P-256]
    ReadFile --> Parse[parsePEM]
    UseInline --> Parse
    ReadDefault --> Parse
    Create --> Parse
```

## Data Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant M as Middleware
    participant V as Verify
    participant R as Redis
    participant P as PEM
    C->>M: HTTP Request
    M->>V: Verify(w, r)
    V->>R: check revoke / jti
    alt Valid token
        V->>P: parseJWT ES256
        V-->>M: Auth
        M-->>C: allow + context
    else Expired token
        V->>R: SetNX lock + getRefreshData
        V->>P: signJWT
        V->>R: update refresh / jti
        V-->>M: Auth + new token
        M-->>C: allow
    else Missing / revoked
        V-->>M: Unauthorized
        M-->>C: 401 / error JSON
    end
```

***

©️ 2025 [邱敬幃 Pardn Chiu](https://www.linkedin.com/in/pardnchiu)
