package golangJwtAuth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type JWTAuth struct {
	config      *Config
	redisClient *redis.Client
	context     context.Context
}

type Config struct {
	PrivateKeyPath       string                       `json:"private_key_path"`      // 私鑰檔案路徑
	PublicKeyPath        string                       `json:"public_key_path"`       // 公鑰檔案路徑
	PrivateKey           string                       `json:"private_key,omitempty"` // 或直接提供私鑰內容
	PublicKey            string                       `json:"public_key,omitempty"`  // 或直接提供公鑰內容
	AccessTokenExpires   time.Duration                `json:"access_token_expires"`
	RefreshIdExpires     time.Duration                `json:"refresh_id_expires"`
	IsProd               bool                         `json:"is_prod"`
	Domain               string                       `json:"domain,omitempty"`
	Redis                RedisConfig                  `json:"redis"`
	CheckUserExists      func(AuthData) (bool, error) `json:"-"`
	AccessTokenCookieKey string                       `json:"access_token_cookie_key"`
	RefreshIdCookieKey   string                       `json:"refresh_id_cookie_key"`
	MaxVersion           int                          `json:"max_version"` // 版本閾值，預設 5
	RefreshTTL           float64                      `json:"refresh_ttl"` // TTL 閾值，預設 0.5
}

type RedisConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password,omitempty"`
	DB       int    `json:"db"`
}

type AuthData struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Email     string   `json:"email"`
	Thumbnail string   `json:"thumbnail,omitempty"`
	Scope     []string `json:"scope,omitempty"`
	Role      string   `json:"role,omitempty"`
	Level     int      `json:"level,omitempty"`
}

type RefreshData struct {
	Data        *AuthData `json:"data,omitempty"`
	Version     int       `json:"version"`
	Fingerprint string    `json:"fp"`
	EXP         int64     `json:"exp"`
	IAT         int64     `json:"iat"`
	JTI         string    `json:"jti"`
}

type AuthResult struct {
	Success    bool      `json:"success"`
	Data       *AuthData `json:"data,omitempty"`
	Error      string    `json:"error,omitempty"`
	StatusCode int       `json:"status_code"`
}

type TokenResult struct {
	Token     string `json:"token"`
	RefreshId string `json:"refresh_id"`
}
