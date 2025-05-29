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
	PrivateKeyPath       string                       `json:"private_key_path"`               // Path to private key file
	PublicKeyPath        string                       `json:"public_key_path"`                // Path to public key file
	PrivateKey           string                       `json:"private_key,omitempty"`          // Or directly provide private key content
	PublicKey            string                       `json:"public_key,omitempty"`           // Or directly provide public key content
	AccessTokenExpires   time.Duration                `json:"access_token_expires,omitempty"` // Default 15 minutes
	RefreshIdExpires     time.Duration                `json:"refresh_id_expires,omitempty"`   // Default 7 days
	IsProd               bool                         `json:"is_prod"`                        // Default false
	Domain               string                       `json:"domain,omitempty"`               // Default localhost
	Redis                RedisConfig                  `json:"redis"`
	CheckUserExists      func(AuthData) (bool, error) `json:"-"`
	AccessTokenCookieKey string                       `json:"access_token_cookie_key,omitempty"` // Default access_token
	RefreshIdCookieKey   string                       `json:"refresh_id_cookie_key,omitempty"`   // Default refresh_id
	MaxVersion           int                          `json:"max_version,omitempty"`             // Version threshold, default 5
	RefreshTTL           float64                      `json:"refresh_ttl,omitempty"`             // TTL threshold, default 0.5
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
