package goJwt

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"time"

	"github.com/pardnchiu/go-logger"
	"github.com/redis/go-redis/v9"
)

const (
	defaultLogPath        = "./logs/jwt"
	defaultLogMaxSize     = 16 * 1024 * 1024
	defaultLogMaxBackup   = 5
	defaultPrivateKeyPath = "./keys/private-key.pem"
	defaultPublicKeyPath  = "./keys/public-key.pem"
)

const (
	cookieKeyDeviceID = "conn.device.id"
	redisKeyRefreshID = "refresh:%s"
	redisKeyLock      = "lock:refresh:%s"
	redisKeyJTI       = "jti:%s"
	redisKeyRevoke    = "revoke:%s"
)

const (
	headerKeyDeviceFP       = "X-Device-FP"
	headerKeyDeviceID       = "X-Device-ID"
	headerKeyRefreshID      = "X-Refresh-ID"
	headerKeyNewAccessToken = "X-New-Access-Token"
	headerKeyNewRefreshID   = "X-New-Refresh-ID"
)

const (
	errorDataMissing    = "data_missing"
	errorDataInvalid    = "data_invalid"
	errorUnAuthorized   = "unauthorized"
	errorRevoked        = "revoked"
	errorNotFound       = "not_found"
	errorNotMatched     = "not_matched"
	errorFailedToUpdate = "failed_to_update"
	errorFailedToCreate = "failed_to_create"
	errorFailedToSign   = "failed_to_sign"
	errorFailedToStore  = "failed_to_store"
	errorFailedToGet    = "failed_to_get"
)

// * 繼承至 pardnchiu/go-logger
type Log = logger.Log
type Logger = logger.Logger

type Config struct {
	Redis     Redis                    `json:"redis"`               // Redis 設定
	File      *File                    `json:"file,omitempty"`      // 檔案設定
	Log       *Log                     `json:"log,omitempty"`       // 日誌設定
	Option    *Option                  `json:"parameter,omitempty"` // 可調參數
	Cookie    *Cookie                  `json:"cookie,omitempty"`    // Cookie 設定
	CheckAuth func(Auth) (bool, error) `json:"-"`                   // 檢查使用者是否存在的函數
}

type Redis struct {
	Host     string `json:"host"`               // Redis 主機位址
	Port     int    `json:"port"`               // Redis 連接埠
	Password string `json:"password,omitempty"` // Redis 密碼
	DB       int    `json:"db"`                 // Redis 資料庫編號
}

type File struct {
	PrivateKeyPath string `json:"private_key_path,omitempty"`
	PublicKeyPath  string `json:"public_key_path,omitempty"`
}

type Option struct {
	PrivateKey           string        `json:"private_key,omitempty"`             // 私鑰內容
	PublicKey            string        `json:"public_key,omitempty"`              // 公鑰內容
	AccessTokenExpires   time.Duration `json:"access_token_expires,omitempty"`    // Access Token 有效期限，預設 15 分鐘
	RefreshIdExpires     time.Duration `json:"refresh_id_expires,omitempty"`      // Refresh ID 有效期限，預設 7 天
	AccessTokenCookieKey string        `json:"access_token_cookie_key,omitempty"` // Access Token Cookie 鍵名，預設 access_token
	RefreshIdCookieKey   string        `json:"refresh_id_cookie_key,omitempty"`   // Refresh ID Cookie 鍵名，預設 refresh_id
	MaxVersion           int           `json:"max_version,omitempty"`             // 重刷 Refresh ID 次數，預設 5（更換 5 次 Access Token 後，Refresh ID 會被重刷）
	RefreshTTL           float64       `json:"refresh_ttl,omitempty"`             // 刷新 Refresh ID 的 TTL 閾值，預設 0.5（低於一半時間）
}

type Cookie struct {
	Domain   *string        `json:"domain,omitempty"`    // Cookie 的網域
	Path     *string        `json:"path,omitempty"`      // Cookie 的路徑，預設 /
	SameSite *http.SameSite `json:"same_site,omitempty"` // Cookie 的 SameSite 屬性，預設 lax
	Secure   *bool          `json:"secure,omitempty"`    // Cookie 是否安全，預設 false
	HttpOnly *bool          `json:"http_only,omitempty"` // Cookie 是否 HttpOnly，預設 true
}

type JWTAuth struct {
	context context.Context
	config  Config
	logger  *Logger
	redis   *redis.Client
	pem     Pem
}

type Pem struct {
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
}

type JWTAuthResult struct {
	StatusCode int          `json:"status_code"`
	Success    bool         `json:"success"`
	Data       *Auth        `json:"data,omitempty"`
	Token      *TokenResult `json:"token,omitempty"`
	Error      string       `json:"error,omitempty"`
	ErrorTag   string       `json:"error_tag,omitempty"`
}

type TokenResult struct {
	Token     string `json:"token"`
	RefreshId string `json:"refresh_id"`
}

type RefreshData struct {
	Data        *Auth  `json:"data,omitempty"`
	Version     int    `json:"version"`
	Fingerprint string `json:"fp"`
	Exp         int64  `json:"exp"`
	Iat         int64  `json:"iat"`
	Jti         string `json:"jti"`
}

type Auth struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Email     string   `json:"email"`
	Thumbnail string   `json:"thumbnail,omitempty"`
	Scope     []string `json:"scope,omitempty"`
	Role      string   `json:"role,omitempty"`
	Level     int      `json:"level,omitempty"`
}
