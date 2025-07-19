package goJwt

import (
	"context"
	"fmt"
	"log/slog"
	"log/syslog"
	"os"
	"time"

	// "github.com/pardnchiu/go-logger"
	"github.com/redis/go-redis/v9"
)

func New(c Config) (*JWTAuth, error) {
	// c.Log = validLoggerConfig(c)
	c.Option = validOptionData(c)

	writer, err := syslog.New(syslog.LOG_INFO|syslog.LOG_LOCAL0, "goCron")
	if err != nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	} else {
		logger = slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	}

	// logger, err := logger.New(c.Log)
	// if err != nil {
	// 	return nil, fmt.Errorf("Failed to initialize `pardnchiu/go-logger`: %w", err)
	// }

	if err := handlePEM(c); err != nil {
		logger.Error("Failed to handle PEM", "error", err)
		return nil, fmt.Errorf("failed to handle PEM: %w", err)
	}

	privateKey, publicKey, err := parsePEM(c)
	if err != nil {
		logger.Error("Failed to parse PEM key", "error", err)
		return nil, fmt.Errorf("failed to parse PEM key: %w", err)
	}

	ctx := context.Background()
	redis := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port),
		Password: c.Redis.Password,
		DB:       c.Redis.DB,
	})
	if _, err := redis.Ping(ctx).Result(); err != nil {
		logger.Error("Failed to connect Redis", err)
		return nil, fmt.Errorf("failed to connect Redis: %w", err)
	}

	return &JWTAuth{
		config:  c,
		redis:   redis,
		context: ctx,
		// logger:  logger,
		pem: Pem{
			private: privateKey,
			public:  publicKey,
		},
	}, nil
}

func (j *JWTAuth) Close() error {
	return j.redis.Close()
}

// func validLoggerConfig(c Config) *Log {
// 	if c.Log == nil {
// 		c.Log = &Log{
// 			Path:    defaultLogPath,
// 			Stdout:  false,
// 			MaxSize: defaultLogMaxSize,
// 		}
// 	}
// 	if c.Log.Path == "" {
// 		c.Log.Path = defaultLogPath
// 	}
// 	if c.Log.MaxSize <= 0 {
// 		c.Log.MaxSize = defaultLogMaxSize
// 	}
// 	if c.Log.MaxBackup <= 0 {
// 		c.Log.MaxBackup = defaultLogMaxBackup
// 	}
// 	return c.Log
// }

func validOptionData(c Config) *Option {
	defaultOption := &Option{
		AccessTokenExpires:   15 * time.Minute,
		RefreshIdExpires:     7 * 24 * time.Hour,
		AccessTokenCookieKey: "access_token",
		RefreshIdCookieKey:   "refresh_id",
		MaxVersion:           5,
		RefreshTTL:           0.5,
	}

	if c.Option == nil {
		c.Option = defaultOption
	}

	if c.Option.AccessTokenExpires <= 0 {
		c.Option.AccessTokenExpires = defaultOption.AccessTokenExpires
	}
	if c.Option.RefreshIdExpires <= 0 {
		c.Option.RefreshIdExpires = defaultOption.RefreshIdExpires
	}
	if c.Option.AccessTokenCookieKey == "" {
		c.Option.AccessTokenCookieKey = defaultOption.AccessTokenCookieKey
	}
	if c.Option.RefreshIdCookieKey == "" {
		c.Option.RefreshIdCookieKey = defaultOption.RefreshIdCookieKey
	}
	if c.Option.MaxVersion <= 0 {
		c.Option.MaxVersion = defaultOption.MaxVersion
	}
	if c.Option.RefreshTTL <= 0 {
		c.Option.RefreshTTL = defaultOption.RefreshTTL
	}

	return c.Option
}
