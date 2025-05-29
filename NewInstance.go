package golangJwtAuth

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

func New(config *Config) (*JWTAuth, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Redis.Host, config.Redis.Port),
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	context := context.Background()

	if _, err := redisClient.Ping(context).Result(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %v", err)
	}

	if config.PrivateKeyPath != "" {
		privateKeyBytes, err := os.ReadFile(config.PrivateKeyPath)
		if err != nil {
			log.Fatal("can not get private key:", err)
		}
		config.PrivateKey = string(privateKeyBytes)
	} else if config.PrivateKey == "" {
		return nil, fmt.Errorf("private key is required")
	}

	if config.PublicKeyPath != "" {
		publicKeyBytes, err := os.ReadFile(config.PublicKeyPath)
		if err != nil {
			log.Fatal("can not get public key:", err)
		}
		config.PublicKey = string(publicKeyBytes)
	} else if config.PublicKey == "" {
		return nil, fmt.Errorf("public key is required")
	}

	if config.AccessTokenExpires == 0 {
		config.AccessTokenExpires = 15 * time.Minute
	}

	if config.RefreshIdExpires == 0 {
		config.RefreshIdExpires = 7 * 24 * time.Hour
	}

	if config.Domain == "" {
		config.Domain = "localhost"
	}

	if config.AccessTokenCookieKey == "" {
		config.AccessTokenCookieKey = "access_token"
	}

	if config.RefreshIdCookieKey == "" {
		config.RefreshIdCookieKey = "refresh_id"
	}

	if config.MaxVersion == 0 {
		config.MaxVersion = 5
	}

	if config.RefreshTTL == 0 {
		config.RefreshTTL = 0.5
	}

	return &JWTAuth{
		config:      config,
		redisClient: redisClient,
		context:     context,
	}, nil
}

func (j *JWTAuth) Close() error {
	return j.redisClient.Close()
}
