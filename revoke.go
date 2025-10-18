package goJwt

import (
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

func (j *JWTAuth) Revoke(w http.ResponseWriter, r *http.Request) JWTAuthResult {
	accessToken := j.getAccessToken(r)
	refreshId := j.getRefreshID(r)

	j.clearCookie(w, j.config.Option.AccessTokenCookieKey)
	j.clearCookie(w, j.config.Option.RefreshIdCookieKey)

	if refreshId == "" {
		logger.Error("Refresh ID missing")
		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      "refresh ID required",
			ErrorTag:   errorDataMissing,
		}
	}

	keyRefreshID := fmt.Sprintf(redisKeyRefreshID, refreshId)
	keyRevoke := fmt.Sprintf(redisKeyRevoke, accessToken)

	// Get refresh data and TTL in single operation (單一操作獲取數據和 TTL)
	refreshData, err := j.redis.Get(j.context, keyRefreshID).Result()
	if err == redis.Nil {
		logger.Error("Refresh token not found")
		return JWTAuthResult{
			StatusCode: http.StatusUnauthorized,
			Error:      "refresh token not found or already revoked",
			ErrorTag:   errorUnAuthorized,
		}
	}
	if err != nil {
		logger.Error("Failed to get refresh token", "error", err)
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      fmt.Errorf("failed to get refresh token: %w", err).Error(),
			ErrorTag:   errorFailedToGet,
		}
	}

	ttl, err := j.redis.TTL(j.context, keyRefreshID).Result()
	if err != nil {
		logger.Error("Failed to get refresh token TTL", "error", err)
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      fmt.Errorf("failed to get TTL: %w", err).Error(),
			ErrorTag:   errorFailedToGet,
		}
	}

	if ttl <= 0 {
		logger.Error("Refresh token expired")
		return JWTAuthResult{
			StatusCode: http.StatusUnauthorized,
			Error:      "refresh token expired",
			ErrorTag:   errorUnAuthorized,
		}
	}

	pipe := j.redis.TxPipeline()
	pipe.SetEx(j.context, keyRefreshID, refreshData, 5*time.Second)
	pipe.SetEx(j.context, keyRevoke, "1", j.config.Option.AccessTokenExpires)

	if _, err := pipe.Exec(j.context); err != nil {
		logger.Error("Failed to revoke tokens", "error", err)
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      fmt.Errorf("failed to revoke tokens: %w", err).Error(),
			ErrorTag:   errorFailedToStore,
		}
	}

	return JWTAuthResult{
		Success:    true,
		StatusCode: http.StatusOK,
	}
}
