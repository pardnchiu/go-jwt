package goJwt

import (
	"fmt"
	"net/http"
	"time"
)

func (j *JWTAuth) Revoke(w http.ResponseWriter, r *http.Request) JWTAuthResult {
	accessToken := j.getAccessToken(r)
	refreshId := j.getRefreshID(r)

	j.clearCookie(w, j.config.Option.AccessTokenCookieKey)
	j.clearCookie(w, j.config.Option.RefreshIdCookieKey)

	if refreshId == "" {
		logger.Error("Failed to acquire lock for refresh token")
		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      "failed to acquire lock for refresh token",
			ErrorTag:   errorDataMissing,
		}
	}

	keyRefreshID := fmt.Sprintf(redisKeyRefreshID, refreshId)
	keyRevoke := fmt.Sprintf(redisKeyRevoke, accessToken)

	pipe1 := j.redis.TxPipeline()
	getCmd := pipe1.Get(j.context, keyRefreshID)
	ttlCmd := pipe1.TTL(j.context, keyRefreshID)
	_, err := pipe1.Exec(j.context)

	if err != nil {
		logger.Error("Failed to acquire lock for refresh token", "error", err)
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      fmt.Errorf("failed to acquire lock for refresh token: %w", err).Error(),
			ErrorTag:   errorFailedToGet,
		}
	}

	result, err := getCmd.Result()
	if err != nil && err.Error() != "redis: nil" {
		logger.Error("Failed to get refresh token", "error", err)
		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      fmt.Errorf("failed to get refresh token: %w", err).Error(),
			ErrorTag:   errorFailedToGet,
		}
	}

	ttl, err := ttlCmd.Result()
	if err != nil {
		logger.Error("Failed to get refresh token TTL", "error", err)
		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      fmt.Errorf("failed to get refresh token TTL: %w", err).Error(),
			ErrorTag:   errorFailedToGet,
		}
	}

	if ttl <= 0 {
		logger.Error("Refresh token expired")
		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      "refresh token expired",
			ErrorTag:   errorUnAuthorized,
		}
	}

	pipe2 := j.redis.TxPipeline()
	pipe2.SetEx(j.context, keyRefreshID, result, 5*time.Second)
	// * Not setting TTL to reduce one parsing step
	pipe2.SetEx(j.context, keyRevoke, "1", j.config.Option.AccessTokenExpires)
	_, err = pipe2.Exec(j.context)

	if err != nil {
		logger.Error("Failed to revoke refresh token", "error", err)
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      fmt.Errorf("failed to revoke refresh token: %w", err).Error(),
			ErrorTag:   errorFailedToStore,
		}
	}

	return JWTAuthResult{
		Success:    true,
		StatusCode: http.StatusOK,
	}
}
