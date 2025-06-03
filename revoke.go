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
		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      j.logger.Error(nil, "Missing refresh ID").Error(),
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
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      j.logger.Error(err, "Failed to execute Redis pipeline").Error(),
			ErrorTag:   errorFailedToGet,
		}
	}

	result, err := getCmd.Result()
	if err != nil && err.Error() != "redis: nil" {
		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      j.logger.Error(err, "Failed to get refresh token").Error(),
			ErrorTag:   errorFailedToGet,
		}
	}

	ttl, err := ttlCmd.Result()
	if err != nil {
		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      j.logger.Error(err, "Failed to get refresh token TTL").Error(),
			ErrorTag:   errorFailedToGet,
		}
	}

	if ttl <= 0 {
		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      j.logger.Error(nil, "Refresh token expired").Error(),
			ErrorTag:   errorUnAuthorized,
		}
	}

	pipe2 := j.redis.TxPipeline()
	pipe2.SetEx(j.context, keyRefreshID, result, 5*time.Second)
	// * Not setting TTL to reduce one parsing step
	pipe2.SetEx(j.context, keyRevoke, "1", j.config.Option.AccessTokenExpires)
	_, err = pipe2.Exec(j.context)

	if err != nil {
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      j.logger.Error(err, "Failed to revoke token").Error(),
			ErrorTag:   errorFailedToStore,
		}
	}

	return JWTAuthResult{
		Success:    true,
		StatusCode: http.StatusOK,
	}
}
