package goJwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func (j *JWTAuth) refresh(w http.ResponseWriter, r *http.Request) JWTAuthResult {
	now := time.Now()
	jti := uuid()
	fp := j.getFingerprint(w, r)
	refreshID := j.getRefreshID(r)

	refreshData, ttl, err := j.getRefreshData(refreshID, fp)
	// * Invalid Refresh ID or expired
	if err != nil || ttl == 0 || refreshData.Data == nil {
		return JWTAuthResult{
			StatusCode: http.StatusUnauthorized,
			Error:      j.logger.Error(err, "Invalid refresh id").Error(),
			ErrorTag:   errorUnAuthorized,
		}
	}

	keyLock := fmt.Sprintf(redisKeyLock, refreshID)
	lockValue := uuid()
	isUnlock, err := j.redis.SetNX(j.context, keyLock, lockValue, 3*time.Second).Result()
	// * Lock failed, another request is processing the same Refresh ID or Redis error
	if err != nil || !isUnlock {
		return JWTAuthResult{
			StatusCode: http.StatusTooManyRequests,
			Error:      j.logger.Error(err, "Refresh token lock acquisition failed").Error(),
			ErrorTag:   errorFailedToUpdate,
		}
	}

	defer func() {
		luaScript := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
		`
		j.redis.Eval(j.context, luaScript, []string{keyLock}, lockValue)
	}()

	newRefreshData := RefreshData{
		Data:        refreshData.Data,
		Version:     refreshData.Version + 1,
		Fingerprint: fp,
		Exp:         refreshData.Exp,
		Iat:         refreshData.Iat,
		Jti:         jti,
	}
	newRefreshDataJson, err := json.Marshal(newRefreshData)
	// * Cannot convert new Refresh Data to JSON
	if err != nil {
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      j.logger.Error(err, "JSON marshaling failed").Error(),
			ErrorTag:   errorFailedToCreate,
		}
	}

	// * Check if user authentication is required
	if j.config.CheckAuth != nil {
		exists, err := j.config.CheckAuth(*refreshData.Data)
		// * User authentication failed or does not exist
		if err != nil || !exists {
			return JWTAuthResult{
				Success:    false,
				StatusCode: http.StatusUnauthorized,
				Error:      j.logger.Error(err, "User authentication failed").Error(),
			}
		}
	}

	keyRefreshID := fmt.Sprintf(redisKeyRefreshID, refreshID)
	// * Check if Refresh Data update threshold has been reached
	if refreshData.Version > j.config.Option.MaxVersion || ttl < time.Duration(float64(j.config.Option.RefreshIdExpires)*j.config.Option.RefreshTTL) {
		// * Cannot update Refresh Data in Redis
		if err := j.redis.SetEx(j.context, keyRefreshID, string(newRefreshDataJson), 3*time.Second).Err(); err != nil {
			return JWTAuthResult{
				StatusCode: http.StatusInternalServerError,
				Error:      j.logger.Error(err, "Redis refresh data update failed").Error(),
				ErrorTag:   errorFailedToStore,
			}
		}
		// * Complete re-signing of Access Token/Refresh Data
		return j.Create(w, r, refreshData.Data)
	}

	newAccessToken, err := j.signJWT(refreshData.Data, refreshID, fp, jti)
	// * Cannot sign new Access Token
	if err != nil {
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      j.logger.Error(err, "JWT signing failed").Error(),
			ErrorTag:   errorFailedToSign,
		}
	}

	keyJTI := fmt.Sprintf(redisKeyJTI, jti)

	pipe := j.redis.TxPipeline()
	pipe.SetEx(j.context, keyRefreshID, string(newRefreshDataJson), ttl)
	pipe.SetEx(j.context, keyJTI, "1", j.config.Option.AccessTokenExpires)
	_, err = pipe.Exec(j.context)
	if err != nil {
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      j.logger.Error(err, "Redis transaction failed").Error(),
			ErrorTag:   errorFailedToStore,
		}
	}

	w.Header().Set(headerKeyNewAccessToken, newAccessToken)
	j.setCookie(w, j.config.Option.AccessTokenCookieKey, newAccessToken, now.Add(j.config.Option.AccessTokenExpires))

	return JWTAuthResult{
		Success:    true,
		StatusCode: http.StatusOK,
		Data:       refreshData.Data,
		Token: &TokenResult{
			Token:     newAccessToken,
			RefreshId: refreshID,
		},
	}
}
