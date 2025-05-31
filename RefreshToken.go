package golangJwtAuth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (j *JWTAuth) Refresh(r *http.Request, w http.ResponseWriter, refreshId string, fp string) *AuthResult {
	dateNow := time.Now()

	refreshData, err := j.getRefreshData(refreshId, fp)
	if err != nil || refreshData.Data == nil {
		j.Logger.Refresh(true,
			"Invalid Refresh ID",
			fmt.Sprintf("Refresh ID: %s", refreshId),
			err.Error(),
		)
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusUnauthorized,
			Error:      "Invalid Refresh ID",
		}
	}

	lockKey := "lock:refresh:" + refreshId
	lockValue := uuid.New().String()
	locked, err := j.Redis.SetNX(j.Context, lockKey, lockValue, 5*time.Second).Result()
	if err != nil || !locked {
		j.Logger.Refresh(
			true,
			"Refresh in progress",
			fmt.Sprintf("Refresh ID: %s", refreshId),
			err.Error(),
		)
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusTooManyRequests,
			Error:      "Refresh in progress",
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
		j.Redis.Eval(j.Context, luaScript, []string{lockKey}, lockValue)
	}()

	newJTI := uuid.New().String()

	newRefreshData := RefreshData{
		Data:        refreshData.Data,
		Version:     refreshData.Version + 1,
		Fingerprint: fp,
		EXP:         refreshData.EXP,
		IAT:         refreshData.IAT,
		JTI:         newJTI,
	}
	newRefreshDataJson, err := json.Marshal(newRefreshData)
	if err != nil {
		j.Logger.Refresh(true,
			"Failed to parse refresh data",
			fmt.Sprintf("Auth ID: %s", refreshData.Data.ID),
			err.Error(),
		)
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to parse refresh data",
		}
	}

	// get ttl first, to update refresh data
	ttl, err := j.Redis.TTL(j.Context, "refresh:"+refreshId).Result()
	if err == nil && ttl > 0 {
		if err := j.Redis.SetEx(j.Context, "refresh:"+refreshId, string(newRefreshDataJson), ttl).Err(); err != nil {
			j.Logger.Refresh(true,
				"Failed to store new refresh data in redis",
				fmt.Sprintf("Auth ID: %s", refreshData.Data.ID),
				err.Error(),
			)
			return &AuthResult{
				Success:    false,
				StatusCode: http.StatusInternalServerError,
				Error:      "Failed to store new refresh data in redis",
			}
		}
	} else {
		j.Logger.Refresh(true,
			"Refresh ID is expired",
			fmt.Sprintf("Auth ID: %s", refreshData.Data.ID),
			err.Error(),
		)
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusUnauthorized,
			Error:      "Refresh ID is expired",
		}
	}

	if refreshData.Version > j.Config.MaxVersion || ttl < time.Duration(float64(j.Config.RefreshIdExpires)*j.Config.RefreshTTL) {
		j.Redis.SetEx(j.Context, "refresh:"+refreshId, string(newRefreshDataJson), 5*time.Second)

		newRefreshId, err := j.createRefreshId(refreshData.Data.ID, refreshData.Data.Name, refreshData.Data.Email, fp)
		if err != nil {
			j.Logger.Create(true,
				"Failed to create New Refresh ID",
				err.Error(),
			)
			return &AuthResult{
				Success:    false,
				StatusCode: http.StatusInternalServerError,
				Error:      "Failed to create New Refresh ID",
			}
		}

		newRefreshData.Version = 0
		newRefreshDataJson, err := json.Marshal(newRefreshData)
		if err != nil {
			j.Logger.Refresh(true,
				"Failed to parse new refresh data",
				fmt.Sprintf("Auth ID: %s", refreshData.Data.ID),
				err.Error(),
			)
			return &AuthResult{
				Success:    false,
				StatusCode: http.StatusInternalServerError,
				Error:      "Failed to parse new refresh data",
			}
		}

		if err := j.Redis.SetEx(j.Context, "refresh:"+newRefreshId, string(newRefreshDataJson), ttl).Err(); err != nil {
			j.Logger.Refresh(true,
				"Failed to store new refresh data in redis",
				fmt.Sprintf("Auth ID: %s", refreshData.Data.ID),
				err.Error(),
			)
			return &AuthResult{
				Success:    false,
				StatusCode: http.StatusInternalServerError,
				Error:      "Failed to store new refresh data in redis",
			}
		}

		w.Header().Set("X-New-Refresh-ID", newRefreshId)
		j.setCookie(w, j.Config.RefreshIdCookieKey, newRefreshId, dateNow.Add(j.Config.RefreshIdExpires))
	}

	if j.Config.CheckUserExists != nil {
		exists, err := j.Config.CheckUserExists(*refreshData.Data)
		if err != nil || !exists {
			j.Logger.Refresh(true,
				"User does not exist",
				fmt.Sprintf("Auth ID: %s", refreshData.Data.ID),
				err.Error(),
			)
			return &AuthResult{
				Success:    false,
				StatusCode: http.StatusUnauthorized,
				Error:      "User does not exist",
			}
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"id":         refreshData.Data.ID,
		"name":       refreshData.Data.Name,
		"email":      refreshData.Data.Email,
		"thumbnail":  refreshData.Data.Thumbnail,
		"scope":      refreshData.Data.Scope,
		"role":       refreshData.Data.Role,
		"level":      refreshData.Data.Level,
		"fp":         fp,
		"refresh_id": refreshId,
		"jti":        newJTI,
		"exp":        dateNow.Add(j.Config.AccessTokenExpires).Unix(),
		"iat":        dateNow.Unix(),
		"nbf":        dateNow.Unix(),
	})

	newAccessToken, err := token.SignedString(j.Config.PrivateKeyPEM)
	if err != nil {
		j.Logger.Refresh(true,
			"Failed to sign new access token",
			fmt.Sprintf("Auth ID: %s", refreshData.Data.ID),
			err.Error(),
		)
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to sign new access token",
		}
	}

	if err := j.Redis.SetEx(j.Context, "jti:"+newJTI, "1", j.Config.AccessTokenExpires).Err(); err != nil {
		j.Logger.Refresh(true,
			"Failed to store JTI in redis",
			fmt.Sprintf("Auth ID: %s", refreshData.Data.ID),
			err.Error(),
		)
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to store JTI in redis",
		}
	}

	j.Logger.Refresh(false,
		"Refreshed access token successfully",
		fmt.Sprintf("user: %s", refreshData.Data.ID),
	)

	w.Header().Set("X-New-Access-Token", newAccessToken)
	j.setCookie(w, j.Config.AccessTokenCookieKey, newAccessToken, dateNow.Add(j.Config.AccessTokenExpires))

	return &AuthResult{
		Success:    true,
		StatusCode: http.StatusOK,
		Data:       refreshData.Data,
	}
}
