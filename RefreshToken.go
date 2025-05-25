package golangJwtAuth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (j *JWTAuth) Refresh(r *http.Request, w http.ResponseWriter, refreshId, fp string) *AuthResult {
	dateNow := time.Now()

	refreshData, err := j.GetRefreshData(refreshId, fp)
	if err != nil || refreshData.Data == nil {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusInternalServerError,
			Error:      "refresh id invalid",
		}
	}

	newRefreshData := map[string]interface{}{
		"data": map[string]interface{}{
			"id":        refreshData.Data.ID,
			"name":      refreshData.Data.Name,
			"email":     refreshData.Data.Email,
			"thumbnail": refreshData.Data.Thumbnail,
			"scope":     refreshData.Data.Scope,
			"role":      refreshData.Data.Role,
			"level":     refreshData.Data.Level,
		},
		"version": refreshData.Version + 1,
		"fp":      fp,
		"exp":     refreshData.EXP,
		"iat":     refreshData.IAT,
	}
	newRefreshDataJson, err := json.Marshal(newRefreshData)
	if err != nil {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusInternalServerError,
			Error:      "failed to marshal refresh data",
		}
	}

	// get ttl first, to update refresh data
	ttl, err := j.redisClient.TTL(j.context, "refresh:"+refreshId).Result()
	if err == nil && ttl > 0 {
		if err := j.redisClient.SetEx(j.context, "refresh:"+refreshId, string(newRefreshDataJson), ttl).Err(); err != nil {
			fmt.Printf("failed to save to redis: %v", err)
		}
	} else {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusUnauthorized,
			Error:      "refresh token invalid",
		}
	}

	// refresh rule
	// version > 5
	// ttl < j.config.RefreshIdExpires / 2
	if refreshData.Version > 5 || ttl < j.config.RefreshIdExpires/2 {
		j.redisClient.SetEx(j.context, "refresh:"+refreshId, string(newRefreshDataJson), 5*time.Second)
		newRefreshId := j.CreateRefreshId(refreshData.Data.ID, refreshData.Data.Name, refreshData.Data.Email, fp)

		newRefreshData["version"] = 0
		newRefreshDataJson, err := json.Marshal(newRefreshData)
		if err != nil {
			return &AuthResult{
				Success:    false,
				StatusCode: http.StatusUnauthorized,
				Error:      "failed to marshal refresh data",
			}
		}

		if err := j.redisClient.SetEx(j.context, "refresh:"+newRefreshId, string(newRefreshDataJson), ttl).Err(); err != nil {
			fmt.Printf("failed to save new refresh data: %v", err)
		}

		w.Header().Set("X-New-Refresh-ID", newRefreshId)
		j.SetCookie(w, j.config.RefreshIdCookieKey, newRefreshId, dateNow.Add(j.config.RefreshIdExpires))
	}

	exists, err := j.config.CheckUserExists(*refreshData.Data)
	if err != nil || !exists {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusUnauthorized,
			Error:      "unauthorized",
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
		"exp":        dateNow.Add(j.config.AccessTokenExpires).Unix(),
		"iat":        dateNow.Unix(),
	})

	privateKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(j.config.PrivateKey))
	if err != nil {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusInternalServerError,
			Error:      "private key invalid",
		}
	}

	newAccessToken, err := token.SignedString(privateKey)
	if err != nil {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusInternalServerError,
			Error:      "failed to sign token",
		}
	}

	w.Header().Set("X-New-Access-Token", newAccessToken)
	j.SetCookie(w, j.config.AccessTokenCookieKey, newAccessToken, dateNow.Add(j.config.AccessTokenExpires))

	return &AuthResult{
		Success:    true,
		StatusCode: http.StatusOK,
		Data:       refreshData.Data,
	}
}
