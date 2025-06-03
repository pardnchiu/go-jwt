package goJwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (j *JWTAuth) Create(w http.ResponseWriter, r *http.Request, auth *Auth) JWTAuthResult {
	now := time.Now()
	jti := uuid()
	fp := j.getFingerprint(w, r)

	// * 未提供 Auth 資料
	if auth == nil {
		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      j.logger.Error(nil, "missing auth data").Error(),
			ErrorTag:   errorDataMissing,
		}
	}

	refreshID, err := j.createRefreshId(auth, fp, jti)
	if err != nil {
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      j.logger.Error(err, "refresh ID creation failed").Error(),
			ErrorTag:   errorFailedToCreate,
		}
	}

	accessToken, err := j.signJWT(auth, refreshID, fp, jti)
	if err != nil {
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      j.logger.Error(err, "JWT signing failed").Error(),
			ErrorTag:   errorFailedToSign,
		}
	}

	j.setCookie(w, j.config.Option.AccessTokenCookieKey, accessToken, now.Add(j.config.Option.AccessTokenExpires))
	j.setCookie(w, j.config.Option.RefreshIdCookieKey, refreshID, now.Add(j.config.Option.RefreshIdExpires))

	refreshData := RefreshData{
		Data:        auth,
		Version:     1,
		Fingerprint: fp,
		Exp:         now.Add(j.config.Option.AccessTokenExpires).Unix(),
		Iat:         now.Unix(),
		Jti:         jti,
	}
	refreshDataJson, err := json.Marshal(refreshData)
	if err != nil {
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      j.logger.Error(err, "refresh data marshaling failed").Error(),
			ErrorTag:   errorFailedToCreate,
		}
	}

	keyRefreshID := fmt.Sprintf(redisKeyRefreshID, refreshID)
	keyJTI := fmt.Sprintf(redisKeyJTI, jti)

	pipe := j.redis.TxPipeline()
	pipe.SetEx(j.context, keyRefreshID, string(refreshDataJson), j.config.Option.RefreshIdExpires)
	pipe.SetEx(j.context, keyJTI, "1", j.config.Option.AccessTokenExpires)
	_, err = pipe.Exec(j.context)
	if err != nil {
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      j.logger.Error(err, "Redis transaction failed").Error(),
			ErrorTag:   errorFailedToStore,
		}
	}

	return JWTAuthResult{
		Success:    true,
		StatusCode: http.StatusOK,
		Data:       auth,
		Token: &TokenResult{
			Token:     accessToken,
			RefreshId: refreshID,
		},
	}
}

func (j *JWTAuth) signJWT(data *Auth, refreshID string, fp string, jti string) (string, error) {
	now := time.Now()
	claimsMap := jwt.MapClaims{
		"id":        data.ID,
		"name":      data.Name,
		"email":     data.Email,
		"thumbnail": data.Thumbnail,
		"scope":     data.Scope,
		"role":      data.Role,
		"level":     data.Level,
		"fp":        fp,
		"jti":       jti,
		"exp":       now.Add(j.config.Option.AccessTokenExpires).Unix(),
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
	}
	claimsMap[j.config.Option.RefreshIdCookieKey] = refreshID
	claims := jwt.NewWithClaims(jwt.SigningMethodES256, claimsMap)
	accessToken, err := claims.SignedString(j.pem.private)
	// * 無法簽署新的 Access Token
	if err != nil {
		return "", err
	}
	return accessToken, nil
}
