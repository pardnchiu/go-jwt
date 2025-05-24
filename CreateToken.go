package golangJwtAuth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (j *JWTAuth) Create(r *http.Request, w http.ResponseWriter, u *AuthData) (*TokenResult, error) {
	if u == nil {
		return nil, fmt.Errorf("user data is required")
	}

	fp := j.GetFingerprint(r)
	dateNow := time.Now()
	refreshId := j.CreateRefreshId(u.ID, u.Name, u.Email, fp)
	claims := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"id":         u.ID,
		"name":       u.Name,
		"email":      u.Email,
		"thumbnail":  u.Thumbnail,
		"scope":      u.Scope,
		"role":       u.Role,
		"level":      u.Level,
		"fp":         fp,
		"refresh_id": refreshId,
		"exp":        dateNow.Add(j.config.AccessTokenExpires).Unix(),
		"iat":        dateNow.Unix(),
	})

	privateKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(j.config.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("private key invalid: %v", err)
	}

	accessToken, err := claims.SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %v", err)
	}

	j.SetCookie(w, j.config.AccessTokenCoolieKey, accessToken, dateNow.Add(j.config.AccessTokenExpires))
	j.SetCookie(w, j.config.RefreshIdCookieKey, refreshId, dateNow.Add(j.config.RefreshIdExpires))

	refreshData, _ := json.Marshal(map[string]interface{}{
		"data": map[string]interface{}{
			"id":        u.ID,
			"name":      u.Name,
			"email":     u.Email,
			"thumbnail": u.Thumbnail,
			"scope":     u.Scope,
			"role":      u.Role,
			"level":     u.Level,
		},
		"version": 1,
		"fp":      fp,
		"exp":     dateNow.Add(j.config.AccessTokenExpires).Unix(),
		"iat":     dateNow.Unix(),
	})
	if err := j.redisClient.SetEx(j.context, "refresh:"+refreshId, string(refreshData), j.config.RefreshIdExpires).Err(); err != nil {
		return nil, fmt.Errorf("failed to save to redis: %v", err)
	}

	return &TokenResult{
		Token:     accessToken,
		RefreshId: refreshId,
	}, nil
}

func (j *JWTAuth) CreateRefreshId(userID, name, email, fp string) string {
	data := map[string]interface{}{
		"id":    userID,
		"name":  name,
		"email": email,
		"fp":    fp,
		"iat":   time.Now(),
	}

	jsonData, _ := json.Marshal(data)
	hash := sha256.Sum256(jsonData)

	return hex.EncodeToString(hash[:])
}
