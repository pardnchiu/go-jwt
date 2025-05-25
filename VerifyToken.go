package golangJwtAuth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func (j *JWTAuth) Verify(r *http.Request, w http.ResponseWriter) *AuthResult {
	fp := j.GetFingerprint(r)
	accessToken := j.GetAccessToken(r)
	refreshId := j.GetRefreshId(r)

	if accessToken == "" && refreshId == "" {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusUnauthorized,
			Error:      "unauthorized",
		}
	}

	if accessToken == "" && refreshId != "" {
		if _, err := j.GetRefreshData(refreshId, fp); err != nil {
			return &AuthResult{
				Success:    false,
				StatusCode: http.StatusBadRequest,
				Error:      "refresh id invalid",
			}
		}

		return j.Refresh(r, w, refreshId, fp)
	}

	revokeVal, err := j.redisClient.Get(j.context, "revoke:"+accessToken).Result()
	if err == nil && revokeVal != "" {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusUnauthorized,
			Error:      "token revoked",
		}
	}

	claims, err := parseToken(accessToken, j.config)
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			token, _ := jwt.Parse(accessToken, nil)
			if token == nil || token.Claims == nil {
				return &AuthResult{
					Success:    false,
					StatusCode: http.StatusBadRequest,
					Error:      "access token invalid",
				}
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return &AuthResult{
					Success:    false,
					StatusCode: http.StatusBadRequest,
					Error:      "access token invalid",
				}
			}

			if claims[j.config.RefreshIdCookieKey].(string) != refreshId {
				return &AuthResult{
					Success:    false,
					StatusCode: http.StatusBadRequest,
					Error:      "refresh id invalid",
				}
			}

			if claims["fp"].(string) != fp {
				return &AuthResult{
					Success:    false,
					StatusCode: http.StatusBadRequest,
					Error:      "fingerprint invalid",
				}
			}

			return j.Refresh(r, w, refreshId, fp)
		}

		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusBadRequest,
			Error:      "access token invalid",
		}
	}

	if claims[j.config.RefreshIdCookieKey].(string) != refreshId {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusBadRequest,
			Error:      "refresh id invalid",
		}
	}

	if claims["fp"].(string) != fp {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusBadRequest,
			Error:      "fingerprint invalid",
		}
	}

	userData := j.GetUserData(claims)

	return &AuthResult{
		Success:    true,
		StatusCode: http.StatusOK,
		Data:       &userData,
	}
}

func (j *JWTAuth) GetAccessToken(r *http.Request) string {
	if cookie, err := r.Cookie(j.config.AccessTokenCookieKey); err == nil {
		return cookie.Value
	}

	auth := r.Header.Get("Authorization")

	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}

// * private function
func parseToken(tokenString string, config *Config) (jwt.MapClaims, error) {
	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(config.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("parse public key failed: %v", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
