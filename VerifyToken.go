package golangJwtAuth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (j *JWTAuth) Verify(r *http.Request, w http.ResponseWriter) *AuthResult {
	fp := j.getFingerprint(r)
	accessToken := j.getAccessToken(r)
	refreshId := j.getRefreshId(r)

	if accessToken == "" && refreshId == "" {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusUnauthorized,
			Error:      "Unauthorized",
		}
	}

	if accessToken == "" && refreshId != "" {
		if _, err := j.getRefreshData(refreshId, fp); err != nil {
			j.Logger.Error(
				"Refresh ID is required",
				err.Error(),
			)
			return &AuthResult{
				Success:    false,
				StatusCode: http.StatusBadRequest,
				Error:      "Refresh ID is required",
			}
		}

		return j.Refresh(r, w, refreshId, fp)
	}

	revokeVal, err := j.Redis.Get(j.Context, "revoke:"+accessToken).Result()
	if err == nil && revokeVal != "" {
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusUnauthorized,
			Error:      "Token has been revoked",
		}
	} else if err.Error() != "redis: nil" {
		j.Logger.Error(
			"Failed to check access token",
			err.Error(),
		)
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to check access token",
		}
	}

	jwtJson, err := j.parseToken(accessToken)
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			token, err := jwt.Parse(accessToken, nil)
			if err != nil || token == nil || token.Claims == nil {
				j.Logger.Error("Invalid access token-1")
				return &AuthResult{
					Success:    false,
					StatusCode: http.StatusBadRequest,
					Error:      "Invalid access token-1",
				}
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				j.Logger.Error("Invalid access token-2")
				return &AuthResult{
					Success:    false,
					StatusCode: http.StatusBadRequest,
					Error:      "Invalid access token-2",
				}
			}

			if claims[j.Config.RefreshIdCookieKey].(string) != refreshId {
				j.Logger.Error("Invalid Refresh ID-1")
				return &AuthResult{
					Success:    false,
					StatusCode: http.StatusBadRequest,
					Error:      "Invalid Refresh ID-1",
				}
			}

			if claims["fp"].(string) != fp {
				j.Logger.Error("Invalid fingerprint-1")
				return &AuthResult{
					Success:    false,
					StatusCode: http.StatusBadRequest,
					Error:      "Invalid fingerprint",
				}
			}

			return j.Refresh(r, w, refreshId, fp)
		}

		j.Logger.Error("Invalid access token-3")
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid access token-3",
		}
	}

	if jti, exists := jwtJson["jti"]; exists {
		if err := j.validateJTI(jti.(string)); err != nil {
			j.Logger.Error("Invalid JTI")
			return &AuthResult{
				Success:    false,
				StatusCode: http.StatusUnauthorized,
				Error:      "Invalid JTI",
			}
		}
	}

	if jwtJson[j.Config.RefreshIdCookieKey].(string) != refreshId {
		j.Logger.Error("Invalid Refresh ID-2")
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid Refresh ID-2",
		}
	}

	if jwtJson["fp"].(string) != fp {
		j.Logger.Error("Invalid fingerprint-2")
		return &AuthResult{
			Success:    false,
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid fingerprint-2",
		}
	}

	userData := j.getUserData(jwtJson)

	j.Logger.Info(
		"Verify access token successfully",
		fmt.Sprintf("user: %s", userData.ID),
	)

	return &AuthResult{
		Success:    true,
		StatusCode: http.StatusOK,
		Data:       &userData,
	}
}

// * private method
func (j *JWTAuth) getAccessToken(r *http.Request) string {
	if cookie, err := r.Cookie(j.Config.AccessTokenCookieKey); err == nil {
		return cookie.Value
	}

	auth := r.Header.Get("Authorization")

	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}

// * private method
func (j *JWTAuth) parseToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.Config.PublicKeyPEM, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		now := time.Now()

		if nbf, exists := claims["nbf"]; exists {
			if nbfTime := time.Unix(int64(nbf.(float64)), 0); now.Before(nbfTime) {
				return nil, fmt.Errorf("token not yet valid")
			}
		}

		if iat, exists := claims["iat"]; exists {
			if iatTime := time.Unix(int64(iat.(float64)), 0); now.Before(iatTime.Add(-5 * time.Minute)) {
				return nil, fmt.Errorf("token issued in future")
			}
		}

		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// * private method
func (j *JWTAuth) validateJTI(jti string) error {
	if jti == "" {
		return fmt.Errorf("missing JWT ID")
	}

	exists, err := j.Redis.Exists(j.Context, "jti:"+jti).Result()
	if err != nil {
		return fmt.Errorf("failed to check JWT ID: %v", err)
	}

	if exists == 0 {
		return fmt.Errorf("JWT ID invalid or expired")
	}

	return nil
}
