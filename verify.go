package goJwt

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (j *JWTAuth) Verify(w http.ResponseWriter, r *http.Request) JWTAuthResult {
	refreshID := j.getRefreshID(r)
	accessToken := j.getAccessToken(r)
	fp := j.getFingerprint(w, r)

	// * No Access Token provided
	if accessToken == "" {
		// * No Refresh ID provided (not logged in)
		if refreshID == "" {
			return JWTAuthResult{
				StatusCode: http.StatusUnauthorized,
				Error:      j.logger.Error(nil, "Authentication required: Not logged in").Error(),
				ErrorTag:   errorUnAuthorized,
			}
		}
		// * Attempt to re-sign Access Token (follow Refresh flow)
		return j.refresh(w, r)
	}

	keyRevoke := fmt.Sprintf(redisKeyRevoke, accessToken)
	resultRevoke, err := j.redis.Get(j.context, keyRevoke).Result()
	// * Redis error
	if err != nil && err.Error() != "redis: nil" {
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      j.logger.Error(err, "Server error: Failed to verify token status").Error(),
			ErrorTag:   errorFailedToGet,
		}
	}
	// * Access Token revocation record exists (logged out)
	if resultRevoke != "" {
		return JWTAuthResult{
			StatusCode: http.StatusUnauthorized,
			Error:      "Session expired: Token revoked",
			ErrorTag:   errorRevoked,
		}
	}

	auth, err := j.parseJWT(accessToken, refreshID, fp)
	// * JWT parsing failed
	if err != nil {
		// * JWT parsing failed due to expiration
		if strings.Contains(err.Error(), "expired") {
			return j.refresh(w, r)
		}

		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      j.logger.Error(err, "Invalid token: Failed to parse").Error(),
			ErrorTag:   errorDataInvalid,
		}
	}

	return JWTAuthResult{
		Success:    true,
		StatusCode: http.StatusOK,
		Data:       auth,
	}
}

func (j *JWTAuth) parseJWT(txt string, refreshID string, fp string) (*Auth, error) {
	token, err := jwt.Parse(txt, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, j.logger.Error(nil, "JWT signing method is not ECDSA")
		}
		return j.pem.public, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		now := time.Now()

		if nbf, exists := claims["nbf"]; exists {
			if nbfTime := time.Unix(int64(nbf.(float64)), 0); now.Before(nbfTime) {
				return nil, j.logger.Error(nil, "Token not valid yet")
			}
		}

		if iat, exists := claims["iat"]; exists {
			if iatTime := time.Unix(int64(iat.(float64)), 0); now.Before(iatTime.Add(-5 * time.Minute)) {
				return nil, j.logger.Error(nil, "Token issued in the future")
			}
		}

		if claims[j.config.Option.RefreshIdCookieKey].(string) != refreshID {
			return nil, j.logger.Error(nil, "Refresh ID does not match")
		}

		if claims["fp"].(string) != fp {
			return nil, j.logger.Error(nil, "Fingerprint does not match")
		}

		if err := j.validateJTI(claims["jti"].(string)); err != nil {
			return nil, err
		}

		auth := j.getAuth(claims)

		return &auth, nil
	}

	return nil, j.logger.Error(nil, "JWT claims are not valid")
}

func (j *JWTAuth) getAuth(data map[string]interface{}) Auth {
	return Auth{
		ID:        getStr(data, "id"),
		Name:      getStr(data, "name"),
		Email:     getStr(data, "email"),
		Thumbnail: getStr(data, "thumbnail"),
		Role:      getStr(data, "role"),
		Level:     getInt(data, "level"),
		Scope:     getScope(data, "scope"),
	}
}

func (j *JWTAuth) validateJTI(jti string) error {
	if jti == "" {
		return fmt.Errorf("JWT ID is empty")
	}

	keyJTI := fmt.Sprintf(redisKeyJTI, jti)
	isExist, err := j.redis.Exists(j.context, keyJTI).Result()
	if err != nil {
		return fmt.Errorf("Failed to check JWT ID existence: %w", err)
	}

	if isExist == 0 {
		return fmt.Errorf("JWT ID does not exist")
	}

	return nil
}
